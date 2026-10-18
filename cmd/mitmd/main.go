package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/hellsing-organization/mitm/internal/audit"
	"github.com/hellsing-organization/mitm/internal/bpf"
	"github.com/hellsing-organization/mitm/internal/certs"
	"github.com/hellsing-organization/mitm/internal/config"
	"github.com/hellsing-organization/mitm/internal/proxy"
	"github.com/hellsing-organization/mitm/internal/redirect"
)

func main() {
	cfgPath := flag.String("config", "/etc/mitm/mitm.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mitmd: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, cfg); err != nil && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "mitmd: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg config.Config) error {
	store, err := audit.OpenStore(cfg.Output.Dir, cfg.Output.JSONL)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer store.Close()

	ca, err := certs.LoadOrGenerateCA(cfg.CA.Key, cfg.CA.Cert, true)
	if err != nil {
		return fmt.Errorf("load ca: %w", err)
	}

	var mgr redirect.Manager
	if cfg.Redirect.Managed {
		factory := redirect.Detect(func(name string) string {
			p, err := exec.LookPath(name)
			if err != nil {
				return ""
			}
			return p
		})
		mgr = factory(cfg, currentUID())
		if mgr == nil {
			return fmt.Errorf("no nft/iptables found for redirect")
		}
		if err := mgr.On(); err != nil {
			return fmt.Errorf("install redirect: %w", err)
		}
		defer mgr.Off()
	}

	flows := audit.NewFlowRegistry(func(e audit.Event) {
		if werr := store.WriteEvent(e); werr != nil {
			fmt.Fprintf(os.Stderr, "mitmd: alert write: %v\n", werr)
		}
	}, cfg.Ports)

	var flowEvents atomic.Int64
	stopBPF, bpfErr := bpf.Load(func(ev bpf.FlowEvent) {
		flowEvents.Add(1)
		srcIP, dstIP := ev.SrcIP().String(), ev.DstIP().String()
		key := audit.FlowKey{
			SrcIP:   srcIP,
			SrcPort: int(ev.Sport),
			DstIP:   dstIP,
			DstPort: int(ev.Dport),
		}
		pid := int32(ev.PID)
		uid := uint32(ev.UID)
		ts := time.Now().UTC()
		flows.Add(key, audit.FlowInfo{PID: pid, UID: uid, Comm: ev.Comm, Ts: ts})
		if werr := store.WriteEvent(audit.Event{
			Ts:     ts,
			Type:   audit.TypeFlow,
			FlowID: audit.FlowID(key),
			PID:    &pid,
			UID:    &uid,
			Comm:   ev.Comm,
			Src:    net.JoinHostPort(srcIP, strconv.Itoa(int(ev.Sport))),
			Dst:    net.JoinHostPort(dstIP, strconv.Itoa(int(ev.Dport))),
		}); werr != nil {
			fmt.Fprintf(os.Stderr, "mitmd: flow write: %v\n", werr)
		}
	}, true)

	startup := audit.Event{Ts: time.Now().UTC(), Type: audit.TypeStartup}
	if bpfErr != nil {
		startup.Alert = &audit.AlertDetail{
			Kind: audit.KindBPFDisabled,
			Note: "flow probe unavailable (" + bpfErr.Error() + "); running degraded: no PID attribution",
		}
		fmt.Fprintf(os.Stderr, "mitmd: bpf disabled: %v\n", bpfErr)
	} else {
		defer stopBPF()
		before := flowEvents.Load()
		if c, derr := net.DialTimeout("tcp", "127.0.0.1:1", 300*time.Millisecond); derr == nil {
			c.Close()
		}
		time.Sleep(500 * time.Millisecond)
		startup.Note = fmt.Sprintf("bpf self-test: %d events after probe connect; %s",
			flowEvents.Load()-before, bpf.LoadInfo())
	}

	if mgr != nil {
		if status, serr := mgr.Status(); serr == nil {
			startup.Note = status + " | " + startup.Note
		}
	}

	_ = store.WriteEvent(startup)

	srv := proxy.New(cfg, ca, store, flows)
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()

	addrFile := filepath.Join(cfg.Output.Dir, "proxy.addr")
	defer os.Remove(addrFile)
	if err := os.MkdirAll(cfg.Output.Dir, 0o755); err == nil {
		for i := 0; i < 100; i++ {
			if addr := srv.Addr(); addr != nil {
				os.WriteFile(addrFile, []byte(addr.String()), 0o644)
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	sweepStop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-sweepStop:
				return
			case <-ticker.C:
				flows.Sweep(time.Now())
			case <-ctx.Done():
				return
			}
		}
	}()
	defer close(sweepStop)

	select {
	case <-ctx.Done():
		srv.Close()
		return nil
	case err := <-errCh:
		srv.Close()
		return err
	}
}

func currentUID() int {
	if u, err := user.Current(); err == nil {
		var uid int
		fmt.Sscanf(u.Uid, "%d", &uid)
		return uid
	}
	return os.Getuid()
}
