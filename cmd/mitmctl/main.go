package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/hellsing-organization/mitm/internal/audit"
	"github.com/hellsing-organization/mitm/internal/certs"
	"github.com/hellsing-organization/mitm/internal/config"
	"github.com/hellsing-organization/mitm/internal/redirect"
)

var (
	queryPrint = func(s string) { fmt.Println(s) }
	tailPrint  = func(s string) { fmt.Println(s) }
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "mitmctl: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: mitmctl <ca|redirect|tail|query> ...")
	}
	switch args[0] {
	case "ca":
		return caCmd(args[1:])
	case "redirect":
		return redirectCmd(args[1:])
	case "tail":
		return tailCmd(args[1:])
	case "query":
		return queryCmd(args[1:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func caCmd(args []string) error {
	fs := flag.NewFlagSet("ca", flag.ExitOnError)
	sub := ""
	if len(args) > 0 && args[0] == "gen" {
		sub = "gen"
		args = args[1:]
	} else if len(args) > 0 && args[0] == "install-android" {
		sub = "install-android"
		args = args[1:]
	}
	key := fs.String("key", "/etc/mitm/ca.key", "CA key path")
	cert := fs.String("cert", "/etc/mitm/ca.crt", "CA cert path")
	force := fs.Bool("force", false, "overwrite existing CA")
	fs.Parse(args)

	switch sub {
	case "gen":
		if *force {
			os.Remove(*key)
			os.Remove(*cert)
		}
		if _, err := certs.LoadOrGenerateCA(*key, *cert, true); err != nil {
			return err
		}
		fmt.Printf("CA written: %s %s\n", *key, *cert)
		return nil
	case "install-android":
		script, err := exec.LookPath("bash")
		if err != nil {
			return err
		}
		cmd := exec.Command(script, "scripts/install-android-ca.sh", *cert)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	default:
		return fmt.Errorf("usage: mitmctl ca gen|install-android [--key P --cert P] [--force]")
	}
}

func redirectCmd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: mitmctl redirect on|off|status --config P")
	}
	action := args[0]
	fs := flag.NewFlagSet("redirect", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/mitm/mitm.yaml", "config path")
	fs.Parse(args[1:])

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	mgr := redirect.Detect(func(name string) string {
		p, err := exec.LookPath(name)
		if err != nil {
			return ""
		}
		return p
	})(cfg, os.Getuid())
	if mgr == nil {
		return fmt.Errorf("no nft/iptables found")
	}
	switch action {
	case "on":
		return mgr.On()
	case "off":
		return mgr.Off()
	case "status":
		s, err := mgr.Status()
		fmt.Println(s)
		return err
	default:
		return fmt.Errorf("unknown redirect action %q", action)
	}
}

func tailCmd(args []string) error {
	fs := flag.NewFlagSet("tail", flag.ExitOnError)
	file := fs.String("file", "", "events.jsonl path (default <config output dir>)")
	cfgPath := fs.String("config", "/etc/mitm/mitm.yaml", "config path")
	follow := fs.Bool("f", false, "follow")
	typ := fs.String("type", "", "filter by event type")
	fs.Parse(args)

	path := *file
	if path == "" {
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			return err
		}
		path = cfg.Output.Dir + string(os.PathSeparator) + cfg.Output.JSONL
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		printEvent(sc.Bytes(), *typ, tailPrint)
	}
	if !*follow {
		return nil
	}
	for {
		line := make([]byte, 16*1024*1024)
		n, err := f.Read(line)
		if n > 0 {
			for _, part := range strings.SplitAfter(string(line[:n]), "\n") {
				if strings.TrimSpace(part) != "" {
					printEvent([]byte(part), *typ, tailPrint)
				}
			}
		}
		if err != nil {
			time.Sleep(200 * time.Millisecond)
		}
	}
}

func printEvent(b []byte, typ string, print func(string)) {
	var e audit.Event
	if err := json.Unmarshal(b, &e); err != nil {
		return
	}
	if typ != "" && e.Type != typ {
		return
	}
	pid := "-"
	if e.PID != nil {
		pid = strconv.FormatInt(int64(*e.PID), 10)
	}
	line := fmt.Sprintf("%s %-5s pid=%-7s %-16s", e.Ts.Format(time.RFC3339), e.Type, pid, e.Comm)
	if e.HTTP != nil {
		line += fmt.Sprintf(" %s %s%s -> %d", e.HTTP.Method, e.HTTP.Host, e.HTTP.Path, e.HTTP.Status)
		if e.HTTP.Err != "" {
			line += " err=" + e.HTTP.Err
		}
	}
	if e.Alert != nil {
		line += " " + e.Alert.Kind + " " + e.Alert.Note
	}
	if e.Src != "" && e.Dst != "" {
		line += fmt.Sprintf(" %s -> %s", e.Src, e.Dst)
	}
	print(line)
}

func queryCmd(args []string) error {
	fs := flag.NewFlagSet("query", flag.ExitOnError)
	file := fs.String("file", "", "events.jsonl path (default <config output dir>)")
	cfgPath := fs.String("config", "/etc/mitm/mitm.yaml", "config path")
	app := fs.String("app", "", "filter by comm")
	domain := fs.String("domain", "", "filter by host/sni substring")
	method := fs.String("method", "", "filter by HTTP method")
	status := fs.String("status", "", "filter by status code")
	since := fs.String("since", "", "only events after RFC3339 timestamp")
	limit := fs.Int("limit", 0, "max results")
	fs.Parse(args)

	path := *file
	if path == "" {
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			return err
		}
		path = cfg.Output.Dir + string(os.PathSeparator) + cfg.Output.JSONL
	}

	var sinceT time.Time
	if *since != "" {
		t, err := time.Parse(time.RFC3339, *since)
		if err != nil {
			return fmt.Errorf("--since: %v", err)
		}
		sinceT = t
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		var e audit.Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			continue
		}
		if *app != "" && e.Comm != *app {
			continue
		}
		if *domain != "" && !strings.Contains(e.SNI, *domain) &&
			(e.HTTP == nil || !strings.Contains(e.HTTP.Host, *domain)) {
			continue
		}
		if *method != "" && (e.HTTP == nil || e.HTTP.Method != *method) {
			continue
		}
		if *status != "" && (e.HTTP == nil || strconv.Itoa(e.HTTP.Status) != *status) {
			continue
		}
		if !sinceT.IsZero() && e.Ts.Before(sinceT) {
			continue
		}
		printEvent(sc.Bytes(), "", queryPrint)
		n++
		if *limit > 0 && n >= *limit {
			break
		}
	}
	return nil
}
