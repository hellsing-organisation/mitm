package redirect

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/hellsing-organization/mitm/internal/config"
)

type Manager interface {
	On() error
	Off() error
	Status() (string, error)
}

type Runner interface {
	Run(name string, args ...string) ([]byte, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

func Detect(lookPath func(string) string) func(config.Config, int) Manager {
	return func(cfg config.Config, uid int) Manager {
		if lookPath("nft") != "" && cfg.Redirect.Backend != "iptables" {
			return NewNft(ExecRunner{}, cfg)
		}
		if lookPath("iptables") != "" {
			return NewIPTables(ExecRunner{}, cfg, uid)
		}
		return nil
	}
}

func listenPort(listen string) (string, error) {
	parts := strings.Split(listen, ":")
	if len(parts) != 2 || parts[1] == "" {
		return "", fmt.Errorf("cannot parse proxy port from %q", listen)
	}
	return parts[1], nil
}

func portList(ports []int) string {
	strs := make([]string, len(ports))
	for i, p := range ports {
		strs[i] = fmt.Sprint(p)
	}
	return strings.Join(strs, ",")
}
