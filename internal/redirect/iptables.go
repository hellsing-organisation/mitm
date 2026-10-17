package redirect

import (
	"fmt"
	"strings"

	"github.com/hellsing-organization/mitm/internal/config"
)

type IPTablesManager struct {
	run Runner
	cfg config.Config
	uid int
}

func NewIPTables(run Runner, cfg config.Config, daemonUID int) *IPTablesManager {
	return &IPTablesManager{run: run, cfg: cfg, uid: daemonUID}
}

func (m *IPTablesManager) families() []string {
	return []string{"iptables", "ip6tables"}
}

func (m *IPTablesManager) On() error {
	port, err := listenPort(m.cfg.Listen)
	if err != nil {
		return err
	}
	dports := portList(m.cfg.Ports)

	for _, ipt := range m.families() {
		var natRules []string
		natRules = append(natRules, "-t", "nat", "-N", "MITM_NAT_OUT")
		natRules = append(natRules, "-t", "nat", "-A", "OUTPUT", "-j", "MITM_NAT_OUT")
		natRules = append(natRules, "-t", "nat", "-F", "MITM_NAT_OUT")
		natRules = append(natRules, "-t", "nat", "-A", "MITM_NAT_OUT",
			"-m", "mark", "--mark", fmt.Sprint(m.cfg.Redirect.Mark), "-j", "RETURN")
		if m.uid != 0 {
			natRules = append(natRules, "-t", "nat", "-A", "MITM_NAT_OUT",
				"-m", "owner", "!", "--uid-owner", fmt.Sprint(m.uid), "-j", "RETURN")
		}
		natRules = append(natRules, "-t", "nat", "-A", "MITM_NAT_OUT",
			"-p", "tcp", "-m", "multiport", "--dports", dports, "-j", "REDIRECT", "--to-ports", port)

		var filtRules []string
		filtRules = append(filtRules, "-N", "MITM_FILT_OUT")
		filtRules = append(filtRules, "-A", "OUTPUT", "-j", "MITM_FILT_OUT")
		filtRules = append(filtRules, "-F", "MITM_FILT_OUT")
		if m.cfg.QUIC.ForceTCP {
			filtRules = append(filtRules, "-A", "MITM_FILT_OUT",
				"-p", "udp", "-m", "multiport", "--dports", "443", "-j", "REJECT")
		}

		for _, chunk := range [][]string{natRules, filtRules} {
			out, err := m.run.Run(ipt, chunk...)
			if err != nil {
				return fmt.Errorf("%s on: %s", ipt, strings.TrimSpace(string(out)))
			}
		}
	}
	return nil
}

func (m *IPTablesManager) Off() error {
	for _, ipt := range m.families() {
		rules := [][]string{
			{"-t", "nat", "-D", "OUTPUT", "-j", "MITM_NAT_OUT"},
			{"-t", "nat", "-F", "MITM_NAT_OUT"},
			{"-t", "nat", "-X", "MITM_NAT_OUT"},
			{"-D", "OUTPUT", "-j", "MITM_FILT_OUT"},
			{"-F", "MITM_FILT_OUT"},
			{"-X", "MITM_FILT_OUT"},
		}
		for _, chunk := range rules {
			out, _ := m.run.Run(ipt, chunk...)
			_ = out
		}
	}
	return nil
}

func (m *IPTablesManager) Status() (string, error) {
	var sb strings.Builder
	for _, ipt := range m.families() {
		out, _ := m.run.Run(ipt, "-t", "nat", "-S", "MITM_NAT_OUT")
		sb.WriteString(ipt + " nat:\n" + strings.TrimSpace(string(out)) + "\n")
		out, _ = m.run.Run(ipt, "-S", "MITM_FILT_OUT")
		sb.WriteString(ipt + " filter:\n" + strings.TrimSpace(string(out)) + "\n")
	}
	return sb.String(), nil
}
