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

type iptCmd struct {
	args     []string
	tolerate bool
}

func (m *IPTablesManager) commands() ([]iptCmd, error) {
	port, err := listenPort(m.cfg.Listen)
	if err != nil {
		return nil, err
	}
	dports := portList(m.cfg.Ports)

	cmds := []iptCmd{
		{args: []string{"-t", "nat", "-D", "OUTPUT", "-j", "MITM_NAT_OUT"}, tolerate: true},
		{args: []string{"-t", "nat", "-F", "MITM_NAT_OUT"}, tolerate: true},
		{args: []string{"-t", "nat", "-X", "MITM_NAT_OUT"}, tolerate: true},
		{args: []string{"-t", "nat", "-N", "MITM_NAT_OUT"}},
		{args: []string{"-t", "nat", "-A", "OUTPUT", "-j", "MITM_NAT_OUT"}},
		{args: []string{"-t", "nat", "-A", "MITM_NAT_OUT",
			"-m", "mark", "--mark", fmt.Sprint(m.cfg.Redirect.Mark), "-j", "RETURN"}},
	}
	if m.uid != 0 {
		cmds = append(cmds, iptCmd{args: []string{"-t", "nat", "-A", "MITM_NAT_OUT",
			"-m", "owner", "!", "--uid-owner", fmt.Sprint(m.uid), "-j", "RETURN"}})
	}
	cmds = append(cmds,
		iptCmd{args: []string{"-t", "nat", "-A", "MITM_NAT_OUT",
			"-p", "tcp", "-m", "multiport", "--dports", dports, "-j", "REDIRECT", "--to-ports", port}},
		iptCmd{args: []string{"-D", "OUTPUT", "-j", "MITM_FILT_OUT"}, tolerate: true},
		iptCmd{args: []string{"-F", "MITM_FILT_OUT"}, tolerate: true},
		iptCmd{args: []string{"-X", "MITM_FILT_OUT"}, tolerate: true},
		iptCmd{args: []string{"-N", "MITM_FILT_OUT"}},
		iptCmd{args: []string{"-A", "OUTPUT", "-j", "MITM_FILT_OUT"}},
	)
	if m.cfg.QUIC.ForceTCP {
		cmds = append(cmds, iptCmd{args: []string{"-A", "MITM_FILT_OUT",
			"-p", "udp", "-m", "multiport", "--dports", "443", "-j", "REJECT"}})
	}
	return cmds, nil
}

func (m *IPTablesManager) On() error {
	cmds, err := m.commands()
	if err != nil {
		return err
	}
	for _, ipt := range m.families() {
		for _, c := range cmds {
			out, err := m.run.Run(ipt, c.args...)
			if err != nil && !c.tolerate {
				return fmt.Errorf("%s on (%s): %s", ipt, strings.Join(c.args, " "), strings.TrimSpace(string(out)))
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
			m.run.Run(ipt, chunk...)
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
