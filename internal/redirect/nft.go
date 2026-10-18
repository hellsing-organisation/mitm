package redirect

import (
	"fmt"
	"strings"

	"github.com/hellsing-organization/mitm/internal/config"
)

type NftManager struct {
	run Runner
	cfg config.Config
}

func NewNft(run Runner, cfg config.Config) *NftManager {
	return &NftManager{run: run, cfg: cfg}
}

type nftCmd struct {
	args     []string
	tolerate bool
}

func (m *NftManager) commands() ([]nftCmd, error) {
	port, err := listenPort(m.cfg.Listen)
	if err != nil {
		return nil, err
	}
	dports := "{ " + strings.Join(strings.Split(portList(m.cfg.Ports), ","), ", ") + " }"

	cmds := []nftCmd{
		{args: []string{"delete", "table", "inet", "mitm_audit"}, tolerate: true},
		{args: []string{"add", "table", "inet", "mitm_audit"}},
		{args: []string{"add", "chain", "inet", "mitm_audit", "output",
			"{ type nat hook output priority -100 ; policy accept ; }"}},
		{args: []string{"add", "rule", "inet", "mitm_audit", "output",
			"meta", "mark", fmt.Sprint(m.cfg.Redirect.Mark), "return"}},
		{args: []string{"add", "rule", "inet", "mitm_audit", "output",
			"tcp", "dport", dports, "redirect", "to", ":" + port}},
	}
	if m.cfg.QUIC.ForceTCP {
		cmds = append(cmds,
			nftCmd{args: []string{"add", "chain", "inet", "mitm_audit", "outfilt",
				"{ type filter hook output priority 0 ; policy accept ; }"}},
			nftCmd{args: []string{"add", "rule", "inet", "mitm_audit", "outfilt",
				"udp", "dport", "443", "reject"}},
		)
	}
	return cmds, nil
}

func (m *NftManager) On() error {
	cmds, err := m.commands()
	if err != nil {
		return err
	}
	for _, c := range cmds {
		out, err := m.run.Run("nft", c.args...)
		if err != nil && !c.tolerate {
			return fmt.Errorf("nft on (%s): %s", strings.Join(c.args, " "), strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func (m *NftManager) Off() error {
	out, err := m.run.Run("nft", "delete", "table", "inet", "mitm_audit")
	if err != nil && !strings.Contains(strings.ToLower(string(out)), "no such file") {
		return fmt.Errorf("nft off: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (m *NftManager) Status() (string, error) {
	out, err := m.run.Run("nft", "list", "table", "inet", "mitm_audit")
	if err != nil {
		return "absent: " + strings.TrimSpace(string(out)), nil
	}
	return strings.TrimSpace(string(out)), nil
}
