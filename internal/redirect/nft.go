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

func (m *NftManager) On() error {
	port, err := listenPort(m.cfg.Listen)
	if err != nil {
		return err
	}
	dports := "{ " + strings.Join(strings.Split(portList(m.cfg.Ports), ","), ", ") + " }"
	rules := []string{
		"add table inet mitm_audit",
		"flush table inet mitm_audit",
		"add chain inet mitm_audit output { type nat hook output priority -100 ; policy accept ; }",
		fmt.Sprintf("add rule inet mitm_audit output meta mark %d return", m.cfg.Redirect.Mark),
		fmt.Sprintf("add rule inet mitm_audit output tcp dport %s redirect to :%s", dports, port),
	}
	if m.cfg.QUIC.ForceTCP {
		rules = append(rules,
			"add chain inet mitm_audit outfilt { type filter hook output priority 0 ; policy accept ; }",
			"add rule inet mitm_audit outfilt udp dport 443 reject",
		)
	}
	out, err := m.run.Run("nft", rules...)
	if err != nil {
		return fmt.Errorf("nft on: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (m *NftManager) Off() error {
	out, err := m.run.Run("nft", "delete table inet mitm_audit")
	if err != nil {
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
