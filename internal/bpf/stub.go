//go:build !bpf

package bpf

func Load(onEvent func(FlowEvent), enabled bool) (*Probe, error) {
	if !enabled {
		return nil, ErrDisabled
	}
	return nil, ErrNotBuilt
}

// Probe is a handle on the loaded eBPF flow probe.
type Probe struct{}

func (p *Probe) Stop() error { return nil }

func (p *Probe) ReadStats() (Stats, error) {
	return Stats{}, ErrNotBuilt
}

func (p *Probe) ReadDiag() (Diag, error) {
	return Diag{}, ErrNotBuilt
}

// LoadInfo reports loader diagnostics; empty when built without the bpf tag.
func LoadInfo() string { return "" }
