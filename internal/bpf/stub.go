//go:build !bpf

package bpf

func Load(onEvent func(FlowEvent), enabled bool) (stop func() error, err error) {
	if !enabled {
		return nil, ErrDisabled
	}
	return nil, ErrNotBuilt
}
