package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"strings"

	"gopkg.in/yaml.v3"
)

type CAPaths struct {
	Key  string `yaml:"key"`
	Cert string `yaml:"cert"`
}

type RedirectCfg struct {
	Mark    int    `yaml:"mark"`
	Managed bool   `yaml:"managed"`
	Backend string `yaml:"backend"`
}

type QUICCfg struct {
	ForceTCP bool `yaml:"force_tcp"`
}

type CaptureCfg struct {
	Bodies              bool     `yaml:"bodies"`
	MaxBodyBytes        int64    `yaml:"max_body_bytes"`
	ContentTypes        []string `yaml:"content_types"`
	ExcludeContentTypes []string `yaml:"exclude_content_types"`
}

type Filters struct {
	ExcludeProcesses []string `yaml:"exclude_processes"`
	IncludeDomains   []string `yaml:"include_domains"`
	ExcludeDomains   []string `yaml:"exclude_domains"`
}

type OutputCfg struct {
	Dir   string `yaml:"dir"`
	JSONL string `yaml:"jsonl"`
}

type Config struct {
	Listen   string      `yaml:"listen"`
	Ports    []int       `yaml:"ports"`
	CA       CAPaths     `yaml:"ca"`
	Redirect RedirectCfg `yaml:"redirect"`
	QUIC     QUICCfg     `yaml:"quic"`
	Capture  CaptureCfg  `yaml:"capture"`
	Filters  Filters     `yaml:"filters"`
	Output   OutputCfg   `yaml:"output"`
}

func Default() Config {
	return Config{
		Listen: "127.0.0.1:8080",
		Ports:  []int{443},
		CA:     CAPaths{Key: "/etc/mitm/ca.key", Cert: "/etc/mitm/ca.crt"},
		Redirect: RedirectCfg{
			Mark:    1337,
			Managed: true,
			Backend: "auto",
		},
		QUIC: QUICCfg{ForceTCP: true},
		Capture: CaptureCfg{
			Bodies:       true,
			MaxBodyBytes: 16777216,
			ContentTypes: []string{"*/*"},
			ExcludeContentTypes: []string{
				"image/*", "video/*", "audio/*", "font/*",
			},
		},
		Filters: Filters{ExcludeProcesses: []string{"mitmd"}},
		Output:  OutputCfg{Dir: "/var/log/mitm-audit", JSONL: "events.jsonl"},
	}
}

func Load(p string) (Config, error) {
	c := Default()
	b, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return c, c.Validate()
		}
		return c, fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("parse config %s: %w", p, err)
	}
	return c, c.Validate()
}

func (c Config) Validate() error {
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return fmt.Errorf("listen %q: %w", c.Listen, err)
	}
	if len(c.Ports) == 0 {
		return errors.New("ports must not be empty")
	}
	for _, p := range c.Ports {
		if p < 1 || p > 65535 {
			return fmt.Errorf("port %d out of range", p)
		}
	}
	if c.CA.Key == "" || c.CA.Cert == "" {
		return errors.New("ca.key and ca.cert must be set")
	}
	if c.Redirect.Mark <= 0 {
		return fmt.Errorf("redirect.mark must be > 0, got %d", c.Redirect.Mark)
	}
	if c.Capture.MaxBodyBytes <= 0 {
		return errors.New("capture.max_body_bytes must be > 0")
	}
	if c.Output.Dir == "" || c.Output.JSONL == "" {
		return errors.New("output.dir and output.jsonl must be set")
	}
	return nil
}

func (c Config) MatchDomain(host string) bool {
	if i := strings.LastIndex(host, ":"); i != -1 {
		if _, _, err := net.SplitHostPort(host); err == nil {
			host = host[:i]
		}
	}
	if matchAny(c.Filters.ExcludeDomains, host) {
		return false
	}
	if len(c.Filters.IncludeDomains) == 0 {
		return true
	}
	return matchAny(c.Filters.IncludeDomains, host)
}

func (c Config) MatchComm(comm string) bool {
	for _, p := range c.Filters.ExcludeProcesses {
		if p == comm {
			return false
		}
	}
	return true
}

func (c Config) MatchContentType(ct string) bool {
	if i := strings.IndexByte(ct, ';'); i != -1 {
		ct = ct[:i]
	}
	ct = strings.TrimSpace(ct)
	if matchAny(c.Capture.ExcludeContentTypes, ct) {
		return false
	}
	if len(c.Capture.ContentTypes) == 0 {
		return true
	}
	return matchAny(c.Capture.ContentTypes, ct)
}

func matchAny(patterns []string, s string) bool {
	for _, p := range patterns {
		if ok, err := path.Match(p, s); err == nil && ok {
			return true
		}
	}
	return false
}
