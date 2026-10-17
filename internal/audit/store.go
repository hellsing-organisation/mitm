package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
)

type Store struct {
	dir    string
	jsonl  string
	mu     sync.Mutex
	f      *os.File
	w      *bufio.Writer
	dayDir string
}

func OpenStore(dir, jsonl string) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dir, "bodies"), 0o755); err != nil {
		return nil, fmt.Errorf("create store dir: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(dir, jsonl), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open jsonl: %w", err)
	}
	return &Store{dir: dir, jsonl: jsonl, f: f, w: bufio.NewWriter(f)}, nil
}

func (s *Store) WriteEvent(e Event) error {
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return fmt.Errorf("store closed")
	}
	if _, err := s.w.Write(append(line, '\n')); err != nil {
		return err
	}
	return s.w.Flush()
}

func (s *Store) SaveBody(kind string, data []byte) (string, error) {
	day := time.Now().UTC().Format("2006-01-02")
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dayDir != day {
		if err := os.MkdirAll(filepath.Join(s.dir, "bodies", day), 0o755); err != nil {
			return "", err
		}
		s.dayDir = day
	}
	rel := filepath.Join("bodies", day, uuid.NewString()+"."+kind)
	if err := os.WriteFile(filepath.Join(s.dir, rel), data, 0o644); err != nil {
		return "", err
	}
	return rel, nil
}

func (s *Store) Path() string {
	return filepath.Join(s.dir, s.jsonl)
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	err := s.w.Flush()
	cerr := s.f.Close()
	s.f = nil
	if err != nil {
		return err
	}
	return cerr
}
