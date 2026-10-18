//go:build integration

package redirect

import (
	"os/exec"
	"strings"
	"testing"
)

// TestNftGeneratedCommandsParse validates the exact argv produced by NftManager
// against the real nft binary's parser. Syntax errors surface before the
// permission check, so this works unprivileged: a well-formed command fails
// with "Operation not permitted", a malformed one with "syntax error".
func TestNftGeneratedCommandsParse(t *testing.T) {
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed")
	}
	r := &fakeRunner{}
	if err := NewNft(r, testCfg()).On(); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) == 0 {
		t.Fatal("no commands generated")
	}
	for _, c := range r.calls {
		out, err := exec.Command(c.name, c.args...).CombinedOutput()
		if err == nil {
			continue
		}
		lower := strings.ToLower(string(out))
		if strings.Contains(lower, "syntax error") {
			t.Fatalf("nft rejects %v:\n%s", c.args, out)
		}
		if !strings.Contains(lower, "operation not permitted") &&
			!strings.Contains(lower, "permission denied") {
			t.Fatalf("unexpected nft failure for %v: %s", c.args, out)
		}
	}
}
