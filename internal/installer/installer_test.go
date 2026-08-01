package installer

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/example/mcp-cli/internal/manifest"
)

func TestParseSpecRequiresFullCommit(t *testing.T) {
	commit := strings.Repeat("a", 40)
	got, err := ParseSpec("owner/repo@" + commit)
	if err != nil || got.Kind != "github" || got.Commit != commit {
		t.Fatalf("ParseSpec() = %#v, %v", got, err)
	}
	for _, bad := range []string{"owner/repo@main", "owner/repo@abc123", "https://github.com/owner/repo", "../tool"} {
		if _, err := ParseSpec(bad); err == nil {
			t.Errorf("ParseSpec(%q) unexpectedly succeeded", bad)
		}
	}
}

func TestRegistryURLAllowlist(t *testing.T) {
	r, err := NewRegistry("https://registry.example", []string{"registry.example"})
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"http://registry.example/v1", "https://evil.example/v1", "https://registry.example:444/v1", "https://user@registry.example/v1"} {
		u, _ := r.base.Parse(raw)
		if err := r.validateRegistryURL(u); err == nil {
			t.Errorf("validateRegistryURL(%q) unexpectedly succeeded", raw)
		}
	}
}

func TestValidatePipLock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "requirements.lock")
	good := "example==1.2.3 --hash=sha256:" + strings.Repeat("a", 64) + "\n"
	if err := os.WriteFile(path, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validatePipLock(path); err != nil {
		t.Fatal(err)
	}
	bad := []string{"example>=1\n", "example==1 https://evil.invalid/x.whl --hash=sha256:" + strings.Repeat("a", 64), "--index-url https://evil.invalid\n"}
	for _, content := range bad {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := validatePipLock(path); err == nil {
			t.Errorf("validatePipLock unexpectedly accepted %q", content)
		}
	}
}

func TestRejectSymlinksAndUnsafePaths(t *testing.T) {
	dir := t.TempDir()
	if _, err := safeJoin(dir, "../escape"); err == nil {
		t.Fatal("safeJoin accepted traversal")
	}
	if err := os.Symlink("target", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := rejectSymlinks(dir); err == nil {
		t.Fatal("rejectSymlinks accepted symlink")
	}
}

type recordingRunner struct {
	calls int
	env   []string
}

func (runner *recordingRunner) Run(context.Context, string, string, []string, []string) error {
	runner.calls++
	return nil
}

func TestManifestNameMustMatchRequestedAndResolvedIdentity(t *testing.T) {
	spec, err := ParseSpec("requested")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateManifestIdentity(spec, Resolution{Package: "other"}, manifest.Manifest{Name: "other"}); err == nil {
		t.Fatal("resolved identity mismatch unexpectedly accepted")
	}
	if err := validateManifestIdentity(spec, Resolution{Package: "requested"}, manifest.Manifest{Name: "other"}); err == nil {
		t.Fatal("manifest identity mismatch unexpectedly accepted")
	}
	if err := validateManifestIdentity(spec, Resolution{Package: "requested"}, manifest.Manifest{Name: "requested"}); err != nil {
		t.Fatalf("matching identities rejected: %v", err)
	}
}

func TestPostInstallTreeRejectsLinksAndSpecialFiles(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Symlink("target", filepath.Join(dir, "link")); err != nil {
			t.Fatal(err)
		}
		if err := validatePackageTree(dir); err == nil {
			t.Fatal("post-install symlink unexpectedly accepted")
		}
	})
	t.Run("hardlink", func(t *testing.T) {
		dir := t.TempDir()
		first := filepath.Join(dir, "first")
		if err := os.WriteFile(first, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(first, filepath.Join(dir, "second")); err != nil {
			t.Fatal(err)
		}
		if err := validatePackageTree(dir); err == nil {
			t.Fatal("multiply-linked post-install file unexpectedly accepted")
		}
	})
	t.Run("special", func(t *testing.T) {
		dir := t.TempDir()
		fifo := filepath.Join(dir, "pipe")
		if err := syscall.Mkfifo(fifo, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := validatePackageTree(dir); err == nil {
			t.Fatal("post-install FIFO unexpectedly accepted")
		}
	})
}

func TestCargoRequiresExplicitOptIn(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Cargo.lock"), []byte("# lock"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := manifest.Manifest{Runtime: manifest.Runtime{Kind: "cargo"}}
	runner := &recordingRunner{}
	if err := installDependencies(context.Background(), dir, m, runner); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("Cargo without opt-in error = %v", err)
	}
	if runner.calls != 0 {
		t.Fatal("Cargo executed without opt-in")
	}
	if err := installDependencies(context.Background(), dir, m, runner, true); err != nil {
		t.Fatalf("opted-in Cargo rejected: %v", err)
	}
	if runner.calls != 1 {
		t.Fatalf("Cargo call count = %d, want 1", runner.calls)
	}
}

func TestSpecialPurposeIPsAreUnsafe(t *testing.T) {
	for _, raw := range []string{
		"100.64.0.1", "192.0.2.1", "198.19.0.1", "198.51.100.1", "203.0.113.1", "240.0.0.1",
		"2001:db8::1", "2002::1", "64:ff9b:1::1", "64:ff9b::7f00:1", "64:ff9b::a00:1", "64:ff9b::c000:201", "::ffff:192.0.2.1",
	} {
		if !unsafeIP(netip.MustParseAddr(raw)) {
			t.Errorf("unsafeIP(%s) = false", raw)
		}
	}
	for _, raw := range []string{"8.8.8.8", "2606:4700:4700::1111"} {
		if unsafeIP(netip.MustParseAddr(raw)) {
			t.Errorf("unsafeIP(%s) = true for public address", raw)
		}
	}
}

func TestParseSpecRejectsNonCanonicalGitHubNames(t *testing.T) {
	commit := strings.Repeat("a", 40)
	for _, raw := range []string{
		"owner-/repo@" + commit,
		"owner/.repo@" + commit,
		"owner/repo.git@" + commit,
		"owner/repo..name@" + commit,
		"owner/repo/@" + commit,
	} {
		if _, err := ParseSpec(raw); err == nil {
			t.Errorf("ParseSpec(%q) unexpectedly accepted noncanonical syntax", raw)
		}
	}
}

func TestInstallerChildEnvironmentExcludesHostSecrets(t *testing.T) {
	t.Setenv("AWS_SECRET_ACCESS_KEY", "do-not-inherit")
	for _, item := range gitEnvironment() {
		if strings.HasPrefix(item, "AWS_SECRET_ACCESS_KEY=") {
			t.Fatalf("Git environment leaked host secret: %q", item)
		}
	}
}

func TestVerifierWriterCapsOutput(t *testing.T) {
	var writer cappedWriter
	payload := make([]byte, maxVerifierOutput+128)
	if count, err := writer.Write(payload); err != nil || count != len(payload) {
		t.Fatalf("Write() = %d, %v", count, err)
	}
	if !writer.exceeded || len(writer.data) != maxVerifierOutput {
		t.Fatalf("capped writer state = exceeded %v, bytes %d", writer.exceeded, len(writer.data))
	}
}
