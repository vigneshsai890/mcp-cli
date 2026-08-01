package config

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestRegisterStoresReferencesAtomicallyAt0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".mcp", "config.json")
	secret := "do-not-persist-this-secret"
	t.Setenv("HOST_TOKEN", secret)
	pkg := Package{Root: filepath.Join(dir, "packages", "tool"), Command: "node", Args: []string{"server.js"}, EnvRefs: map[string]string{"TOKEN": "HOST_TOKEN"}}
	if err := Register(path, "tool", pkg); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) || !strings.Contains(string(data), "HOST_TOKEN") {
		t.Fatalf("config should contain the reference but not its value: %s", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
	cfg, err := Load(path)
	if err != nil || cfg.Packages["tool"].EnvRefs["TOKEN"] != "HOST_TOKEN" {
		t.Fatalf("Load() = %#v, %v", cfg, err)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"packages":{},"secret":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load unexpectedly accepted unknown field")
	}
}

func TestRegisterRefusesSymlinkTarget(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.WriteFile(real, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	if err := os.Symlink(real, path); err != nil {
		t.Fatal(err)
	}
	err := Register(path, "tool", Package{Root: filepath.Join(dir, "tool"), Command: "tool"})
	if err == nil {
		t.Fatal("Register unexpectedly followed symlink")
	}
}

func TestRegisterConcurrentUpdatesAreNotLost(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".mcp", "config.json")
	const count = 16
	var wg sync.WaitGroup
	errors := make(chan error, count)
	for index := 0; index < count; index++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			name := fmt.Sprintf("tool-%02d", index)
			errors <- Register(path, name, Package{Root: filepath.Join(dir, "packages", name), Command: "tool"})
		}(index)
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Packages) != count {
		t.Fatalf("registered package count = %d, want %d", len(cfg.Packages), count)
	}
}

func TestRegisterResolvesSymlinkedConfigParent(t *testing.T) {
	dir := t.TempDir()
	realParent := filepath.Join(dir, "real")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(realParent, alias); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(alias, "config.json")
	if err := Register(path, "tool", Package{Root: filepath.Join(dir, "tool"), Command: "tool"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(realParent, "config.json")); err != nil {
		t.Fatalf("config was not written through canonical parent: %v", err)
	}
}

func TestLoadCapsConfigSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, MaxConfigSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized config error = %v", err)
	}
}

func TestAcquireLockRejectsInsecureLockFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".mcp")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".install.lock"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	lock, err := AcquireLock(context.Background(), filepath.Join(dir, "config.json"))
	if lock != nil {
		lock.Close()
	}
	if err == nil {
		t.Fatal("insecure lock file unexpectedly accepted")
	}
}
