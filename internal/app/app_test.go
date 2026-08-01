package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveEnvUsesReferenceAtRuntime(t *testing.T) {
	t.Setenv("MCP_TEST_SOURCE", "runtime-value")
	env, err := resolveEnv(map[string]string{"TOKEN": "MCP_TEST_SOURCE"})
	if err != nil {
		t.Fatal(err)
	}
	if !contains(env, "TOKEN=runtime-value") {
		t.Fatalf("resolved env missing mapped value: %q", env)
	}
	if _, err := resolveEnv(map[string]string{"TOKEN": "MCP_DEFINITELY_MISSING"}); err == nil {
		t.Fatal("missing reference unexpectedly succeeded")
	}
}

func TestSafeCommandRejectsTraversalAndSymlink(t *testing.T) {
	dir := t.TempDir()
	if _, err := safeCommand(dir, "../tool"); err == nil {
		t.Fatal("traversal unexpectedly succeeded")
	}
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := safeCommand(dir, "./link"); err == nil {
		t.Fatal("symlink command unexpectedly succeeded")
	}
}

func contains(items []string, want string) bool {
	for _, item := range items {
		if strings.EqualFold(item, want) {
			return true
		}
	}
	return false
}

func TestResolveEnvExcludesUndeclaredSecrets(t *testing.T) {
	t.Setenv("AWS_SECRET_ACCESS_KEY", "must-not-leak")
	t.Setenv("MCP_DECLARED_SECRET", "declared-value")
	env, err := resolveEnv(map[string]string{"API_TOKEN": "MCP_DECLARED_SECRET"})
	if err != nil {
		t.Fatal(err)
	}
	if containsKey(env, "AWS_SECRET_ACCESS_KEY") {
		t.Fatalf("undeclared host secret leaked into child environment: %q", env)
	}
	if !contains(env, "API_TOKEN=declared-value") {
		t.Fatalf("declared environment mapping missing: %q", env)
	}
	if _, err := resolveEnv(map[string]string{"LD_PRELOAD": "MCP_DECLARED_SECRET"}); err == nil {
		t.Fatal("loader control environment target unexpectedly accepted")
	}
}

func TestSafeCommandRejectsSymlinkedParentComponent(t *testing.T) {
	root := t.TempDir()
	realBin := filepath.Join(root, "real-bin")
	if err := os.Mkdir(realBin, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(realBin, "tool"), []byte("x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realBin, filepath.Join(root, "bin")); err != nil {
		t.Fatal(err)
	}
	if _, err := safeCommand(root, "./bin/tool"); err == nil {
		t.Fatal("command beneath symlinked parent unexpectedly accepted")
	}
}

func containsKey(items []string, key string) bool {
	prefix := key + "="
	for _, item := range items {
		if strings.HasPrefix(item, prefix) {
			return true
		}
	}
	return false
}
