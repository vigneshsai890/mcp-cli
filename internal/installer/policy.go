package installer

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/example/mcp-cli/internal/envpolicy"
	"github.com/example/mcp-cli/internal/manifest"
	"github.com/example/mcp-cli/internal/safefs"
)

type CommandRunner interface {
	Run(ctx context.Context, dir, name string, args []string, env []string) error
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, dir, name string, args []string, env []string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("execute %s: %w", name, err)
	}
	return nil
}

func installDependencies(ctx context.Context, root string, m manifest.Manifest, runner CommandRunner, allowUnsafeCargo ...bool) error {
	env := envpolicy.Minimal()
	cargoAllowed := len(allowUnsafeCargo) != 0 && allowUnsafeCargo[0]
	switch m.Runtime.Kind {
	case "npm":
		if err := requireRegular(root, "package-lock.json"); err != nil {
			return fmt.Errorf("npm packages require package-lock.json: %w", err)
		}
		return runner.Run(ctx, root, "npm", []string{"ci", "--ignore-scripts", "--no-audit", "--no-fund"}, env)
	case "python":
		lock := filepath.Join(root, "requirements.lock")
		if err := requireRegular(root, "requirements.lock"); err != nil {
			return fmt.Errorf("Python packages require requirements.lock: %w", err)
		}
		if err := validatePipLock(lock); err != nil {
			return err
		}
		return runner.Run(ctx, root, "python3", []string{"-m", "pip", "install", "--require-hashes", "--only-binary=:all:", "--no-deps", "--target", ".mcp-deps", "-r", "requirements.lock"}, env)
	case "cargo":
		if !cargoAllowed {
			return fmt.Errorf("Cargo installation is disabled because build.rs executes unsandboxed code; explicitly set MCP_ALLOW_UNSANDBOXED_CARGO=1 to accept this residual risk")
		}
		if err := requireRegular(root, "Cargo.lock"); err != nil {
			return fmt.Errorf("Cargo packages require Cargo.lock: %w", err)
		}
		return runner.Run(ctx, root, "cargo", []string{"build", "--locked"}, env)
	case "exec":
		return nil
	default:
		return fmt.Errorf("unsupported runtime %q", m.Runtime.Kind)
	}
}

func requireRegular(root, name string) error {
	p, err := safeJoin(root, name)
	if err != nil {
		return err
	}
	if err := safefs.RequireRegular(p, 0); err != nil {
		return fmt.Errorf("%s is not a safe regular file: %w", name, err)
	}
	return nil
}

var hashRE = regexp.MustCompile(`--hash=sha256:[0-9a-fA-F]{64}(?:\s|$)`)

func validatePipLock(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	var logical string
	entries := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		logical += " " + strings.TrimSuffix(line, "\\")
		if strings.HasSuffix(line, "\\") {
			continue
		}
		entry := strings.TrimSpace(logical)
		logical = ""
		withoutHashes := hashRE.ReplaceAllString(entry+" ", "")
		if strings.HasPrefix(entry, "-") || strings.Contains(entry, "://") || strings.Contains(entry, " @ ") || strings.Contains(withoutHashes, "--") || !strings.Contains(entry, "==") || !hashRE.MatchString(entry+" ") {
			return fmt.Errorf("requirements.lock entries must be exact pins with sha256 hashes and no URLs or options")
		}
		entries++
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if logical != "" || entries == 0 {
		return fmt.Errorf("requirements.lock is empty or has an incomplete continuation")
	}
	return nil
}

func safeJoin(root, relative string) (string, error) {
	if relative == "" || filepath.IsAbs(relative) {
		return "", fmt.Errorf("unsafe path %q", relative)
	}
	clean := filepath.Clean(relative)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("unsafe path %q", relative)
	}
	joined := filepath.Join(root, clean)
	rel, err := filepath.Rel(root, joined)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes package root")
	}
	return joined, nil
}

func validatePackageTree(root string) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		mode := info.Mode()
		if mode&os.ModeSymlink != 0 {
			return fmt.Errorf("package contains forbidden symlink %q", path)
		}
		if mode.IsDir() {
			return nil
		}
		if !mode.IsRegular() {
			return fmt.Errorf("package contains forbidden special file %q", path)
		}
		if links, ok := safefs.LinkCount(info); ok && links != 1 {
			return fmt.Errorf("package contains multiply-linked regular file %q", path)
		}
		return nil
	})
}

// Kept as a narrow compatibility helper for callers/tests of the original policy.
func rejectSymlinks(root string) error {
	return validatePackageTree(root)
}
