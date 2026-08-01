package installer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/example/mcp-cli/internal/config"
	"github.com/example/mcp-cli/internal/envpolicy"
	"github.com/example/mcp-cli/internal/manifest"
	"github.com/example/mcp-cli/internal/safefs"
)

type Installer struct {
	Registry              *Registry
	Runner                CommandRunner
	ConfigPath            string
	PackagesDir           string
	AllowUnsandboxedCargo bool
}

func New(registry *Registry, configPath string) *Installer {
	return &Installer{
		Registry:    registry,
		Runner:      ExecRunner{},
		ConfigPath:  configPath,
		PackagesDir: filepath.Join(filepath.Dir(configPath), "packages"),
	}
}

func (i *Installer) Install(ctx context.Context, raw string) error {
	spec, err := ParseSpec(raw)
	if err != nil {
		return err
	}
	lock, err := config.AcquireLock(ctx, i.ConfigPath)
	if err != nil {
		return err
	}
	defer lock.Close()

	resolution, err := i.Registry.Resolve(ctx, spec)
	if err != nil {
		return err
	}
	trustedManifest, err := i.Registry.FetchVerifiedManifest(ctx, resolution.Manifest)
	if err != nil {
		return err
	}
	m, err := manifest.Decode(trustedManifest)
	if err != nil {
		return err
	}
	if err := validateManifestIdentity(spec, resolution, m); err != nil {
		return err
	}

	packagesDir, err := safefs.Resolve(i.PackagesDir)
	if err != nil {
		return fmt.Errorf("resolve package directory: %w", err)
	}
	if err := os.MkdirAll(packagesDir, 0o700); err != nil {
		return fmt.Errorf("create package directory: %w", err)
	}
	packagesDir, err = safefs.Resolve(packagesDir)
	if err != nil {
		return fmt.Errorf("resolve package directory: %w", err)
	}
	if err := safefs.RequireDirectory(packagesDir); err != nil {
		return fmt.Errorf("insecure package directory: %w", err)
	}
	if err := os.Chmod(packagesDir, 0o700); err != nil {
		return fmt.Errorf("secure package directory: %w", err)
	}
	stage, err := os.MkdirTemp(packagesDir, ".install-")
	if err != nil {
		return fmt.Errorf("create installation stage: %w", err)
	}
	defer os.RemoveAll(stage)
	if err := i.clonePinned(ctx, packagesDir, stage, resolution.Source); err != nil {
		return err
	}
	if err := validatePackageTree(stage); err != nil {
		return err
	}
	checkedPath, err := safeJoin(stage, "mcp.json")
	if err != nil {
		return err
	}
	checkedManifest, err := os.ReadFile(checkedPath)
	if err != nil {
		return fmt.Errorf("read checked-out mcp.json: %w", err)
	}
	sum := sha256.Sum256(checkedManifest)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), resolution.Manifest.SHA256) {
		return fmt.Errorf("checked-out mcp.json does not match the registry-trusted SHA-256")
	}
	checked, err := manifest.Decode(checkedManifest)
	if err != nil {
		return err
	}
	if err := validateManifestIdentity(spec, resolution, checked); err != nil {
		return err
	}
	if err := os.RemoveAll(filepath.Join(stage, ".git")); err != nil {
		return fmt.Errorf("remove source metadata: %w", err)
	}
	if err := installDependencies(ctx, stage, m, i.Runner, i.AllowUnsandboxedCargo); err != nil {
		return err
	}
	// Dependency tools can create links or special files; do not trust the
	// pre-install checkout validation as a statement about the resulting tree.
	if err := validatePackageTree(stage); err != nil {
		return fmt.Errorf("unsafe post-install package tree: %w", err)
	}
	finalName := fmt.Sprintf("%s-%s", m.Name, strings.ToLower(resolution.Source.Commit[:12]))
	finalPath, err := safeJoin(packagesDir, finalName)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(finalPath); err == nil {
		return fmt.Errorf("package destination already exists: %s", finalPath)
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(stage, finalPath); err != nil {
		return fmt.Errorf("publish package atomically: %w", err)
	}
	pkg := config.Package{Root: finalPath, Command: m.Runtime.Command, Args: append([]string(nil), m.Runtime.Args...), EnvRefs: cloneMap(m.Env)}
	if err := config.RegisterLocked(i.ConfigPath, m.Name, pkg); err != nil {
		_ = os.RemoveAll(finalPath)
		return fmt.Errorf("register package: %w", err)
	}
	return nil
}

func validateManifestIdentity(spec Spec, resolution Resolution, m manifest.Manifest) error {
	if !centralNameRE.MatchString(resolution.Package) {
		return fmt.Errorf("resolved package identity is invalid")
	}
	if spec.Kind == "central" && resolution.Package != spec.Name {
		return fmt.Errorf("resolved package identity does not match the requested package")
	}
	if m.Name != resolution.Package {
		return fmt.Errorf("manifest package name %q does not match resolved package identity %q", m.Name, resolution.Package)
	}
	return nil
}

func (i *Installer) clonePinned(ctx context.Context, workDir, destination string, source SourceMetadata) error {
	env := gitEnvironment()
	cloneArgs := []string{"-c", "core.hooksPath=" + os.DevNull, "-c", "protocol.file.allow=never", "-c", "http.followRedirects=false", "clone", "--no-checkout", "--filter=blob:none", "--", source.URL, destination}
	if err := i.Runner.Run(ctx, workDir, "git", cloneArgs, env); err != nil {
		return fmt.Errorf("clone package: %w", err)
	}
	fetchArgs := []string{"-c", "core.hooksPath=" + os.DevNull, "-c", "protocol.file.allow=never", "-c", "http.followRedirects=false", "-C", destination, "fetch", "--depth=1", "--no-tags", "origin", source.Commit}
	if err := i.Runner.Run(ctx, workDir, "git", fetchArgs, env); err != nil {
		return fmt.Errorf("fetch pinned commit: %w", err)
	}
	checkoutArgs := []string{"-c", "core.hooksPath=" + os.DevNull, "-c", "protocol.file.allow=never", "-c", "http.followRedirects=false", "-C", destination, "checkout", "--detach", source.Commit, "--"}
	if err := i.Runner.Run(ctx, workDir, "git", checkoutArgs, env); err != nil {
		return fmt.Errorf("checkout pinned commit: %w", err)
	}
	var verifier outputRunner
	if err := verifier.run(ctx, destination, env, "git", "-c", "core.hooksPath="+os.DevNull, "-c", "protocol.file.allow=never", "-c", "http.followRedirects=false", "rev-parse", "HEAD"); err != nil {
		return err
	}
	if strings.TrimSpace(verifier.output) != strings.ToLower(source.Commit) {
		return fmt.Errorf("Git checkout did not resolve to the trusted full commit")
	}
	return nil
}

func gitEnvironment() []string {
	env := envpolicy.Minimal()
	return append(env,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ALLOW_PROTOCOL=https",
	)
}

func cloneMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	result := make(map[string]string, len(input))
	for k, v := range input {
		result[k] = v
	}
	return result
}
