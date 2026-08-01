package app

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/example/mcp-cli/internal/config"
	"github.com/example/mcp-cli/internal/envpolicy"
	"github.com/example/mcp-cli/internal/installer"
	"github.com/example/mcp-cli/internal/safefs"
)

type runningProcess struct {
	name string
	cmd  *exec.Cmd
}

type App struct {
	Registry   *installer.Registry
	Installer  *installer.Installer
	ConfigPath string
	Out        io.Writer
	Err        io.Writer
}

func (a *App) Search(ctx context.Context, query string) error {
	results, err := a.Registry.Search(ctx, query)
	if err != nil {
		return err
	}
	if len(results) == 0 {
		fmt.Fprintln(a.Out, "No packages found.")
		return nil
	}
	for _, result := range results {
		fmt.Fprintf(a.Out, "%s\t%s\t%s\n", result.Name, result.Version, result.Description)
	}
	return nil
}

func (a *App) Start(ctx context.Context) error {
	cfg, err := config.Load(a.ConfigPath)
	if err != nil {
		return err
	}
	if len(cfg.Packages) == 0 {
		return fmt.Errorf("no MCP packages installed")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	names := make([]string, 0, len(cfg.Packages))
	for name := range cfg.Packages {
		names = append(names, name)
	}
	sort.Strings(names)
	processes := make([]runningProcess, 0, len(names))
	for _, name := range names {
		pkg := cfg.Packages[name]
		root, err := safeRoot(pkg.Root)
		if err != nil {
			return fmt.Errorf("package %s: %w", name, err)
		}
		command, err := safeCommand(root, pkg.Command)
		if err != nil {
			return fmt.Errorf("package %s: %w", name, err)
		}
		env, err := resolveEnv(pkg.EnvRefs)
		if err != nil {
			return fmt.Errorf("package %s: %w", name, err)
		}
		cmd := exec.CommandContext(ctx, command, pkg.Args...)
		cmd.Dir = root
		cmd.Env = env
		cmd.Stdin = os.Stdin
		cmd.Stdout = a.Out
		cmd.Stderr = a.Err
		if err := cmd.Start(); err != nil {
			cancel()
			waitAll(processes)
			return fmt.Errorf("start package %s: %w", name, err)
		}
		processes = append(processes, runningProcess{name: name, cmd: cmd})
		fmt.Fprintf(a.Err, "started %s (pid %d)\n", name, cmd.Process.Pid)
	}
	results := make(chan error, len(processes))
	var wg sync.WaitGroup
	for _, process := range processes {
		wg.Add(1)
		go func(p runningProcess) {
			defer wg.Done()
			if err := p.cmd.Wait(); err != nil && ctx.Err() == nil {
				results <- fmt.Errorf("package %s exited: %w", p.name, err)
				cancel()
			}
		}(process)
	}
	wg.Wait()
	close(results)
	for err := range results {
		return err
	}
	return ctx.Err()
}

func resolveEnv(refs map[string]string) ([]string, error) {
	envMap := make(map[string]string)
	for _, item := range envpolicy.Minimal() {
		if index := strings.IndexByte(item, '='); index >= 0 {
			envMap[item[:index]] = item[index+1:]
		}
	}
	for target, source := range refs {
		if envpolicy.Blocked(target) || envpolicy.Blocked(source) {
			return nil, fmt.Errorf("blocked loader/runtime environment mapping %s -> %s", target, source)
		}
		value, ok := os.LookupEnv(source)
		if !ok {
			return nil, fmt.Errorf("required environment variable %s is not set", source)
		}
		envMap[target] = value
	}
	result := make([]string, 0, len(envMap))
	for key, value := range envMap {
		result = append(result, key+"="+value)
	}
	sort.Strings(result)
	return result, nil
}

func safeRoot(root string) (string, error) {
	resolvedRoot, err := safefs.Resolve(root)
	if err != nil {
		return "", fmt.Errorf("resolve package root: %w", err)
	}
	if err := safefs.RequireDirectory(resolvedRoot); err != nil {
		return "", fmt.Errorf("invalid package root: %w", err)
	}
	return resolvedRoot, nil
}

func safeCommand(root, command string) (string, error) {
	if strings.ContainsAny(command, "\x00\r\n") {
		return "", fmt.Errorf("invalid command")
	}
	resolvedRoot, err := safeRoot(root)
	if err != nil {
		return "", err
	}
	if !strings.ContainsRune(command, filepath.Separator) {
		return command, nil
	}
	if filepath.IsAbs(command) {
		return "", fmt.Errorf("manifest commands containing paths must be relative")
	}
	clean := filepath.Clean(command)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("command escapes package root")
	}
	full, err := safefs.JoinNoSymlinks(resolvedRoot, clean)
	if err != nil {
		return "", fmt.Errorf("inspect command path: %w", err)
	}
	info, err := os.Lstat(full)
	if err != nil {
		return "", fmt.Errorf("inspect command: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("command must be a regular non-symlink file")
	}
	if links, ok := safefs.LinkCount(info); ok && links != 1 {
		return "", fmt.Errorf("command must not be multiply linked")
	}
	return full, nil
}

func waitAll(processes []runningProcess) {
	for _, process := range processes {
		_ = process.cmd.Wait()
	}
}
