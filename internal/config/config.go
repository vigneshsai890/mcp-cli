package config

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/example/mcp-cli/internal/envpolicy"
	"github.com/example/mcp-cli/internal/safefs"
)

const (
	Version       = 1
	MaxConfigSize = 1 << 20
	lockWait      = 10 * time.Second
)

var envNameRE = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

type Config struct {
	Version  int                `json:"version"`
	Packages map[string]Package `json:"packages"`
}

type Package struct {
	Root    string            `json:"root"`
	Command string            `json:"command"`
	Args    []string          `json:"args,omitempty"`
	EnvRefs map[string]string `json:"envRefs,omitempty"`
}

type Lock struct {
	file *os.File
}

func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("find home directory: %w", err)
	}
	return filepath.Join(home, ".mcp", "config.json"), nil
}

// ResolvePath canonicalizes existing directory ancestors while preserving the
// final filename so a symlink in that final position can be rejected.
func ResolvePath(path string) (string, error) {
	dir, err := safefs.Resolve(filepath.Dir(path))
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, filepath.Base(path)), nil
}

func Load(path string) (Config, error) {
	path, err := ResolvePath(path)
	if err != nil {
		return Config{}, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return Config{Version: Version, Packages: make(map[string]Package)}, nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("inspect config: %w", err)
	}
	if err := safefs.RequireRegular(path, 0o600); err != nil {
		return Config{}, fmt.Errorf("insecure config: %w", err)
	}
	if info.Size() > MaxConfigSize {
		return Config{}, fmt.Errorf("config exceeds %d bytes", MaxConfigSize)
	}
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open config: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, MaxConfigSize+1))
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	if len(data) > MaxConfigSize {
		return Config{}, fmt.Errorf("config exceeds %d bytes", MaxConfigSize)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return Config{}, fmt.Errorf("config has trailing JSON data")
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if c.Version != Version {
		return fmt.Errorf("unsupported config version %d", c.Version)
	}
	if c.Packages == nil {
		return fmt.Errorf("packages must be an object")
	}
	for name, pkg := range c.Packages {
		if name == "" || !filepath.IsAbs(pkg.Root) || pkg.Command == "" {
			return fmt.Errorf("invalid package entry %q", name)
		}
		for target, source := range pkg.EnvRefs {
			if !envNameRE.MatchString(target) || !envNameRE.MatchString(source) || envpolicy.Blocked(target) || envpolicy.Blocked(source) {
				return fmt.Errorf("package %q contains an invalid or blocked environment reference", name)
			}
		}
	}
	return nil
}

// AcquireLock takes a per-config advisory lock. Kernel locks disappear when a
// process dies, so stale lock files cannot wedge future installs. Waiting is
// bounded even when the caller did not provide a deadline.
func AcquireLock(ctx context.Context, configPath string) (*Lock, error) {
	configPath, err := ResolvePath(configPath)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create config directory: %w", err)
	}
	dir, err = safefs.Resolve(dir)
	if err != nil {
		return nil, err
	}
	if err := safefs.RequireDirectory(dir); err != nil {
		return nil, fmt.Errorf("insecure config directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("secure config directory: %w", err)
	}
	lockPath := filepath.Join(dir, ".install.lock")
	deadline := time.Now().Add(lockWait)
	if existing, ok := ctx.Deadline(); ok && existing.Before(deadline) {
		deadline = existing
	}
	for {
		file, err := openLockFile(lockPath)
		if err != nil {
			return nil, err
		}
		acquired, lockErr := tryLock(file)
		if lockErr != nil {
			_ = file.Close()
			return nil, fmt.Errorf("lock config: %w", lockErr)
		}
		if acquired {
			pathInfo, statErr := os.Lstat(lockPath)
			fileInfo, fileErr := file.Stat()
			if statErr == nil && fileErr == nil && os.SameFile(pathInfo, fileInfo) {
				return &Lock{file: file}, nil
			}
			_ = unlockFile(file)
		}
		_ = file.Close()
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timed out waiting for config/install lock")
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("wait for config/install lock: %w", ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func openLockFile(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL|noFollowFlag(), 0o600)
	if err == nil {
		if chmodErr := file.Chmod(0o600); chmodErr != nil {
			_ = file.Close()
			return nil, fmt.Errorf("secure config lock: %w", chmodErr)
		}
	} else if errors.Is(err, os.ErrExist) {
		file, err = os.OpenFile(path, os.O_RDWR|noFollowFlag(), 0)
	}
	if err != nil {
		return nil, fmt.Errorf("open config lock: %w", err)
	}
	if err := safefs.RequireRegular(path, 0o600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("insecure config lock: %w", err)
	}
	fileInfo, err := file.Stat()
	if err != nil || !fileInfo.Mode().IsRegular() || fileInfo.Mode().Perm() != 0o600 {
		_ = file.Close()
		return nil, fmt.Errorf("insecure opened config lock")
	}
	if links, ok := safefs.LinkCount(fileInfo); ok && links != 1 {
		_ = file.Close()
		return nil, fmt.Errorf("config lock must have exactly one hard link")
	}
	return file, nil
}

func (lock *Lock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	err := unlockFile(lock.file)
	closeErr := lock.file.Close()
	lock.file = nil
	if err != nil {
		return err
	}
	return closeErr
}

func Register(path, name string, pkg Package) error {
	ctx, cancel := context.WithTimeout(context.Background(), lockWait)
	defer cancel()
	lock, err := AcquireLock(ctx, path)
	if err != nil {
		return err
	}
	defer lock.Close()
	return RegisterLocked(path, name, pkg)
}

// RegisterLocked updates config while the caller holds AcquireLock.
func RegisterLocked(path, name string, pkg Package) error {
	cfg, err := Load(path)
	if err != nil {
		return err
	}
	cfg.Packages[name] = pkg
	if err := cfg.Validate(); err != nil {
		return err
	}
	return writeAtomic(path, cfg)
}

func writeAtomic(path string, cfg Config) error {
	path, err := ResolvePath(path)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := safefs.RequireDirectory(dir); err != nil {
		return fmt.Errorf("insecure config directory: %w", err)
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing non-regular config path")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect config path: %w", err)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	data = append(data, '\n')
	if len(data) > MaxConfigSize {
		return fmt.Errorf("config exceeds %d bytes", MaxConfigSize)
	}
	tmp, err := os.OpenFile(filepath.Join(dir, ".config-"+randomSuffix()), os.O_WRONLY|os.O_CREATE|os.O_EXCL|noFollowFlag(), 0o600)
	if err != nil {
		return fmt.Errorf("create temporary config: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err = tmp.Write(data); err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err != nil {
		return fmt.Errorf("write temporary config: %w", err)
	}
	if closeErr != nil {
		return fmt.Errorf("close temporary config: %w", closeErr)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace config: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("secure config: %w", err)
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func randomSuffix() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return fmt.Sprintf("%d", os.Getpid())
	}
	return hex.EncodeToString(value[:])
}
