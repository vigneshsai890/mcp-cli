package safefs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
)

// Resolve resolves every existing ancestor and appends any not-yet-existing
// suffix. Callers must use the returned path, rather than checking one path and
// operating through a potentially symlinked alias.
func Resolve(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("make path absolute: %w", err)
	}
	current := filepath.Clean(absolute)
	var missing []string
	for {
		_, err := os.Lstat(current)
		if err == nil {
			resolved, err := filepath.EvalSymlinks(current)
			if err != nil {
				return "", fmt.Errorf("resolve path ancestors: %w", err)
			}
			for index := len(missing) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, missing[index])
			}
			return filepath.Clean(resolved), nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("inspect path ancestor: %w", err)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("no existing ancestor for %q", path)
		}
		missing = append(missing, filepath.Base(current))
		current = parent
	}
}

func RequireDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%q is not a non-symlink directory", path)
	}
	return nil
}

func RequireRegular(path string, requiredMode os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("%q is not a non-symlink regular file", path)
	}
	if links, ok := LinkCount(info); ok && links != 1 {
		return fmt.Errorf("%q must have exactly one hard link", path)
	}
	if requiredMode != 0 && info.Mode().Perm() != requiredMode.Perm() {
		return fmt.Errorf("%q has mode %04o; require %04o", path, info.Mode().Perm(), requiredMode.Perm())
	}
	return nil
}

// LinkCount extracts the portable Nlink field supplied by supported Unix
// os.FileInfo implementations without binding this package to one Stat_t ABI.
func LinkCount(info os.FileInfo) (uint64, bool) {
	value := reflect.ValueOf(info.Sys())
	if !value.IsValid() {
		return 0, false
	}
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return 0, false
		}
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		return 0, false
	}
	field := value.FieldByName("Nlink")
	if !field.IsValid() {
		return 0, false
	}
	switch field.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return field.Uint(), true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if field.Int() < 0 {
			return 0, false
		}
		return uint64(field.Int()), true
	default:
		return 0, false
	}
}

// JoinNoSymlinks joins relative beneath root and rejects every existing
// component that is a symlink. root itself should already be canonical.
func JoinNoSymlinks(root, relative string) (string, error) {
	if relative == "" || filepath.IsAbs(relative) {
		return "", fmt.Errorf("unsafe relative path %q", relative)
	}
	clean := filepath.Clean(relative)
	if clean == "." || clean == ".." || len(clean) > 3 && clean[:3] == ".."+string(filepath.Separator) {
		return "", fmt.Errorf("unsafe relative path %q", relative)
	}
	current := root
	parts := splitPath(clean)
	for index, part := range parts {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("path contains forbidden symlink %q", current)
		}
		if index < len(parts)-1 && !info.IsDir() {
			return "", fmt.Errorf("path ancestor %q is not a directory", current)
		}
	}
	return current, nil
}

func splitPath(path string) []string {
	var parts []string
	for path != "." && path != string(filepath.Separator) {
		dir, base := filepath.Split(path)
		if base != "" {
			parts = append([]string{base}, parts...)
		}
		path = filepath.Clean(dir)
	}
	return parts
}
