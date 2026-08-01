//go:build !darwin && !linux

package config

import (
	"fmt"
	"os"
	"runtime"
)

func noFollowFlag() int { return 0 }

func tryLock(_ *os.File) (bool, error) {
	return false, fmt.Errorf("mcp-cli config locking is unsupported on %s", runtime.GOOS)
}

func unlockFile(_ *os.File) error { return nil }
