package manifest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/example/mcp-cli/internal/envpolicy"
)

const MaxSize = 1 << 20

var (
	nameRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$`)
	envRE  = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
)

type Manifest struct {
	SchemaVersion int               `json:"schemaVersion"`
	Name          string            `json:"name"`
	Version       string            `json:"version"`
	Runtime       Runtime           `json:"runtime"`
	Env           map[string]string `json:"env,omitempty"`
}

type Runtime struct {
	Kind    string   `json:"kind"`
	Command string   `json:"command"`
	Args    []string `json:"args,omitempty"`
}

func Decode(data []byte) (Manifest, error) {
	if len(data) > MaxSize {
		return Manifest{}, fmt.Errorf("manifest exceeds %d bytes", MaxSize)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("decode manifest: %w", err)
	}
	if err := expectEOF(dec); err != nil {
		return Manifest{}, err
	}
	if err := m.Validate(); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

func (m Manifest) Validate() error {
	if m.SchemaVersion != 1 {
		return fmt.Errorf("unsupported schemaVersion %d", m.SchemaVersion)
	}
	if !nameRE.MatchString(m.Name) {
		return fmt.Errorf("invalid package name %q", m.Name)
	}
	if m.Version == "" || len(m.Version) > 128 || hasControl(m.Version) {
		return fmt.Errorf("invalid version")
	}
	switch m.Runtime.Kind {
	case "npm", "python", "cargo", "exec":
	default:
		return fmt.Errorf("unsupported runtime kind %q", m.Runtime.Kind)
	}
	if m.Runtime.Command == "" || len(m.Runtime.Command) > 4096 || strings.ContainsAny(m.Runtime.Command, "\x00\r\n") {
		return fmt.Errorf("invalid runtime command")
	}
	for _, arg := range m.Runtime.Args {
		if len(arg) > 1<<16 || strings.ContainsRune(arg, '\x00') {
			return fmt.Errorf("invalid runtime argument")
		}
	}
	for target, source := range m.Env {
		if !envRE.MatchString(target) || !envRE.MatchString(source) {
			return fmt.Errorf("environment mapping %q -> %q must contain variable names only", target, source)
		}
		if envpolicy.Blocked(target) || envpolicy.Blocked(source) {
			return fmt.Errorf("environment mapping %q -> %q uses a blocked loader/runtime control name", target, source)
		}
	}
	return nil
}

func expectEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("unexpected data after JSON object")
		}
		return fmt.Errorf("decode trailing data: %w", err)
	}
	return nil
}

func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}
