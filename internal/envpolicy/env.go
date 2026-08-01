package envpolicy

import (
	"os"
	"sort"
	"strings"
)

// inheritedNames is deliberately small. Package children do not inherit arbitrary
// credentials or tool-specific configuration from the mcp process.
var inheritedNames = []string{
	"HOME", "LANG", "LC_ALL", "LC_CTYPE", "PATH", "SystemRoot", "TEMP", "TMP", "TMPDIR", "TZ", "USERPROFILE", "WINDIR",
}

var blockedExact = map[string]struct{}{
	"BASH_ENV": {}, "CDPATH": {}, "CLASSPATH": {}, "ENV": {}, "GCONV_PATH": {},
	"HOSTALIASES": {}, "HOME": {}, "IFS": {}, "JAVA_TOOL_OPTIONS": {}, "JDK_JAVA_OPTIONS": {},
	"LIBPATH": {}, "LOCPATH": {}, "MCP_ALLOW_UNSANDBOXED_CARGO": {}, "NLSPATH": {},
	"NODE_OPTIONS": {}, "NODE_PATH": {}, "PATH": {}, "PERL5LIB": {}, "PERLLIB": {}, "PERL5OPT": {}, "PS4": {},
	"PYTHONHOME": {}, "PYTHONINSPECT": {}, "PYTHONPATH": {}, "PYTHONSTARTUP": {},
	"RUBYLIB": {}, "RUBYOPT": {}, "SHLIB_PATH": {}, "SHELLOPTS": {}, "SYSTEMROOT": {},
	"TEMP": {}, "TMP": {}, "TMPDIR": {}, "USERPROFILE": {}, "WINDIR": {}, "_JAVA_OPTIONS": {},
}

var blockedPrefixes = []string{"DYLD_", "LD_", "LDR_", "_RLD_"}

// Blocked reports whether name can alter a loader or language runtime before
// the package's own code starts.
func Blocked(name string) bool {
	upper := strings.ToUpper(name)
	if _, ok := blockedExact[upper]; ok {
		return true
	}
	for _, prefix := range blockedPrefixes {
		if strings.HasPrefix(upper, prefix) {
			return true
		}
	}
	return false
}

// Minimal returns only benign process essentials from the host environment.
func Minimal() []string {
	env := make([]string, 0, len(inheritedNames))
	for _, name := range inheritedNames {
		if value, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+value)
		}
	}
	sort.Strings(env)
	return env
}
