package installer

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	centralNameRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$`)
	githubSpecRE  = regexp.MustCompile(`^([A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?)/([A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?)@([0-9a-fA-F]{40})$`)
)

type Spec struct {
	Raw        string
	Kind       string
	Name       string
	Owner      string
	Repository string
	Commit     string
}

func ParseSpec(value string) (Spec, error) {
	if m := githubSpecRE.FindStringSubmatch(value); m != nil {
		if strings.HasSuffix(strings.ToLower(m[2]), ".git") || strings.Contains(m[2], "..") {
			return Spec{}, fmt.Errorf("GitHub packages must use canonical owner/repository syntax without .git")
		}
		return Spec{Raw: value, Kind: "github", Owner: m[1], Repository: m[2], Commit: strings.ToLower(m[3])}, nil
	}
	if strings.Contains(value, "@") || strings.Contains(value, "/") {
		return Spec{}, fmt.Errorf("GitHub packages must use canonical owner/repository@ followed by a full 40-hex commit")
	}
	if !centralNameRE.MatchString(value) {
		return Spec{}, fmt.Errorf("invalid central package name %q", value)
	}
	return Spec{Raw: value, Kind: "central", Name: value}, nil
}
