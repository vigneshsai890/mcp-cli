package cli

import "testing"

func TestParseExactCommands(t *testing.T) {
	tests := []struct {
		args []string
		want Command
	}{
		{[]string{"install", "tool"}, Command{Name: "install", Value: "tool"}},
		{[]string{"search", "database"}, Command{Name: "search", Value: "database"}},
		{[]string{"start"}, Command{Name: "start"}},
	}
	for _, tt := range tests {
		got, err := Parse(tt.args)
		if err != nil || got != tt.want {
			t.Fatalf("Parse(%q) = %#v, %v; want %#v", tt.args, got, err, tt.want)
		}
	}
}

func TestParseRejectsOtherForms(t *testing.T) {
	bad := [][]string{nil, {"install"}, {"install", "a", "b"}, {"search"}, {"search", "a", "b"}, {"start", "now"}, {"help"}}
	for _, args := range bad {
		if _, err := Parse(args); err == nil {
			t.Errorf("Parse(%q) unexpectedly succeeded", args)
		}
	}
}
