package cli

import "fmt"

type Command struct {
	Name  string
	Value string
}

const Usage = "usage: mcp install <pkg> | mcp search <query> | mcp start"

func Parse(args []string) (Command, error) {
	if len(args) == 0 {
		return Command{}, fmt.Errorf("%s", Usage)
	}
	switch args[0] {
	case "install":
		if len(args) != 2 || args[1] == "" {
			return Command{}, fmt.Errorf("install requires exactly one package argument; %s", Usage)
		}
		return Command{Name: "install", Value: args[1]}, nil
	case "search":
		if len(args) != 2 || args[1] == "" {
			return Command{}, fmt.Errorf("search requires exactly one query argument; %s", Usage)
		}
		return Command{Name: "search", Value: args[1]}, nil
	case "start":
		if len(args) != 1 {
			return Command{}, fmt.Errorf("start accepts no arguments; %s", Usage)
		}
		return Command{Name: "start"}, nil
	default:
		return Command{}, fmt.Errorf("unknown command %q; %s", args[0], Usage)
	}
}
