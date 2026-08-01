package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/example/mcp-cli/internal/app"
	"github.com/example/mcp-cli/internal/cli"
	"github.com/example/mcp-cli/internal/config"
	"github.com/example/mcp-cli/internal/installer"
)

const registryURL = "https://registry.mcp.dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "mcp:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	command, err := cli.Parse(args)
	if err != nil {
		return err
	}
	registry, err := installer.NewRegistry(registryURL, []string{"registry.mcp.dev"})
	if err != nil {
		return err
	}
	configPath, err := config.DefaultPath()
	if err != nil {
		return err
	}
	packageInstaller := installer.New(registry, configPath)
	packageInstaller.AllowUnsandboxedCargo = os.Getenv("MCP_ALLOW_UNSANDBOXED_CARGO") == "1"
	service := &app.App{
		Registry:   registry,
		Installer:  packageInstaller,
		ConfigPath: configPath,
		Out:        os.Stdout,
		Err:        os.Stderr,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch command.Name {
	case "install":
		if err := service.Installer.Install(ctx, command.Value); err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "installed %s\n", command.Value)
		return nil
	case "search":
		return service.Search(ctx, command.Value)
	case "start":
		return service.Start(ctx)
	default:
		return fmt.Errorf("internal error: unsupported command")
	}
}
