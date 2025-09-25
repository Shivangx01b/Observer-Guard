package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"observeguard/cmd/observeguard/commands"
)

var (
	version = "1.0.0"
	commit  = "dev"
	date    = "unknown"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "observeguard",
		Short: "ObserveGuard - AI Observability and Security Platform",
		Long: `ObserveGuard is a comprehensive Go+eBPF backend API for AI observability and security.
It provides zero-instrumentation monitoring with AI-specific threat detection capabilities.`,
		Version: fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date),
	}

	// Global flags
	rootCmd.PersistentFlags().String("config", "", "config file (default is $HOME/.observeguard.yaml)")
	rootCmd.PersistentFlags().Bool("debug", false, "enable debug logging")
	rootCmd.PersistentFlags().String("log-level", "info", "log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().String("log-format", "json", "log format (json, text)")

	// Bind flags to viper
	viper.BindPFlag("debug", rootCmd.PersistentFlags().Lookup("debug"))
	viper.BindPFlag("log.level", rootCmd.PersistentFlags().Lookup("log-level"))
	viper.BindPFlag("log.format", rootCmd.PersistentFlags().Lookup("log-format"))

	// Add subcommands
	rootCmd.AddCommand(commands.NewServerCommand())
	rootCmd.AddCommand(commands.NewCollectCommand())
	rootCmd.AddCommand(commands.NewAnalyzeCommand())
	rootCmd.AddCommand(commands.NewConfigCommand())
	rootCmd.AddCommand(commands.NewPolicyCommand())
	rootCmd.AddCommand(commands.NewExportCommand())
	rootCmd.AddCommand(commands.NewCleanupCommand())
	rootCmd.AddCommand(commands.NewVersionCommand(version, commit, date))

	// Execute root command
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}