// Package main provides functionality to monitor Azure AD application secrets
// for approaching expiration dates. It supports both command-line and configuration
// file based setup, with options to output results in both human-readable and JSON formats.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	msgraph "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Config holds all application configuration parameters used to configure
// the Azure AD secret monitoring tool.
type Config struct {
	// ClientID is the Azure AD application client ID
	ClientID string `mapstructure:"client_id"`
	// ClientSecret is the Azure AD application client secret
	ClientSecret string `mapstructure:"client_secret"`
	// TenantID is the Azure AD tenant ID
	TenantID string `mapstructure:"tenant_id"`
	// MonitorTag is the tag used to filter which applications to monitor
	MonitorTag string `mapstructure:"monitor_tag"`
	// ExpiryThresholdDays is the number of days before expiration to check secrets
	ExpiryThresholdDays int `mapstructure:"expiry_threshold_days"`
	// Format specifies the output format (text or json)
	Format string `mapstructure:"format"`
}

// SecretInfo represents detailed information about an expiring secret
// including its associated application and expiration details.
type SecretInfo struct {
	// ApplicationName is the display name of the Azure AD application
	ApplicationName string `json:"application_name"`
	// ApplicationID is the unique identifier of the Azure AD application
	ApplicationID string `json:"application_id"`
	// SecretID is the unique identifier of the secret
	SecretID string `json:"secret_id"`
	// ExpiryDate is the date when the secret will expire (format: YYYY-MM-DD)
	ExpiryDate string `json:"expiry_date"`
	// DaysToExpiry is the number of days until the secret expires
	DaysToExpiry int `json:"days_to_expiry"`
}

// ExecutionInfo contains metadata about the current execution
type ExecutionInfo struct {
	// Timestamp when the check was performed
	Timestamp string `json:"timestamp"`
	// Configuration settings used for this run
	Config ConfigInfo `json:"config"`
}

// ConfigInfo contains the non-sensitive configuration used for the execution
type ConfigInfo struct {
	// ExpiryThresholdDays is the threshold used for checking expiration
	ExpiryThresholdDays int `json:"expiry_threshold_days"`
	// MonitorTag is the tag used to filter applications
	MonitorTag string `json:"monitor_tag"`
	// Format specifies the output format used
	Format string `json:"format"`
}

// OutputResult represents the complete output of the monitor
type OutputResult struct {
	// Results contains the list of expiring secrets
	Results []SecretInfo `json:"results"`
	// Info contains metadata about the execution
	Info ExecutionInfo `json:"execution_info"`
}

// Monitor handles all monitoring operations for Azure AD application secrets.
// It maintains a connection to the Microsoft Graph API and implements
// the secret checking logic.
type Monitor struct {
	client *msgraph.GraphServiceClient
	config Config
}

// NewMonitor creates a new Monitor instance with the provided configuration.
// It establishes the necessary Azure AD authentication and creates a Microsoft
// Graph API client.
func NewMonitor(config Config) (*Monitor, error) {
	cred, err := azidentity.NewClientSecretCredential(
		config.TenantID,
		config.ClientID,
		config.ClientSecret,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("credential error: %v", err)
	}

	client, err := msgraph.NewGraphServiceClientWithCredentials(cred, []string{"https://graph.microsoft.com/.default"})
	if err != nil {
		return nil, fmt.Errorf("client error: %v", err)
	}

	return &Monitor{
		client: client,
		config: config,
	}, nil
}

// CheckSecrets queries the Microsoft Graph API to retrieve all application secrets
// and checks for those approaching expiration based on the configured notification
// threshold (ExpiryThresholdDays).
func (m *Monitor) CheckSecrets(ctx context.Context) ([]SecretInfo, error) {
	apps, err := m.client.Applications().Get(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get applications: %v", err)
	}

	var results []SecretInfo
	for _, app := range apps.GetValue() {
		if !contains(app.GetTags(), m.config.MonitorTag) {
			continue
		}

		for _, cred := range app.GetPasswordCredentials() {
			endDateTime := cred.GetEndDateTime()
			if endDateTime == nil {
				continue
			}

			daysToExpiry := int(time.Until(endDateTime.UTC()).Hours() / 24)
			if daysToExpiry <= m.config.ExpiryThresholdDays {
				keyID := cred.GetKeyId()
				if keyID == nil {
					continue
				}

				displayName := app.GetDisplayName()
				if displayName == nil {
					continue
				}

				appID := app.GetAppId()
				if appID == nil {
					continue
				}

				results = append(results, SecretInfo{
					ApplicationName: *displayName,
					ApplicationID:   *appID,
					SecretID:        keyID.String(),
					ExpiryDate:      endDateTime.Format("2006-01-02"),
					DaysToExpiry:    daysToExpiry,
				})
			}
		}
	}

	return results, nil
}

// contains checks if a string slice contains a specific string pattern.
// It supports both exact matches and regular expressions.
func contains(slice []string, pattern string) bool {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		// If the pattern is invalid, fall back to exact match
		for _, s := range slice {
			if s == pattern {
				return true
			}
		}
		return false
	}

	for _, s := range slice {
		if regex.MatchString(s) {
			return true
		}
	}
	return false
}

// printJSON outputs the secret information in JSON format to stdout.
func printJSON(secrets []SecretInfo, config Config) error {
	if secrets == nil {
		secrets = []SecretInfo{} // Convert nil to empty slice
	}

	result := OutputResult{
		Results: secrets,
		Info: ExecutionInfo{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Config: ConfigInfo{
				ExpiryThresholdDays: config.ExpiryThresholdDays,
				MonitorTag:          config.MonitorTag,
				Format:              config.Format,
			},
		},
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

// printText outputs the secret information in a human-readable format to stdout.
func printText(secrets []SecretInfo, config Config) {
	fmt.Printf("Azure Secret Monitor Report\n")
	fmt.Printf("Generated at: %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Printf("Configuration:\n")
	fmt.Printf("  - Expiry Threshold: %d days\n", config.ExpiryThresholdDays)
	fmt.Printf("  - Monitor Tag: %s\n", config.MonitorTag)
	fmt.Printf("\n")

	if secrets == nil || len(secrets) == 0 {
		fmt.Println("No expiring secrets found.")
		return
	}

	fmt.Printf("Found %d expiring secrets:\n\n", len(secrets))
	for _, secret := range secrets {
		fmt.Printf("Application: %s\n", secret.ApplicationName)
		fmt.Printf("App ID: %s\n", secret.ApplicationID)
		fmt.Printf("Secret ID: %s\n", secret.SecretID)
		fmt.Printf("Expiry Date: %s\n", secret.ExpiryDate)
		fmt.Printf("Days Until Expiry: %d\n", secret.DaysToExpiry)
		fmt.Println(strings.Repeat("-", 50))
	}
}

// initConfig initializes the application configuration using Viper.
// It loads configuration from files, environment variables, and command-line flags.
func initConfig(cfgFile string) error {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.AddConfigPath(".")
		viper.SetConfigName("config")
	}

	viper.AutomaticEnv()
	viper.SetEnvPrefix("AZURE")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	// Set defaults
	viper.SetDefault("format", "text")
	viper.SetDefault("monitor_tag", "MonitorSecrets")
	viper.SetDefault("expiry_threshold_days", 30)

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return fmt.Errorf("error reading config file: %w", err)
		}
	}

	return nil
}

func main() {
	var (
		config  Config
		cfgFile string
	)

	// rootCmd represents the base command when called without any subcommands
	rootCmd := &cobra.Command{
		Use:     "azure-secret-monitor",
		Short:   "Monitor Azure AD application secrets for expiration",
		Long:    `A tool to monitor Azure AD application secrets and identify those approaching expiration.`,
		Version: "1.0.0",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := initConfig(cfgFile); err != nil {
				return err
			}

			// Bind all flags to viper using the correct mapping
			flags := cmd.Flags()
			mappings := map[string]string{
				"client-id":             "client_id",
				"client-secret":         "client_secret",
				"tenant-id":             "tenant_id",
				"monitor-tag":           "monitor_tag",
				"expiry-threshold-days": "expiry_threshold_days",
				"format":                "format",
			}

			for flagName, configKey := range mappings {
				if err := viper.BindPFlag(configKey, flags.Lookup(flagName)); err != nil {
					return fmt.Errorf("error binding flag '%s': %w", flagName, err)
				}
			}

			if err := viper.Unmarshal(&config); err != nil {
				return fmt.Errorf("error unmarshaling config: %w", err)
			}

			// Validate required fields
			if config.ClientID == "" {
				return fmt.Errorf("client ID is required (use --client-id flag, AZURE_CLIENT_ID env var, or config file)")
			}
			if config.ClientSecret == "" {
				return fmt.Errorf("client secret is required (use --client-secret flag, AZURE_CLIENT_SECRET env var, or config file)")
			}
			if config.TenantID == "" {
				return fmt.Errorf("tenant ID is required (use --tenant-id flag, AZURE_TENANT_ID env var, or config file)")
			}

			// Validate format
			if config.Format != "text" && config.Format != "json" {
				return fmt.Errorf("invalid format '%s': must be 'text' or 'json'", config.Format)
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			monitor, err := NewMonitor(config)
			if err != nil {
				return fmt.Errorf("failed to create monitor: %v", err)
			}

			ctx := context.Background()
			secrets, err := monitor.CheckSecrets(ctx)
			if err != nil {
				return fmt.Errorf("failed to check secrets: %v", err)
			}

			if secrets == nil {
				secrets = []SecretInfo{} // Convert nil to empty slice
			}

			if config.Format == "json" {
				if err := printJSON(secrets, config); err != nil {
					return fmt.Errorf("failed to print JSON: %v", err)
				}
			} else {
				printText(secrets, config)
			}

			return nil
		},
	}

	// Define flags with names matching the config mapping
	flags := rootCmd.Flags()
	flags.StringVar(&cfgFile, "config", "", "config file (default is ./config.yaml)")
	flags.String("client-id", "", "Azure AD client ID")
	flags.String("client-secret", "", "Azure AD client secret")
	flags.String("tenant-id", "", "Azure AD tenant ID")
	flags.String("monitor-tag", "MonitorSecrets", "Tag to monitor")
	flags.Int("expiry-threshold-days", 30, "Number of days before expiration to check secrets")
	flags.String("format", "text", "Output format (text/json)")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
