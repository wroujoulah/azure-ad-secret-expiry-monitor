# Azure AD Secret Expiry Monitor

Azure AD Secret Expiry Monitor is a command-line tool that helps organizations maintain security by monitoring Azure AD application secrets (client secrets) that are approaching expiration. The tool can scan your Azure tenant for applications with specific tags and alert you about secrets that will expire within a configurable time frame.

## Features

- Monitor Azure AD application secrets across your tenant
- Filter applications using tags
- Configurable expiration threshold
- Multiple output formats (JSON and human-readable text)
- Flexible configuration through config files, environment variables, or command-line flags
- Easy integration with monitoring and alerting systems

## Prerequisites

- Go 1.20 or later
- Azure AD tenant
- Service Principal with appropriate permissions to read AD application registrations
  - Required Microsoft Graph API Permission: `Application.Read.All` (Microsoft Graph > Application > Application.Read.All)

## Installation

```bash
# Clone the repository
git clone https://github.com/wroujoulah/azure-ad-secret-expiry-monitor.git

# Change to the project directory
cd azure-ad-secret-expiry-monitor

# Build the binary
go build -o asm
```

## Configuration

The tool supports three methods of configuration, in order of precedence:

1. Command-line flags
2. Environment variables
3. Configuration file

### Configuration File

Create a `config.yaml` file in the working directory:

```yaml
tenant_id: "your-tenant-id"
client_id: "your-client-id"
client_secret: "your-client-secret"
expiry_threshold_days: 30
monitor_tag: "MonitorSecrets"
format: "json"
```

### Environment Variables

```bash
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret"
export AZURE_EXPIRY_THRESHOLD_DAYS="30"
export AZURE_MONITOR_TAG="MonitorSecrets"
export AZURE_FORMAT="json"
```

### Command-line Flags

```bash
asm \
  --tenant-id "your-tenant-id" \
  --client-id "your-client-id" \
  --client-secret "your-client-secret" \
  --expiry-threshold-days 30 \
  --monitor-tag "MonitorSecrets" \
  --format json
```

## Usage

Basic usage with default configuration file:

```bash
./asm
```

Specify a custom configuration file:

```bash
./asm --config /path/to/config.yaml
```

Use command-line flags:

```bash
./asm \
  --tenant-id "a923015c-b511-46ed-8691-9be1371a8841" \
  --client-id "cf6d6be9-a946-4d2e-9f0a-1f41eaaf41e1" \
  --client-secret "your-secret-here" \
  --expiry-threshold-days 95 \
  --monitor-tag "MonitorSecrets" \
  --format json
```

## Output Formats

### Text Format (Default)

```
Azure Secret Monitor Report
Generated at: 2024-12-22T15:04:05Z
Configuration:
  - Expiry Threshold: 30 days
  - Monitor Tag: MonitorSecrets

Found 2 expiring secrets:

Application: MyApp1
App ID: cf6d6be9-a946-4d2e-9f0a-1f41eaaf41e1
Secret ID: 12345678-1234-1234-1234-123456789012
Expiry Date: 2025-01-15
Days Until Expiry: 24
--------------------------------------------------
Application: MyApp2
App ID: 98765432-9876-9876-9876-987654321098
Secret ID: abcdef12-abcd-abcd-abcd-abcdef123456
Expiry Date: 2025-01-20
Days Until Expiry: 29
--------------------------------------------------
```

### JSON Format

```json
{
  "results": [
    {
      "application_name": "MyApp1",
      "application_id": "cf6d6be9-a946-4d2e-9f0a-1f41eaaf41e1",
      "secret_id": "12345678-1234-1234-1234-123456789012",
      "expiry_date": "2025-01-15",
      "days_to_expiry": 24
    },
    {
      "application_name": "MyApp2",
      "application_id": "98765432-9876-9876-9876-987654321098",
      "secret_id": "abcdef12-abcd-abcd-abcd-abcdef123456",
      "expiry_date": "2025-01-20",
      "days_to_expiry": 29
    }
  ],
  "execution_info": {
    "timestamp": "2024-12-22T15:04:05Z",
    "config": {
      "expiry_threshold_days": 30,
      "monitor_tag": "MonitorSecrets",
      "format": "json"
    }
  }
}
```

## Integration Examples

### Monitoring with Cron

Add to crontab to run daily:

```bash
0 8 * * * /path/to/asm --config /path/to/config.yaml >> /var/log/asm.log 2>&1
```

### Alert Integration

Using JSON output with jq for monitoring systems:

```bash
./asm --format json | jq -e '.results | length > 0'
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## Acknowledgments

- [Azure SDK for Go](https://github.com/Azure/azure-sdk-for-go)
- [Microsoft Graph SDK for Go](https://github.com/microsoftgraph/msgraph-sdk-go)
