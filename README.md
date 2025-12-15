# Foundry Health Check

A comprehensive health check tool for Azure API Management (APIM) and Azure AI Foundry / Cognitive Services. Analyzes your Azure configurations against best practices and provides AI-powered recommendations using Claude.

## Features

- **Automated Health Checks** for:
  - Azure API Management (APIM)
  - Azure AI Services / Cognitive Services

- **Security Checks**:
  - Backend HTTPS and TLS certificate validation
  - Subscription key exposure in logs/traces
  - Named values stored in Key Vault vs plain text
  - JWT validation policies
  - Sensitive header stripping
  - Network security (VNet, Private Endpoints, IP restrictions)
  - Managed Identity configuration

- **Reliability Checks**:
  - SKU recommendations
  - Availability Zones
  - Diagnostics configuration

- **AI-Powered Analysis**:
  - Uses Claude API for intelligent analysis
  - Context-aware recommendations
  - Azure Well-Architected Framework alignment

## Installation

```bash
pip install -r requirements.txt
```

### Requirements

- Python 3.10+
- Azure subscription with appropriate permissions
- Claude API key (from Anthropic)

## Usage

### GUI Mode (Recommended)

```bash
python health_check_gui.py
```

Features:
- Interactive Azure subscription/resource browser
- Secure API key storage (Windows Credential Manager)
- HTML and JSON report export
- Claude AI analysis integration

### CLI Mode

```bash
# Basic scan
python health_check.py --subscription <sub-id> --resource-group <rg-name>

# Scan specific APIM
python health_check.py --subscription <sub-id> --resource-group <rg-name> --apim-name <apim>

# Generate HTML report
python health_check.py --subscription <sub-id> --resource-group <rg-name> --output report.html

# Include Claude AI analysis
python health_check.py --subscription <sub-id> --resource-group <rg-name> --claude-api-key <key>
```

## Health Checks

### APIM Checks

| Check | Severity | Category |
|-------|----------|----------|
| Developer SKU (not for production) | HIGH | Reliability |
| No Managed Identity | HIGH | Security |
| API without subscription requirement | HIGH | Security |
| Backend not using HTTPS | CRITICAL | Security |
| TLS certificate validation disabled | HIGH | Security |
| Secrets not in Key Vault | HIGH | Security |
| Subscription keys exposed in logs | HIGH | Security |
| No rate limiting | MEDIUM | Security |
| No JWT validation | MEDIUM | Security |
| No VNet integration | MEDIUM | Security |
| No diagnostics configured | MEDIUM | Operations |
| Sensitive headers forwarded to backend | MEDIUM | Security |
| No CORS policy | LOW | Security |

### AI Services Checks

| Check | Severity | Category |
|-------|----------|----------|
| Public network access enabled | MEDIUM | Security |
| No Managed Identity | MEDIUM | Security |
| Local auth enabled | LOW | Security |
| Network ACLs allow all traffic | MEDIUM | Security |
| No private endpoints | LOW | Security |
| Dynamic throttling disabled | LOW | Performance |
| Outbound network unrestricted | LOW | Security |
| Content filtering review needed | INFO | Compliance |

## Health Score

The health score (0-100) is calculated based on finding severity:
- CRITICAL: -25 points
- HIGH: -15 points
- MEDIUM: -8 points
- LOW: -3 points
- INFO: 0 points

## Output Formats

- **Console**: Colored output with severity indicators
- **HTML**: Professional report with styling
- **JSON**: Machine-readable format for automation

## API Key Storage

The GUI stores your Claude API key securely:
- **Windows**: Windows Credential Manager (via keyring)
- **macOS**: Keychain
- **Linux**: Secret Service

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License
