# Contributing to Foundry Health Check

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## Getting Started

1. Fork the repository
2. Clone your fork locally
3. Install dependencies: `pip install -r requirements.txt`
4. Create a feature branch: `git checkout -b feature/your-feature-name`

## Development Setup

### Prerequisites
- Python 3.10+
- Azure subscription (for testing)
- Claude API key (for AI analysis features)

### Running Locally
```bash
# CLI mode
python health_check.py --subscription <sub-id> --resource-group <rg>

# GUI mode
python health_check_gui.py
```

## Adding New Health Checks

### APIM Checks
Add checks in the `APIMHealthChecker.check_health()` method in `health_check.py`:

```python
findings.append(Finding(
    title="Your Check Title",
    description="Description of what was found",
    severity=Severity.MEDIUM,  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category=Category.SECURITY,  # SECURITY, PERFORMANCE, RELIABILITY, COST, OPERATIONS, COMPLIANCE
    resource_type="APIM",
    resource_name=self.apim_name,
    recommendation="What the user should do",
    details={"key": "value"}
))
```

### AI Services Checks
Add checks in the `AIFoundryHealthChecker.check_health()` method.

## Code Style

- Follow PEP 8 guidelines
- Use type hints where possible
- Add docstrings for new functions/classes
- Keep functions focused and small

## Testing

Before submitting a PR:
1. Test with a real Azure subscription if possible
2. Verify both CLI and GUI modes work
3. Check that HTML report generation works
4. Ensure no personal/sensitive data is hardcoded

## Submitting Changes

1. Commit with clear messages
2. Push to your fork
3. Create a Pull Request with:
   - Description of changes
   - Any new dependencies
   - Screenshots (for GUI changes)

## Reporting Issues

When reporting bugs, please include:
- Python version
- OS (Windows/macOS/Linux)
- Error messages/stack traces
- Steps to reproduce

## Feature Requests

We welcome ideas for new health checks! Please open an issue describing:
- What the check should detect
- Why it's important (security, reliability, etc.)
- Reference to Azure documentation if applicable
