#!/usr/bin/env python3
"""
Foundry Health Check

Analyzes Azure API Management and AI Foundry configurations against best practices
and provides recommendations using Claude AI.

Usage:
    python health_check.py --subscription <sub-id> --resource-group <rg-name>
    python health_check.py --subscription <sub-id> --resource-group <rg-name> --apim-name <apim>
    python health_check.py --subscription <sub-id> --resource-group <rg-name> --output report.html
"""

import argparse
import json
import logging
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from azure.identity import DefaultAzureCredential
from azure.mgmt.apimanagement import ApiManagementClient
from azure.mgmt.cognitiveservices import CognitiveServicesManagementClient
from azure.mgmt.resource import ResourceManagementClient

# Try to import azure-ai-client, fall back to anthropic
try:
    from azure_ai import AzureAIClient
    USE_AZURE_AI_CLIENT = True
except ImportError:
    import anthropic
    USE_AZURE_AI_CLIENT = False

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class Severity(Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(Enum):
    """Categories for findings."""
    SECURITY = "security"
    PERFORMANCE = "performance"
    RELIABILITY = "reliability"
    COST = "cost"
    OPERATIONS = "operations"
    COMPLIANCE = "compliance"


@dataclass
class Finding:
    """Represents a health check finding."""
    title: str
    description: str
    severity: Severity
    category: Category
    resource_type: str
    resource_name: str
    recommendation: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HealthCheckResult:
    """Results of the health check."""
    timestamp: datetime
    subscription_id: str
    resource_group: str
    findings: List[Finding] = field(default_factory=list)
    resources_scanned: Dict[str, int] = field(default_factory=dict)
    ai_analysis: Optional[str] = None

    def add_finding(self, finding: Finding):
        self.findings.append(finding)

    def get_findings_by_severity(self, severity: Severity) -> List[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def get_findings_by_category(self, category: Category) -> List[Finding]:
        return [f for f in self.findings if f.category == category]

    @property
    def critical_count(self) -> int:
        return len(self.get_findings_by_severity(Severity.CRITICAL))

    @property
    def high_count(self) -> int:
        return len(self.get_findings_by_severity(Severity.HIGH))

    @property
    def score(self) -> int:
        """Calculate health score (0-100)."""
        if not self.findings:
            return 100

        # Weighted penalty per severity
        penalties = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 8,
            Severity.LOW: 3,
            Severity.INFO: 0
        }

        total_penalty = sum(penalties[f.severity] for f in self.findings)
        return max(0, 100 - total_penalty)


class APIMHealthChecker:
    """Checks Azure API Management health and best practices."""

    def __init__(self, client: ApiManagementClient, resource_group: str, apim_name: str):
        self.client = client
        self.resource_group = resource_group
        self.apim_name = apim_name
        self.config: Dict[str, Any] = {}

    def collect_configuration(self) -> Dict[str, Any]:
        """Collect APIM configuration for analysis."""
        logger.info(f"Collecting APIM configuration for {self.apim_name}...")

        try:
            # Get service details
            service = self.client.api_management_service.get(
                self.resource_group, self.apim_name
            )

            self.config["service"] = {
                "name": service.name,
                "location": service.location,
                "sku": service.sku.name if service.sku else None,
                "capacity": service.sku.capacity if service.sku else None,
                "virtual_network_type": service.virtual_network_type,
                "public_network_access": service.public_network_access,
                "identity_type": service.identity.type if service.identity else None,
                "zones": service.zones,
                "platform_version": service.platform_version,
            }

            # Get APIs
            apis = list(self.client.api.list_by_service(self.resource_group, self.apim_name))
            self.config["apis"] = []
            for api in apis:
                # Get subscription key parameter names (it's an object, not a dict)
                sub_key_params = api.subscription_key_parameter_names
                header_name = None
                query_name = None
                if sub_key_params:
                    header_name = getattr(sub_key_params, 'header', None)
                    query_name = getattr(sub_key_params, 'query', None)

                api_config = {
                    "name": api.name,
                    "display_name": api.display_name,
                    "path": api.path,
                    "protocols": api.protocols,
                    "subscription_required": api.subscription_required,
                    "api_version": api.api_version,
                    "subscription_key_header_name": header_name,
                    "subscription_key_query_name": query_name,
                }

                # Get API policy
                try:
                    policy = self.client.api_policy.get(
                        self.resource_group, self.apim_name, api.name, "policy"
                    )
                    api_config["policy"] = policy.value
                except Exception:
                    api_config["policy"] = None

                self.config["apis"].append(api_config)

            # Get backends
            backends = list(self.client.backend.list_by_service(self.resource_group, self.apim_name))
            self.config["backends"] = [
                {
                    "name": b.name,
                    "url": b.url,
                    "protocol": b.protocol,
                    "resource_id": b.resource_id,
                    "has_credentials": b.credentials is not None,
                    "tls_validate_cert": b.tls.validate_certificate_chain if b.tls else True,
                    "tls_validate_name": b.tls.validate_certificate_name if b.tls else True,
                }
                for b in backends
            ]

            # Get products
            products = list(self.client.product.list_by_service(self.resource_group, self.apim_name))
            self.config["products"] = [
                {
                    "name": p.name,
                    "display_name": p.display_name,
                    "subscription_required": p.subscription_required,
                    "approval_required": p.approval_required,
                    "state": p.state,
                }
                for p in products
            ]

            # Get named values
            named_values = list(self.client.named_value.list_by_service(self.resource_group, self.apim_name))
            self.config["named_values"] = [
                {
                    "name": nv.name,
                    "display_name": nv.display_name,
                    "secret": nv.secret,
                    "key_vault": nv.key_vault is not None,
                }
                for nv in named_values
            ]

            # Get diagnostics/logging
            try:
                diagnostics = list(self.client.diagnostic.list_by_service(
                    self.resource_group, self.apim_name
                ))
                self.config["diagnostics"] = []
                for d in diagnostics:
                    diag_config = {
                        "name": d.name,
                        "logger_id": d.logger_id,
                        "sampling_percentage": d.sampling.percentage if d.sampling else None,
                        "always_log": d.always_log,
                        "log_client_ip": d.log_client_ip,
                    }
                    # Check if headers are logged (potential secret exposure)
                    if d.frontend:
                        diag_config["frontend_request_headers"] = d.frontend.request.headers if d.frontend.request else []
                        diag_config["frontend_response_headers"] = d.frontend.response.headers if d.frontend.response else []
                    if d.backend:
                        diag_config["backend_request_headers"] = d.backend.request.headers if d.backend.request else []
                        diag_config["backend_response_headers"] = d.backend.response.headers if d.backend.response else []
                    self.config["diagnostics"].append(diag_config)
            except Exception:
                self.config["diagnostics"] = []

        except Exception as e:
            logger.error(f"Error collecting APIM configuration: {e}")
            raise

        return self.config

    def check_health(self) -> List[Finding]:
        """Run health checks and return findings."""
        findings = []

        if not self.config:
            self.collect_configuration()

        service = self.config.get("service", {})

        # Check SKU
        sku = service.get("sku")
        if sku == "Consumption":
            findings.append(Finding(
                title="Consumption SKU has limited features",
                description="Consumption tier lacks VNet integration, built-in cache, and has cold start latency",
                severity=Severity.INFO,
                category=Category.PERFORMANCE,
                resource_type="APIM",
                resource_name=self.apim_name,
                recommendation="Consider Developer/Standard/Premium for production workloads",
                details={"current_sku": sku}
            ))
        elif sku == "Developer":
            findings.append(Finding(
                title="Developer SKU is not for production",
                description="Developer SKU has no SLA and is not suitable for production workloads",
                severity=Severity.HIGH,
                category=Category.RELIABILITY,
                resource_type="APIM",
                resource_name=self.apim_name,
                recommendation="Use Standard or Premium SKU for production",
                details={"current_sku": sku}
            ))

        # Check managed identity
        if not service.get("identity_type"):
            findings.append(Finding(
                title="Managed Identity not enabled",
                description="APIM does not have a managed identity configured",
                severity=Severity.HIGH,
                category=Category.SECURITY,
                resource_type="APIM",
                resource_name=self.apim_name,
                recommendation="Enable System-assigned managed identity for secure backend authentication",
                details={}
            ))

        # Check VNet integration
        vnet_type = service.get("virtual_network_type")
        if vnet_type == "None" or not vnet_type:
            findings.append(Finding(
                title="No VNet integration",
                description="APIM is not integrated with a Virtual Network",
                severity=Severity.MEDIUM,
                category=Category.SECURITY,
                resource_type="APIM",
                resource_name=self.apim_name,
                recommendation="Consider VNet integration for network isolation",
                details={"virtual_network_type": vnet_type}
            ))

        # Check availability zones
        if not service.get("zones") and sku in ["Premium"]:
            findings.append(Finding(
                title="Availability Zones not configured",
                description="Premium APIM is not deployed across availability zones",
                severity=Severity.MEDIUM,
                category=Category.RELIABILITY,
                resource_type="APIM",
                resource_name=self.apim_name,
                recommendation="Enable zone redundancy for high availability",
                details={}
            ))

        # Check APIs
        api_header_names = set()
        for api in self.config.get("apis", []):
            # Collect header names for consistency check
            header_name = api.get("subscription_key_header_name")
            if header_name:
                api_header_names.add(header_name)

            # Check subscription requirement
            if not api.get("subscription_required"):
                findings.append(Finding(
                    title="API does not require subscription",
                    description=f"API '{api['display_name']}' allows anonymous access",
                    severity=Severity.HIGH,
                    category=Category.SECURITY,
                    resource_type="API",
                    resource_name=api["name"],
                    recommendation="Enable subscription requirement for API access control",
                    details={"api_name": api["name"]}
                ))

            # Check subscription key header (prefer 'api-key' over 'Ocp-Apim-Subscription-Key')
            if header_name and header_name.lower() == "ocp-apim-subscription-key":
                findings.append(Finding(
                    title="Using default APIM subscription header",
                    description=f"API '{api['display_name']}' uses 'Ocp-Apim-Subscription-Key' header",
                    severity=Severity.INFO,
                    category=Category.OPERATIONS,
                    resource_type="API",
                    resource_name=api["name"],
                    recommendation="Consider using 'api-key' header for consistency with Azure AI/OpenAI conventions",
                    details={"api_name": api["name"], "current_header": header_name}
                ))

            # Check for policies
            policy = api.get("policy")
            if policy:
                # Check for rate limiting
                if "rate-limit" not in policy.lower() and "quota" not in policy.lower():
                    findings.append(Finding(
                        title="No rate limiting configured",
                        description=f"API '{api['display_name']}' has no rate limiting policy",
                        severity=Severity.MEDIUM,
                        category=Category.SECURITY,
                        resource_type="API",
                        resource_name=api["name"],
                        recommendation="Add rate-limit or quota policy to prevent abuse",
                        details={"api_name": api["name"]}
                    ))

                # Check for CORS if needed
                if "cors" not in policy.lower():
                    findings.append(Finding(
                        title="CORS not configured",
                        description=f"API '{api['display_name']}' has no CORS policy",
                        severity=Severity.LOW,
                        category=Category.SECURITY,
                        resource_type="API",
                        resource_name=api["name"],
                        recommendation="Configure CORS if API is accessed from browsers",
                        details={"api_name": api["name"]}
                    ))

                # Check for authentication
                if "authentication-managed-identity" in policy.lower():
                    findings.append(Finding(
                        title="Using Managed Identity authentication",
                        description=f"API '{api['display_name']}' uses managed identity (best practice)",
                        severity=Severity.INFO,
                        category=Category.SECURITY,
                        resource_type="API",
                        resource_name=api["name"],
                        recommendation="Good! Managed identity is the recommended authentication method",
                        details={"api_name": api["name"]}
                    ))

                # Check for JWT validation
                if "validate-jwt" not in policy.lower():
                    findings.append(Finding(
                        title="No JWT validation configured",
                        description=f"API '{api['display_name']}' has no validate-jwt policy for token validation",
                        severity=Severity.MEDIUM,
                        category=Category.SECURITY,
                        resource_type="API",
                        resource_name=api["name"],
                        recommendation="Add validate-jwt policy if using OAuth2/OpenID Connect authentication",
                        details={"api_name": api["name"]}
                    ))

                # Check for sensitive header stripping in outbound
                sensitive_headers = ["ocp-apim-subscription-key", "authorization", "api-key", "x-api-key"]
                policy_lower = policy.lower()
                if "<outbound>" in policy_lower:
                    outbound_section = policy_lower.split("<outbound>")[1].split("</outbound>")[0] if "</outbound>" in policy_lower else ""
                    headers_stripped = "set-header" in outbound_section and any(h in outbound_section for h in sensitive_headers)
                    if not headers_stripped:
                        findings.append(Finding(
                            title="Sensitive headers may be exposed to backend",
                            description=f"API '{api['display_name']}' may forward sensitive headers like subscription keys to backend",
                            severity=Severity.MEDIUM,
                            category=Category.SECURITY,
                            resource_type="API",
                            resource_name=api["name"],
                            recommendation="Use set-header policy in outbound to remove sensitive headers before sending to backend",
                            details={"api_name": api["name"]}
                        ))
            else:
                # No policy at all
                findings.append(Finding(
                    title="No API policy configured",
                    description=f"API '{api['display_name']}' has no policy configured",
                    severity=Severity.MEDIUM,
                    category=Category.SECURITY,
                    resource_type="API",
                    resource_name=api["name"],
                    recommendation="Configure API policies for security, rate limiting, and request/response transformation",
                    details={"api_name": api["name"]}
                ))

        # Check for inconsistent subscription key headers across APIs
        if len(api_header_names) > 1:
            findings.append(Finding(
                title="Inconsistent subscription key headers",
                description=f"APIs use different subscription key headers: {', '.join(api_header_names)}",
                severity=Severity.MEDIUM,
                category=Category.OPERATIONS,
                resource_type="APIM",
                resource_name=self.apim_name,
                recommendation="Standardize on a single header name (recommend 'api-key') for all APIs for simpler client integration",
                details={"headers_found": list(api_header_names)}
            ))

        # Check backends
        for backend in self.config.get("backends", []):
            url = backend.get("url", "")

            # Check for HTTPS
            if url and not url.lower().startswith("https://"):
                findings.append(Finding(
                    title="Backend not using HTTPS",
                    description=f"Backend '{backend['name']}' URL does not use HTTPS: {url}",
                    severity=Severity.CRITICAL,
                    category=Category.SECURITY,
                    resource_type="Backend",
                    resource_name=backend["name"],
                    recommendation="Use HTTPS for all backend connections to ensure data encryption in transit",
                    details={"backend_url": url}
                ))

            # Check TLS certificate validation
            if not backend.get("tls_validate_cert", True):
                findings.append(Finding(
                    title="Backend TLS certificate validation disabled",
                    description=f"Backend '{backend['name']}' has certificate chain validation disabled",
                    severity=Severity.HIGH,
                    category=Category.SECURITY,
                    resource_type="Backend",
                    resource_name=backend["name"],
                    recommendation="Enable certificate validation to prevent man-in-the-middle attacks",
                    details={"backend": backend["name"]}
                ))

            if not backend.get("tls_validate_name", True):
                findings.append(Finding(
                    title="Backend TLS certificate name validation disabled",
                    description=f"Backend '{backend['name']}' has certificate name validation disabled",
                    severity=Severity.MEDIUM,
                    category=Category.SECURITY,
                    resource_type="Backend",
                    resource_name=backend["name"],
                    recommendation="Enable certificate name validation for proper TLS verification",
                    details={"backend": backend["name"]}
                ))

        # Check named values - secrets and plain text
        for nv in self.config.get("named_values", []):
            if nv.get("secret") and not nv.get("key_vault"):
                findings.append(Finding(
                    title="Secret not stored in Key Vault",
                    description=f"Named value '{nv['display_name']}' is a secret but not linked to Key Vault",
                    severity=Severity.HIGH,
                    category=Category.SECURITY,
                    resource_type="Named Value",
                    resource_name=nv["name"],
                    recommendation="Store secrets in Azure Key Vault for better security",
                    details={"named_value": nv["name"]}
                ))
            elif not nv.get("secret"):
                # Check if name suggests it might be a secret stored in plain text
                name_lower = nv.get("display_name", "").lower()
                secret_indicators = ["key", "secret", "password", "token", "credential", "apikey", "api-key"]
                if any(indicator in name_lower for indicator in secret_indicators):
                    findings.append(Finding(
                        title="Potential secret stored as plain text",
                        description=f"Named value '{nv['display_name']}' may contain sensitive data but is not marked as secret",
                        severity=Severity.HIGH,
                        category=Category.SECURITY,
                        resource_type="Named Value",
                        resource_name=nv["name"],
                        recommendation="Mark as secret and store in Azure Key Vault if this contains sensitive data",
                        details={"named_value": nv["name"]}
                    ))

        # Check diagnostics
        diagnostics = self.config.get("diagnostics", [])
        if not diagnostics:
            findings.append(Finding(
                title="No diagnostics configured",
                description="APIM has no diagnostic logging configured",
                severity=Severity.MEDIUM,
                category=Category.OPERATIONS,
                resource_type="APIM",
                resource_name=self.apim_name,
                recommendation="Enable Application Insights or Azure Monitor diagnostics",
                details={}
            ))
        else:
            # Check for sensitive headers being logged
            sensitive_headers = ["ocp-apim-subscription-key", "authorization", "api-key", "x-api-key", "x-functions-key"]
            for diag in diagnostics:
                all_logged_headers = []
                for header_key in ["frontend_request_headers", "frontend_response_headers",
                                   "backend_request_headers", "backend_response_headers"]:
                    headers = diag.get(header_key, []) or []
                    all_logged_headers.extend([h.lower() for h in headers])

                exposed_secrets = [h for h in sensitive_headers if h in all_logged_headers]
                if exposed_secrets:
                    findings.append(Finding(
                        title="Subscription keys may be exposed in logs",
                        description=f"Diagnostic '{diag['name']}' logs sensitive headers: {', '.join(exposed_secrets)}",
                        severity=Severity.HIGH,
                        category=Category.SECURITY,
                        resource_type="Diagnostic",
                        resource_name=diag["name"],
                        recommendation="Remove sensitive headers from diagnostic logging to prevent credential exposure",
                        details={"exposed_headers": exposed_secrets, "diagnostic": diag["name"]}
                    ))

        return findings


class AIFoundryHealthChecker:
    """Checks Azure AI Foundry/Cognitive Services health and best practices."""

    def __init__(self, client: CognitiveServicesManagementClient, resource_group: str,
                 subscription_id: str, credential: DefaultAzureCredential):
        self.client = client
        self.resource_group = resource_group
        self.subscription_id = subscription_id
        self.credential = credential
        self.resources: List[Dict[str, Any]] = []
        self.rai_policies: Dict[str, List[Dict[str, Any]]] = {}  # account_name -> policies

    def collect_configuration(self) -> List[Dict[str, Any]]:
        """Collect AI Services configuration for analysis."""
        logger.info(f"Collecting AI Services configuration in {self.resource_group}...")

        try:
            accounts = list(self.client.accounts.list_by_resource_group(self.resource_group))

            for account in accounts:
                resource_config = {
                    "name": account.name,
                    "kind": account.kind,
                    "location": account.location,
                    "sku": account.sku.name if account.sku else None,
                    "endpoint": account.properties.endpoint if account.properties else None,
                    "public_network_access": account.properties.public_network_access if account.properties else None,
                    "disable_local_auth": account.properties.disable_local_auth if account.properties else None,
                    "custom_subdomain": account.properties.custom_sub_domain_name if account.properties else None,
                    "identity_type": account.identity.type if account.identity else None,
                    "network_acls": None,
                    "private_endpoints": [],
                    "dynamic_throttling_enabled": account.properties.dynamic_throttling_enabled if account.properties else None,
                    "restrict_outbound_network_access": account.properties.restrict_outbound_network_access if account.properties else None,
                    "user_owned_storage": account.properties.user_owned_storage if account.properties else None,
                }

                # Get network ACLs
                if account.properties and account.properties.network_acls:
                    resource_config["network_acls"] = {
                        "default_action": account.properties.network_acls.default_action,
                        "ip_rules_count": len(account.properties.network_acls.ip_rules or []),
                        "vnet_rules_count": len(account.properties.network_acls.virtual_network_rules or []),
                    }

                # Get private endpoints
                if account.properties and account.properties.private_endpoint_connections:
                    resource_config["private_endpoints"] = [
                        pe.name for pe in account.properties.private_endpoint_connections
                    ]

                self.resources.append(resource_config)

                # Collect RAI policies for this account
                try:
                    policies = self._collect_rai_policies(account.name)
                    self.rai_policies[account.name] = policies
                    resource_config["rai_policies"] = policies
                except Exception as e:
                    logger.warning(f"Could not collect RAI policies for {account.name}: {e}")
                    resource_config["rai_policies"] = []

        except Exception as e:
            logger.error(f"Error collecting AI Services configuration: {e}")
            raise

        return self.resources

    def _collect_rai_policies(self, account_name: str) -> List[Dict[str, Any]]:
        """Collect RAI (Responsible AI) content filter policies for an account."""
        policies = []

        try:
            # Get access token for ARM API
            token = self.credential.get_token("https://management.azure.com/.default")
            headers = {"Authorization": f"Bearer {token.token}"}

            url = (
                f"https://management.azure.com/subscriptions/{self.subscription_id}"
                f"/resourceGroups/{self.resource_group}"
                f"/providers/Microsoft.CognitiveServices/accounts/{account_name}"
                f"/raiPolicies?api-version=2024-10-01"
            )

            response = requests.get(url, headers=headers, timeout=30)
            if response.status_code == 200:
                data = response.json()
                for policy in data.get("value", []):
                    policy_config = {
                        "name": policy.get("name"),
                        "type": policy.get("properties", {}).get("type"),  # SystemManaged or UserManaged
                        "mode": policy.get("properties", {}).get("mode"),  # Default or Blocking
                        "base_policy": policy.get("properties", {}).get("basePolicyName"),
                        "content_filters": [],
                    }

                    for cf in policy.get("properties", {}).get("contentFilters", []):
                        policy_config["content_filters"].append({
                            "name": cf.get("name"),
                            "source": cf.get("source"),  # Prompt or Completion
                            "enabled": cf.get("enabled", True),
                            "blocking": cf.get("blocking", True),
                            "severity_threshold": cf.get("severityThreshold"),
                        })

                    policies.append(policy_config)

        except Exception as e:
            logger.warning(f"Error fetching RAI policies for {account_name}: {e}")

        return policies

    def check_health(self) -> List[Finding]:
        """Run health checks and return findings."""
        findings = []

        if not self.resources:
            self.collect_configuration()

        for resource in self.resources:
            # Check public network access
            if resource.get("public_network_access") == "Enabled":
                findings.append(Finding(
                    title="Public network access enabled",
                    description=f"AI Service '{resource['name']}' allows public network access",
                    severity=Severity.MEDIUM,
                    category=Category.SECURITY,
                    resource_type="AI Services",
                    resource_name=resource["name"],
                    recommendation="Consider disabling public network access and using private endpoints",
                    details={"resource": resource["name"]}
                ))

            # Check managed identity
            if not resource.get("identity_type"):
                findings.append(Finding(
                    title="Managed Identity not enabled",
                    description=f"AI Service '{resource['name']}' does not have managed identity",
                    severity=Severity.MEDIUM,
                    category=Category.SECURITY,
                    resource_type="AI Services",
                    resource_name=resource["name"],
                    recommendation="Enable managed identity for secure service-to-service authentication",
                    details={"resource": resource["name"]}
                ))

            # Check local auth
            if not resource.get("disable_local_auth"):
                findings.append(Finding(
                    title="Local authentication enabled",
                    description=f"AI Service '{resource['name']}' allows API key authentication",
                    severity=Severity.LOW,
                    category=Category.SECURITY,
                    resource_type="AI Services",
                    resource_name=resource["name"],
                    recommendation="Consider disabling local auth to enforce Azure AD authentication",
                    details={"resource": resource["name"]}
                ))

            # Check network ACLs
            network_acls = resource.get("network_acls")
            if network_acls:
                if network_acls.get("default_action") == "Allow":
                    if network_acls.get("ip_rules_count", 0) == 0:
                        findings.append(Finding(
                            title="Network ACLs allow all traffic",
                            description=f"AI Service '{resource['name']}' has no IP restrictions",
                            severity=Severity.MEDIUM,
                            category=Category.SECURITY,
                            resource_type="AI Services",
                            resource_name=resource["name"],
                            recommendation="Configure IP rules or VNet rules to restrict access",
                            details={"resource": resource["name"]}
                        ))

            # Check custom subdomain
            if not resource.get("custom_subdomain"):
                findings.append(Finding(
                    title="No custom subdomain configured",
                    description=f"AI Service '{resource['name']}' uses default endpoint",
                    severity=Severity.INFO,
                    category=Category.OPERATIONS,
                    resource_type="AI Services",
                    resource_name=resource["name"],
                    recommendation="Configure custom subdomain for better URL management",
                    details={"resource": resource["name"]}
                ))

            # Check private endpoints
            if not resource.get("private_endpoints"):
                findings.append(Finding(
                    title="No private endpoints configured",
                    description=f"AI Service '{resource['name']}' has no private endpoint connections",
                    severity=Severity.LOW,
                    category=Category.SECURITY,
                    resource_type="AI Services",
                    resource_name=resource["name"],
                    recommendation="Consider using private endpoints for network isolation",
                    details={"resource": resource["name"]}
                ))

            # Check dynamic throttling for Azure OpenAI
            kind = resource.get("kind", "").lower()
            if "openai" in kind or "aiservices" in kind:
                if not resource.get("dynamic_throttling_enabled"):
                    findings.append(Finding(
                        title="Dynamic throttling not enabled",
                        description=f"AI Service '{resource['name']}' does not have dynamic throttling enabled",
                        severity=Severity.LOW,
                        category=Category.PERFORMANCE,
                        resource_type="AI Services",
                        resource_name=resource["name"],
                        recommendation="Enable dynamic throttling to improve performance under high load",
                        details={"resource": resource["name"]}
                    ))

            # Check outbound network access restriction (data exfiltration risk)
            if resource.get("restrict_outbound_network_access") is False:
                findings.append(Finding(
                    title="Outbound network access not restricted",
                    description=f"AI Service '{resource['name']}' can make outbound network calls without restriction",
                    severity=Severity.LOW,
                    category=Category.SECURITY,
                    resource_type="AI Services",
                    resource_name=resource["name"],
                    recommendation="Consider restricting outbound network access to prevent data exfiltration",
                    details={"resource": resource["name"]}
                ))

            # Check RAI (Content Filtering) policies
            rai_policies = resource.get("rai_policies", [])
            if "openai" in kind or "aiservices" in kind:
                if not rai_policies:
                    findings.append(Finding(
                        title="No custom content filter policies",
                        description=f"AI Service '{resource['name']}' only uses default content filtering",
                        severity=Severity.INFO,
                        category=Category.COMPLIANCE,
                        resource_type="AI Services",
                        resource_name=resource["name"],
                        recommendation="Review if default content filtering meets your requirements. Custom policies allow fine-tuning.",
                        details={"resource": resource["name"]}
                    ))
                else:
                    findings.extend(self._check_rai_policies(resource["name"], rai_policies))

        return findings

    def _check_rai_policies(self, resource_name: str, policies: List[Dict[str, Any]]) -> List[Finding]:
        """Check RAI policies for security issues."""
        findings = []

        for policy in policies:
            policy_name = policy.get("name", "unknown")

            # Skip system-managed default policies
            if policy.get("type") == "SystemManaged":
                continue

            content_filters = policy.get("content_filters", [])

            # Check for disabled filters
            disabled_filters = [cf for cf in content_filters if not cf.get("enabled", True)]
            if disabled_filters:
                filter_names = [cf["name"] for cf in disabled_filters]
                findings.append(Finding(
                    title="Content filters disabled",
                    description=f"Policy '{policy_name}' has disabled filters: {', '.join(filter_names)}",
                    severity=Severity.MEDIUM,
                    category=Category.COMPLIANCE,
                    resource_type="RAI Policy",
                    resource_name=policy_name,
                    recommendation="Ensure disabled filters are intentional and documented for compliance",
                    details={"resource": resource_name, "policy": policy_name, "disabled_filters": filter_names}
                ))

            # Check for non-blocking filters (potential bypass)
            non_blocking = [cf for cf in content_filters
                           if cf.get("enabled", True) and not cf.get("blocking", True)]
            if non_blocking:
                filter_names = [cf["name"] for cf in non_blocking]
                findings.append(Finding(
                    title="Content filters set to non-blocking",
                    description=f"Policy '{policy_name}' has non-blocking filters: {', '.join(filter_names)}. Content is flagged but not blocked.",
                    severity=Severity.LOW,
                    category=Category.COMPLIANCE,
                    resource_type="RAI Policy",
                    resource_name=policy_name,
                    recommendation="Non-blocking mode logs violations but allows content through. Ensure this is intentional.",
                    details={"resource": resource_name, "policy": policy_name, "non_blocking_filters": filter_names}
                ))

            # Check for permissive thresholds (High = most permissive)
            high_threshold_filters = [cf for cf in content_filters
                                      if cf.get("severity_threshold") == "High"
                                      and cf.get("name") in ["Sexual", "Violence", "Hate", "Selfharm"]]
            if high_threshold_filters:
                filter_names = [cf["name"] for cf in high_threshold_filters]
                findings.append(Finding(
                    title="Content filters at maximum permissive threshold",
                    description=f"Policy '{policy_name}' has 'High' threshold (most permissive) for: {', '.join(filter_names)}",
                    severity=Severity.INFO,
                    category=Category.COMPLIANCE,
                    resource_type="RAI Policy",
                    resource_name=policy_name,
                    recommendation="High threshold only blocks severe content. Consider Medium for stricter filtering if needed.",
                    details={"resource": resource_name, "policy": policy_name, "high_threshold_filters": filter_names}
                ))

            # Check if Jailbreak protection is disabled
            jailbreak_filters = [cf for cf in content_filters if cf.get("name") == "Jailbreak"]
            if jailbreak_filters:
                jb = jailbreak_filters[0]
                if not jb.get("enabled", True):
                    findings.append(Finding(
                        title="Jailbreak protection disabled",
                        description=f"Policy '{policy_name}' has jailbreak detection disabled",
                        severity=Severity.MEDIUM,
                        category=Category.SECURITY,
                        resource_type="RAI Policy",
                        resource_name=policy_name,
                        recommendation="Jailbreak detection helps prevent prompt injection attacks. Enable unless you have specific reasons.",
                        details={"resource": resource_name, "policy": policy_name}
                    ))

        return findings


class ClaudeAnalyzer:
    """Uses Claude AI to analyze configurations and provide recommendations."""

    def __init__(self, api_key: str):
        """
        Initialize Claude analyzer.

        Args:
            api_key: APIM subscription key (if using azure-ai-client) or Anthropic API key
        """
        self.api_key = api_key
        if USE_AZURE_AI_CLIENT:
            self.client = AzureAIClient(api_key=api_key)
        else:
            self.client = anthropic.Anthropic(api_key=api_key)

    def analyze(
        self,
        apim_config: Optional[Dict[str, Any]],
        ai_services_config: Optional[List[Dict[str, Any]]],
        findings: List[Finding]
    ) -> str:
        """Get Claude's analysis and recommendations."""

        # Build context
        context_parts = []

        if apim_config:
            context_parts.append(f"## APIM Configuration\n```json\n{json.dumps(apim_config, indent=2, default=str)}\n```")

        if ai_services_config:
            context_parts.append(f"## AI Services Configuration\n```json\n{json.dumps(ai_services_config, indent=2, default=str)}\n```")

        findings_summary = []
        for f in findings:
            findings_summary.append({
                "title": f.title,
                "severity": f.severity.value,
                "category": f.category.value,
                "resource": f.resource_name,
                "recommendation": f.recommendation
            })

        context_parts.append(f"## Automated Findings\n```json\n{json.dumps(findings_summary, indent=2)}\n```")

        prompt = f"""You are an Azure cloud architect expert specializing in API Management and Azure AI Services.
Analyze the following Azure configuration and automated findings, then provide a comprehensive health assessment.

{chr(10).join(context_parts)}

Please provide:

1. **Executive Summary** - A brief overview of the overall health status

2. **Critical Issues** - Any critical security or reliability concerns that need immediate attention

3. **Architecture Review** - Assessment of the current architecture and design patterns

4. **Security Assessment** - Detailed security review including:
   - Authentication and authorization
   - Network security
   - Data protection
   - Secret management
   - Content filtering / RAI policies

5. **Performance & Reliability** - Assessment of:
   - Scalability configuration
   - High availability setup
   - Disaster recovery readiness

6. **Cost Optimization** - Opportunities to optimize costs

7. **Recommended Actions** - Prioritized list of recommended improvements with:
   - Priority (P1/P2/P3)
   - Estimated effort (Low/Medium/High)
   - Expected benefit

8. **Best Practices Compliance** - How well the configuration aligns with Azure Well-Architected Framework

Format your response in clear markdown with headers and bullet points."""

        logger.info("Requesting Claude analysis...")

        if USE_AZURE_AI_CLIENT:
            # Use azure-ai-client (routes through APIM)
            return self.client.chat(
                prompt,
                model="claude-sonnet-4-5",  # Use deployment name
                max_tokens=4096
            )
        else:
            # Fall back to direct Anthropic SDK
            response = self.client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=4096,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            return response.content[0].text


def generate_html_report(result: HealthCheckResult, output_path: Path):
    """Generate an HTML report from the health check results."""

    severity_colors = {
        Severity.CRITICAL: "#dc3545",
        Severity.HIGH: "#fd7e14",
        Severity.MEDIUM: "#ffc107",
        Severity.LOW: "#17a2b8",
        Severity.INFO: "#6c757d",
    }

    findings_html = ""
    for finding in sorted(result.findings, key=lambda f: list(Severity).index(f.severity)):
        color = severity_colors[finding.severity]
        findings_html += f"""
        <div class="finding" style="border-left: 4px solid {color};">
            <div class="finding-header">
                <span class="severity" style="background-color: {color};">{finding.severity.value.upper()}</span>
                <span class="category">{finding.category.value}</span>
                <h4>{finding.title}</h4>
            </div>
            <p><strong>Resource:</strong> {finding.resource_type} - {finding.resource_name}</p>
            <p>{finding.description}</p>
            <p><strong>Recommendation:</strong> {finding.recommendation}</p>
        </div>
        """

    ai_analysis_html = ""
    if result.ai_analysis:
        # Convert markdown to basic HTML
        import re
        analysis = result.ai_analysis
        analysis = re.sub(r'^### (.+)$', r'<h3>\1</h3>', analysis, flags=re.MULTILINE)
        analysis = re.sub(r'^## (.+)$', r'<h2>\1</h2>', analysis, flags=re.MULTILINE)
        analysis = re.sub(r'^# (.+)$', r'<h1>\1</h1>', analysis, flags=re.MULTILINE)
        analysis = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', analysis)
        analysis = re.sub(r'\*(.+?)\*', r'<em>\1</em>', analysis)
        analysis = re.sub(r'^- (.+)$', r'<li>\1</li>', analysis, flags=re.MULTILINE)
        analysis = analysis.replace('\n\n', '</p><p>')
        ai_analysis_html = f'<div class="ai-analysis"><h2>AI Analysis</h2>{analysis}</div>'

    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Foundry Health Check Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 2px solid #0078d4; padding-bottom: 10px; }}
        .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
        .summary-card {{ flex: 1; padding: 20px; border-radius: 8px; text-align: center; }}
        .score {{ font-size: 48px; font-weight: bold; }}
        .score-good {{ background: #d4edda; color: #155724; }}
        .score-warning {{ background: #fff3cd; color: #856404; }}
        .score-bad {{ background: #f8d7da; color: #721c24; }}
        .finding {{ background: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 4px; }}
        .finding-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }}
        .severity {{ padding: 2px 8px; border-radius: 4px; color: white; font-size: 12px; font-weight: bold; }}
        .category {{ background: #e9ecef; padding: 2px 8px; border-radius: 4px; font-size: 12px; }}
        .finding h4 {{ margin: 0; }}
        .ai-analysis {{ margin-top: 30px; padding: 20px; background: #f0f7ff; border-radius: 8px; }}
        .ai-analysis h2 {{ color: #0078d4; }}
        .stats {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin: 20px 0; }}
        .stat {{ text-align: center; padding: 15px; background: #f8f9fa; border-radius: 4px; }}
        .stat-value {{ font-size: 24px; font-weight: bold; }}
        .timestamp {{ color: #6c757d; font-size: 14px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Foundry Health Check Report</h1>
        <p class="timestamp">Generated: {result.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        <p>Subscription: {result.subscription_id} | Resource Group: {result.resource_group}</p>

        <div class="summary">
            <div class="summary-card {'score-good' if result.score >= 80 else 'score-warning' if result.score >= 60 else 'score-bad'}">
                <div class="score">{result.score}</div>
                <div>Health Score</div>
            </div>
        </div>

        <div class="stats">
            <div class="stat">
                <div class="stat-value" style="color: #dc3545;">{result.critical_count}</div>
                <div>Critical</div>
            </div>
            <div class="stat">
                <div class="stat-value" style="color: #fd7e14;">{result.high_count}</div>
                <div>High</div>
            </div>
            <div class="stat">
                <div class="stat-value" style="color: #ffc107;">{len(result.get_findings_by_severity(Severity.MEDIUM))}</div>
                <div>Medium</div>
            </div>
            <div class="stat">
                <div class="stat-value" style="color: #17a2b8;">{len(result.get_findings_by_severity(Severity.LOW))}</div>
                <div>Low</div>
            </div>
            <div class="stat">
                <div class="stat-value" style="color: #6c757d;">{len(result.get_findings_by_severity(Severity.INFO))}</div>
                <div>Info</div>
            </div>
        </div>

        <h2>Findings ({len(result.findings)} total)</h2>
        {findings_html}

        {ai_analysis_html}
    </div>
</body>
</html>"""

    output_path.write_text(html, encoding='utf-8')
    logger.info(f"HTML report generated: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Foundry Health Check - Analyze APIM and AI Foundry configurations"
    )

    parser.add_argument(
        "--subscription", "-s",
        required=True,
        help="Azure subscription ID"
    )
    parser.add_argument(
        "--resource-group", "-g",
        required=True,
        help="Resource group name"
    )
    parser.add_argument(
        "--apim-name",
        help="Specific APIM instance to check (optional)"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file path for HTML report"
    )
    parser.add_argument(
        "--skip-ai-analysis",
        action="store_true",
        help="Skip Claude AI analysis"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output findings as JSON"
    )

    args = parser.parse_args()

    # Check for Claude API key (prefer AZURE_APIM_KEY for unified architecture)
    api_key = os.environ.get("AZURE_APIM_KEY") or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key and not args.skip_ai_analysis:
        if USE_AZURE_AI_CLIENT:
            logger.warning("AZURE_APIM_KEY not set. Skipping AI analysis.")
        else:
            logger.warning("ANTHROPIC_API_KEY not set. Skipping AI analysis.")
        args.skip_ai_analysis = True

    # Initialize Azure clients
    credential = DefaultAzureCredential()

    result = HealthCheckResult(
        timestamp=datetime.utcnow(),
        subscription_id=args.subscription,
        resource_group=args.resource_group
    )

    apim_config = None
    ai_services_config = None

    # Check APIM
    try:
        apim_client = ApiManagementClient(credential, args.subscription)

        if args.apim_name:
            apim_names = [args.apim_name]
        else:
            # List all APIM instances in the resource group
            services = list(apim_client.api_management_service.list_by_resource_group(args.resource_group))
            apim_names = [s.name for s in services]

        for apim_name in apim_names:
            logger.info(f"Checking APIM: {apim_name}")
            checker = APIMHealthChecker(apim_client, args.resource_group, apim_name)
            apim_config = checker.collect_configuration()
            findings = checker.check_health()
            for f in findings:
                result.add_finding(f)
            result.resources_scanned["apim"] = result.resources_scanned.get("apim", 0) + 1

    except Exception as e:
        logger.error(f"Error checking APIM: {e}")

    # Check AI Services
    try:
        ai_client = CognitiveServicesManagementClient(credential, args.subscription)
        checker = AIFoundryHealthChecker(
            ai_client, args.resource_group, args.subscription, credential
        )
        ai_services_config = checker.collect_configuration()
        findings = checker.check_health()
        for f in findings:
            result.add_finding(f)
        result.resources_scanned["ai_services"] = len(ai_services_config)

    except Exception as e:
        logger.error(f"Error checking AI Services: {e}")

    # Run Claude analysis
    if not args.skip_ai_analysis and api_key:
        try:
            analyzer = ClaudeAnalyzer(api_key)
            result.ai_analysis = analyzer.analyze(apim_config, ai_services_config, result.findings)
        except Exception as e:
            logger.error(f"Error during AI analysis: {e}")

    # Output results
    if args.json:
        output = {
            "timestamp": result.timestamp.isoformat(),
            "subscription_id": result.subscription_id,
            "resource_group": result.resource_group,
            "score": result.score,
            "resources_scanned": result.resources_scanned,
            "findings": [
                {
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity.value,
                    "category": f.category.value,
                    "resource_type": f.resource_type,
                    "resource_name": f.resource_name,
                    "recommendation": f.recommendation,
                }
                for f in result.findings
            ],
            "ai_analysis": result.ai_analysis
        }
        print(json.dumps(output, indent=2))
    else:
        # Print summary
        print("\n" + "=" * 60)
        print("FOUNDRY HEALTH CHECK REPORT")
        print("=" * 60)
        print(f"Subscription: {result.subscription_id}")
        print(f"Resource Group: {result.resource_group}")
        print(f"Timestamp: {result.timestamp}")
        print(f"\nHealth Score: {result.score}/100")
        print(f"\nFindings Summary:")
        print(f"  Critical: {result.critical_count}")
        print(f"  High: {result.high_count}")
        print(f"  Medium: {len(result.get_findings_by_severity(Severity.MEDIUM))}")
        print(f"  Low: {len(result.get_findings_by_severity(Severity.LOW))}")
        print(f"  Info: {len(result.get_findings_by_severity(Severity.INFO))}")

        print("\n" + "-" * 60)
        print("FINDINGS")
        print("-" * 60)

        for finding in sorted(result.findings, key=lambda f: list(Severity).index(f.severity)):
            print(f"\n[{finding.severity.value.upper()}] {finding.title}")
            print(f"  Resource: {finding.resource_type} - {finding.resource_name}")
            print(f"  {finding.description}")
            print(f"  Recommendation: {finding.recommendation}")

        if result.ai_analysis:
            print("\n" + "=" * 60)
            print("AI ANALYSIS")
            print("=" * 60)
            print(result.ai_analysis)

    # Generate HTML report if requested
    if args.output:
        output_path = Path(args.output)
        generate_html_report(result, output_path)

    # Return exit code based on findings
    if result.critical_count > 0:
        sys.exit(2)
    elif result.high_count > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
