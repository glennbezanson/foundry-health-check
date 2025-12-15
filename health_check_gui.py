#!/usr/bin/env python3
"""
Foundry Health Check GUI

A graphical interface for analyzing Azure API Management and AI Foundry
configurations against best practices with Claude AI recommendations.

Features:
- Secure API key storage using Windows Credential Manager
- Azure subscription/resource group browser
- Interactive health check with progress
- HTML report generation
- Claude AI analysis integration
"""

import json
import logging
import os
import sys
import threading
import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk
import tkinter as tk
from typing import Any, Dict, List, Optional

# Import the health check logic
from health_check import (
    APIMHealthChecker,
    AIFoundryHealthChecker,
    ClaudeAnalyzer,
    Finding,
    HealthCheckResult,
    Severity,
    generate_html_report,
)

# Azure imports
from azure.identity import DefaultAzureCredential, InteractiveBrowserCredential
from azure.mgmt.apimanagement import ApiManagementClient
from azure.mgmt.cognitiveservices import CognitiveServicesManagementClient
from azure.mgmt.resource import SubscriptionClient, ResourceManagementClient

# For secure credential storage on Windows
try:
    import keyring
    KEYRING_AVAILABLE = True
except ImportError:
    KEYRING_AVAILABLE = False

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Constants
APP_NAME = "FoundryHealthCheck"
CREDENTIAL_SERVICE = "FoundryHealthCheck_Anthropic"
CONFIG_FILE = Path(__file__).parent / "config.json"


class SecureStorage:
    """Handles secure storage of API keys using Windows Credential Manager."""

    @staticmethod
    def save_api_key(api_key: str) -> bool:
        """Save API key securely."""
        if KEYRING_AVAILABLE:
            try:
                keyring.set_password(CREDENTIAL_SERVICE, "api_key", api_key)
                return True
            except Exception as e:
                logger.error(f"Failed to save API key: {e}")
                return False
        else:
            # Fallback to config file (less secure but works)
            try:
                config = SecureStorage._load_config()
                config["api_key"] = api_key
                SecureStorage._save_config(config)
                return True
            except Exception as e:
                logger.error(f"Failed to save API key to config: {e}")
                return False

    @staticmethod
    def get_api_key() -> Optional[str]:
        """Retrieve API key from secure storage."""
        if KEYRING_AVAILABLE:
            try:
                return keyring.get_password(CREDENTIAL_SERVICE, "api_key")
            except Exception:
                pass

        # Fallback to config file
        try:
            config = SecureStorage._load_config()
            return config.get("api_key")
        except Exception:
            return None

    @staticmethod
    def delete_api_key() -> bool:
        """Delete API key from secure storage."""
        if KEYRING_AVAILABLE:
            try:
                keyring.delete_password(CREDENTIAL_SERVICE, "api_key")
            except Exception:
                pass

        # Also remove from config file
        try:
            config = SecureStorage._load_config()
            if "api_key" in config:
                del config["api_key"]
                SecureStorage._save_config(config)
            return True
        except Exception:
            return False

    @staticmethod
    def _load_config() -> dict:
        """Load configuration from file."""
        if CONFIG_FILE.exists():
            return json.loads(CONFIG_FILE.read_text())
        return {}

    @staticmethod
    def _save_config(config: dict):
        """Save configuration to file."""
        CONFIG_FILE.write_text(json.dumps(config, indent=2))

    @staticmethod
    def save_last_settings(subscription: str, resource_group: str, apim_name: str = ""):
        """Save last used settings."""
        config = SecureStorage._load_config()
        config["last_subscription"] = subscription
        config["last_resource_group"] = resource_group
        config["last_apim_name"] = apim_name
        SecureStorage._save_config(config)

    @staticmethod
    def get_last_settings() -> Dict[str, str]:
        """Get last used settings."""
        config = SecureStorage._load_config()
        return {
            "subscription": config.get("last_subscription", ""),
            "resource_group": config.get("last_resource_group", ""),
            "apim_name": config.get("last_apim_name", ""),
        }


class HealthCheckGUI:
    """Main GUI application for Foundry Health Check."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Foundry Health Check")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)

        # State
        self.credential = None
        self.subscriptions = []
        self.resource_groups = []
        self.apim_instances = []
        self.current_result: Optional[HealthCheckResult] = None
        self.is_running = False

        # Create UI
        self._create_menu()
        self._create_main_frame()
        self._load_saved_settings()

        # Check if keyring is available
        if not KEYRING_AVAILABLE:
            logger.warning("keyring not available, using config file for API key storage")

    def _create_menu(self):
        """Create the menu bar."""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Export Report...", command=self._export_report)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)

        # Settings menu
        settings_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Settings", menu=settings_menu)
        settings_menu.add_command(label="Configure API Key...", command=self._show_api_key_dialog)
        settings_menu.add_command(label="Clear Saved Credentials", command=self._clear_credentials)

        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self._show_about)

    def _create_main_frame(self):
        """Create the main application frame."""
        # Main container with padding
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # === Azure Connection Section ===
        azure_frame = ttk.LabelFrame(main_frame, text="Azure Connection", padding="10")
        azure_frame.pack(fill=tk.X, pady=(0, 10))

        # Login button and status
        login_frame = ttk.Frame(azure_frame)
        login_frame.pack(fill=tk.X, pady=(0, 10))

        self.login_btn = ttk.Button(login_frame, text="Connect to Azure", command=self._connect_azure)
        self.login_btn.pack(side=tk.LEFT)

        self.azure_status = ttk.Label(login_frame, text="Not connected", foreground="red")
        self.azure_status.pack(side=tk.LEFT, padx=(10, 0))

        # Subscription selection
        sub_frame = ttk.Frame(azure_frame)
        sub_frame.pack(fill=tk.X, pady=(0, 5))

        ttk.Label(sub_frame, text="Subscription:").pack(side=tk.LEFT)
        self.subscription_var = tk.StringVar()
        self.subscription_combo = ttk.Combobox(sub_frame, textvariable=self.subscription_var, width=60, state="readonly")
        self.subscription_combo.pack(side=tk.LEFT, padx=(10, 0), fill=tk.X, expand=True)
        self.subscription_combo.bind("<<ComboboxSelected>>", self._on_subscription_change)

        # Resource Group selection
        rg_frame = ttk.Frame(azure_frame)
        rg_frame.pack(fill=tk.X, pady=(0, 5))

        ttk.Label(rg_frame, text="Resource Group:").pack(side=tk.LEFT)
        self.rg_var = tk.StringVar()
        self.rg_combo = ttk.Combobox(rg_frame, textvariable=self.rg_var, width=60, state="readonly")
        self.rg_combo.pack(side=tk.LEFT, padx=(10, 0), fill=tk.X, expand=True)
        self.rg_combo.bind("<<ComboboxSelected>>", self._on_rg_change)

        # APIM selection (optional)
        apim_frame = ttk.Frame(azure_frame)
        apim_frame.pack(fill=tk.X)

        ttk.Label(apim_frame, text="APIM (optional):").pack(side=tk.LEFT)
        self.apim_var = tk.StringVar()
        self.apim_combo = ttk.Combobox(apim_frame, textvariable=self.apim_var, width=60, state="readonly")
        self.apim_combo.pack(side=tk.LEFT, padx=(10, 0), fill=tk.X, expand=True)

        # === Analysis Options ===
        options_frame = ttk.LabelFrame(main_frame, text="Analysis Options", padding="10")
        options_frame.pack(fill=tk.X, pady=(0, 10))

        self.use_ai_var = tk.BooleanVar(value=True)
        self.ai_check = ttk.Checkbutton(options_frame, text="Include Claude AI Analysis", variable=self.use_ai_var)
        self.ai_check.pack(side=tk.LEFT)

        self.api_key_status = ttk.Label(options_frame, text="")
        self.api_key_status.pack(side=tk.LEFT, padx=(20, 0))
        self._update_api_key_status()

        ttk.Button(options_frame, text="Configure API Key", command=self._show_api_key_dialog).pack(side=tk.RIGHT)

        # === Run Button ===
        run_frame = ttk.Frame(main_frame)
        run_frame.pack(fill=tk.X, pady=(0, 10))

        self.run_btn = ttk.Button(run_frame, text="Run Health Check", command=self._run_health_check, state="disabled")
        self.run_btn.pack(side=tk.LEFT)

        self.progress = ttk.Progressbar(run_frame, mode="indeterminate", length=200)
        self.progress.pack(side=tk.LEFT, padx=(10, 0))

        self.status_label = ttk.Label(run_frame, text="")
        self.status_label.pack(side=tk.LEFT, padx=(10, 0))

        # === Results Section ===
        results_frame = ttk.LabelFrame(main_frame, text="Results", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True)

        # Score display
        score_frame = ttk.Frame(results_frame)
        score_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(score_frame, text="Health Score:", font=("Segoe UI", 12, "bold")).pack(side=tk.LEFT)
        self.score_label = ttk.Label(score_frame, text="--", font=("Segoe UI", 24, "bold"))
        self.score_label.pack(side=tk.LEFT, padx=(10, 0))

        # Severity counts
        self.severity_frame = ttk.Frame(score_frame)
        self.severity_frame.pack(side=tk.RIGHT)

        self.severity_labels = {}
        for severity, color in [("Critical", "red"), ("High", "orange"), ("Medium", "goldenrod"), ("Low", "blue"), ("Info", "gray")]:
            lbl = ttk.Label(self.severity_frame, text=f"{severity}: 0")
            lbl.pack(side=tk.LEFT, padx=(10, 0))
            self.severity_labels[severity.lower()] = lbl

        # Results text area
        self.results_text = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD, height=20)
        self.results_text.pack(fill=tk.BOTH, expand=True)

        # Configure text tags for coloring
        self.results_text.tag_configure("critical", foreground="red", font=("Consolas", 10, "bold"))
        self.results_text.tag_configure("high", foreground="orange", font=("Consolas", 10, "bold"))
        self.results_text.tag_configure("medium", foreground="goldenrod", font=("Consolas", 10, "bold"))
        self.results_text.tag_configure("low", foreground="blue", font=("Consolas", 10))
        self.results_text.tag_configure("info", foreground="gray", font=("Consolas", 10))
        self.results_text.tag_configure("header", font=("Consolas", 11, "bold"))
        self.results_text.tag_configure("good", foreground="green", font=("Consolas", 10, "bold"))

        # Export buttons
        export_frame = ttk.Frame(results_frame)
        export_frame.pack(fill=tk.X, pady=(10, 0))

        ttk.Button(export_frame, text="Export HTML Report", command=self._export_report).pack(side=tk.LEFT)
        ttk.Button(export_frame, text="Export JSON", command=self._export_json).pack(side=tk.LEFT, padx=(10, 0))
        ttk.Button(export_frame, text="Open in Browser", command=self._open_in_browser).pack(side=tk.LEFT, padx=(10, 0))

    def _load_saved_settings(self):
        """Load previously saved settings."""
        settings = SecureStorage.get_last_settings()
        # Settings will be applied after Azure connection

    def _update_api_key_status(self):
        """Update the API key status display."""
        api_key = SecureStorage.get_api_key()
        if api_key:
            self.api_key_status.config(text="API Key: Configured", foreground="green")
        else:
            self.api_key_status.config(text="API Key: Not configured", foreground="red")

    def _show_api_key_dialog(self):
        """Show dialog to configure API key."""
        dialog = tk.Toplevel(self.root)
        dialog.title("Configure Anthropic API Key")
        dialog.geometry("500x200")
        dialog.transient(self.root)
        dialog.grab_set()

        frame = ttk.Frame(dialog, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Enter your Anthropic API Key:").pack(anchor=tk.W)
        ttk.Label(frame, text="(Get one at https://console.anthropic.com)", foreground="gray").pack(anchor=tk.W)

        key_var = tk.StringVar()
        current_key = SecureStorage.get_api_key()
        if current_key:
            key_var.set(current_key[:10] + "..." + current_key[-4:] if len(current_key) > 14 else current_key)

        key_entry = ttk.Entry(frame, textvariable=key_var, width=60, show="*")
        key_entry.pack(fill=tk.X, pady=(10, 0))

        show_var = tk.BooleanVar(value=False)

        def toggle_show():
            if show_var.get():
                key_entry.config(show="")
            else:
                key_entry.config(show="*")

        ttk.Checkbutton(frame, text="Show key", variable=show_var, command=toggle_show).pack(anchor=tk.W, pady=(5, 0))

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=(20, 0))

        def save_key():
            key = key_var.get().strip()
            if key and not key.endswith("..."):
                if SecureStorage.save_api_key(key):
                    messagebox.showinfo("Success", "API key saved securely!")
                    self._update_api_key_status()
                    dialog.destroy()
                else:
                    messagebox.showerror("Error", "Failed to save API key")
            else:
                messagebox.showwarning("Warning", "Please enter a valid API key")

        def delete_key():
            if messagebox.askyesno("Confirm", "Are you sure you want to delete the saved API key?"):
                SecureStorage.delete_api_key()
                self._update_api_key_status()
                dialog.destroy()

        ttk.Button(btn_frame, text="Save", command=save_key).pack(side=tk.LEFT)
        ttk.Button(btn_frame, text="Delete Key", command=delete_key).pack(side=tk.LEFT, padx=(10, 0))
        ttk.Button(btn_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT)

    def _clear_credentials(self):
        """Clear all saved credentials."""
        if messagebox.askyesno("Confirm", "This will clear all saved credentials and settings. Continue?"):
            SecureStorage.delete_api_key()
            if CONFIG_FILE.exists():
                CONFIG_FILE.unlink()
            self._update_api_key_status()
            messagebox.showinfo("Success", "All credentials cleared")

    def _connect_azure(self):
        """Connect to Azure using DefaultAzureCredential."""
        self.login_btn.config(state="disabled")
        self.azure_status.config(text="Connecting...", foreground="orange")
        self.root.update()

        def connect():
            try:
                self.credential = DefaultAzureCredential()
                sub_client = SubscriptionClient(self.credential)
                self.subscriptions = list(sub_client.subscriptions.list())

                self.root.after(0, self._on_azure_connected)
            except Exception as e:
                self.root.after(0, lambda: self._on_azure_error(str(e)))

        threading.Thread(target=connect, daemon=True).start()

    def _on_azure_connected(self):
        """Handle successful Azure connection."""
        self.azure_status.config(text="Connected", foreground="green")
        self.login_btn.config(state="normal", text="Reconnect")

        # Populate subscriptions
        sub_names = [f"{s.display_name} ({s.subscription_id})" for s in self.subscriptions]
        self.subscription_combo["values"] = sub_names

        # Try to select last used subscription
        settings = SecureStorage.get_last_settings()
        if settings["subscription"]:
            for i, s in enumerate(self.subscriptions):
                if s.subscription_id == settings["subscription"]:
                    self.subscription_combo.current(i)
                    self._on_subscription_change(None)
                    break

    def _on_azure_error(self, error: str):
        """Handle Azure connection error."""
        self.azure_status.config(text="Connection failed", foreground="red")
        self.login_btn.config(state="normal")
        messagebox.showerror("Azure Connection Error", f"Failed to connect to Azure:\n\n{error}")

    def _on_subscription_change(self, event):
        """Handle subscription selection change."""
        idx = self.subscription_combo.current()
        if idx < 0:
            return

        subscription = self.subscriptions[idx]
        self.rg_combo.set("")
        self.apim_combo.set("")
        self.rg_combo["values"] = []
        self.apim_combo["values"] = []
        self.run_btn.config(state="disabled")

        def load_rgs():
            try:
                rm_client = ResourceManagementClient(self.credential, subscription.subscription_id)
                self.resource_groups = list(rm_client.resource_groups.list())
                rg_names = [rg.name for rg in self.resource_groups]
                self.root.after(0, lambda: self._update_rg_list(rg_names))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to load resource groups: {e}"))

        threading.Thread(target=load_rgs, daemon=True).start()

    def _update_rg_list(self, rg_names: List[str]):
        """Update resource group combo box."""
        self.rg_combo["values"] = rg_names

        # Try to select last used RG
        settings = SecureStorage.get_last_settings()
        if settings["resource_group"] in rg_names:
            self.rg_combo.set(settings["resource_group"])
            self._on_rg_change(None)

    def _on_rg_change(self, event):
        """Handle resource group selection change."""
        rg_name = self.rg_var.get()
        if not rg_name:
            return

        idx = self.subscription_combo.current()
        subscription = self.subscriptions[idx]

        self.apim_combo.set("")
        self.apim_combo["values"] = []
        self.run_btn.config(state="normal")

        def load_apim():
            try:
                apim_client = ApiManagementClient(self.credential, subscription.subscription_id)
                services = list(apim_client.api_management_service.list_by_resource_group(rg_name))
                apim_names = ["(All APIM instances)"] + [s.name for s in services]
                self.apim_instances = services
                self.root.after(0, lambda: self._update_apim_list(apim_names))
            except Exception as e:
                self.root.after(0, lambda: self.apim_combo.configure(values=["(No APIM found)"]))

        threading.Thread(target=load_apim, daemon=True).start()

    def _update_apim_list(self, apim_names: List[str]):
        """Update APIM combo box."""
        self.apim_combo["values"] = apim_names
        self.apim_combo.current(0)

        # Try to select last used APIM
        settings = SecureStorage.get_last_settings()
        if settings["apim_name"] in apim_names:
            self.apim_combo.set(settings["apim_name"])

    def _run_health_check(self):
        """Run the health check."""
        if self.is_running:
            return

        idx = self.subscription_combo.current()
        if idx < 0:
            messagebox.showwarning("Warning", "Please select a subscription")
            return

        rg_name = self.rg_var.get()
        if not rg_name:
            messagebox.showwarning("Warning", "Please select a resource group")
            return

        subscription = self.subscriptions[idx]
        apim_name = self.apim_var.get()
        if apim_name == "(All APIM instances)" or apim_name == "(No APIM found)":
            apim_name = None

        use_ai = self.use_ai_var.get()
        api_key = SecureStorage.get_api_key() if use_ai else None

        if use_ai and not api_key:
            if not messagebox.askyesno("No API Key", "Claude AI analysis requires an API key. Continue without AI analysis?"):
                return
            use_ai = False

        # Save settings
        SecureStorage.save_last_settings(subscription.subscription_id, rg_name, apim_name or "")

        # Start health check
        self.is_running = True
        self.run_btn.config(state="disabled")
        self.progress.start()
        self.results_text.delete(1.0, tk.END)
        self.status_label.config(text="Running health check...")

        def run():
            try:
                result = HealthCheckResult(
                    timestamp=datetime.now(timezone.utc),
                    subscription_id=subscription.subscription_id,
                    resource_group=rg_name
                )

                apim_config = None
                ai_services_config = None

                # Check APIM
                self.root.after(0, lambda: self.status_label.config(text="Checking APIM..."))
                try:
                    apim_client = ApiManagementClient(self.credential, subscription.subscription_id)

                    if apim_name:
                        apim_names = [apim_name]
                    else:
                        services = list(apim_client.api_management_service.list_by_resource_group(rg_name))
                        apim_names = [s.name for s in services]

                    for name in apim_names:
                        checker = APIMHealthChecker(apim_client, rg_name, name)
                        apim_config = checker.collect_configuration()
                        findings = checker.check_health()
                        for f in findings:
                            result.add_finding(f)
                        result.resources_scanned["apim"] = result.resources_scanned.get("apim", 0) + 1

                except Exception as e:
                    logger.error(f"Error checking APIM: {e}")

                # Check AI Services
                self.root.after(0, lambda: self.status_label.config(text="Checking AI Services..."))
                try:
                    ai_client = CognitiveServicesManagementClient(self.credential, subscription.subscription_id)
                    checker = AIFoundryHealthChecker(ai_client, rg_name)
                    ai_services_config = checker.collect_configuration()
                    findings = checker.check_health()
                    for f in findings:
                        result.add_finding(f)
                    result.resources_scanned["ai_services"] = len(ai_services_config)

                except Exception as e:
                    logger.error(f"Error checking AI Services: {e}")

                # Run Claude analysis
                if use_ai and api_key:
                    self.root.after(0, lambda: self.status_label.config(text="Running AI analysis..."))
                    try:
                        analyzer = ClaudeAnalyzer(api_key)
                        result.ai_analysis = analyzer.analyze(apim_config, ai_services_config, result.findings)
                    except Exception as e:
                        logger.error(f"Error during AI analysis: {e}")
                        result.ai_analysis = f"AI analysis failed: {e}"

                self.current_result = result
                self.root.after(0, lambda: self._display_results(result))

            except Exception as e:
                self.root.after(0, lambda: self._on_check_error(str(e)))
            finally:
                self.root.after(0, self._on_check_complete)

        threading.Thread(target=run, daemon=True).start()

    def _on_check_complete(self):
        """Handle health check completion."""
        self.is_running = False
        self.run_btn.config(state="normal")
        self.progress.stop()
        self.status_label.config(text="Complete")

    def _on_check_error(self, error: str):
        """Handle health check error."""
        messagebox.showerror("Error", f"Health check failed:\n\n{error}")

    def _display_results(self, result: HealthCheckResult):
        """Display health check results in the UI."""
        # Update score
        score = result.score
        if score >= 80:
            color = "green"
        elif score >= 60:
            color = "orange"
        else:
            color = "red"
        self.score_label.config(text=f"{score}/100", foreground=color)

        # Update severity counts
        self.severity_labels["critical"].config(text=f"Critical: {result.critical_count}")
        self.severity_labels["high"].config(text=f"High: {result.high_count}")
        self.severity_labels["medium"].config(text=f"Medium: {len(result.get_findings_by_severity(Severity.MEDIUM))}")
        self.severity_labels["low"].config(text=f"Low: {len(result.get_findings_by_severity(Severity.LOW))}")
        self.severity_labels["info"].config(text=f"Info: {len(result.get_findings_by_severity(Severity.INFO))}")

        # Display findings
        self.results_text.delete(1.0, tk.END)

        self.results_text.insert(tk.END, "FINDINGS\n", "header")
        self.results_text.insert(tk.END, "=" * 60 + "\n\n")

        for finding in sorted(result.findings, key=lambda f: list(Severity).index(f.severity)):
            severity_tag = finding.severity.value
            self.results_text.insert(tk.END, f"[{finding.severity.value.upper()}] ", severity_tag)
            self.results_text.insert(tk.END, f"{finding.title}\n")
            self.results_text.insert(tk.END, f"  Resource: {finding.resource_type} - {finding.resource_name}\n")
            self.results_text.insert(tk.END, f"  {finding.description}\n")
            self.results_text.insert(tk.END, f"  Recommendation: {finding.recommendation}\n\n")

        if result.ai_analysis:
            self.results_text.insert(tk.END, "\nAI ANALYSIS\n", "header")
            self.results_text.insert(tk.END, "=" * 60 + "\n\n")
            self.results_text.insert(tk.END, result.ai_analysis)

    def _export_report(self):
        """Export results to HTML report."""
        if not self.current_result:
            messagebox.showwarning("Warning", "No results to export. Run a health check first.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML files", "*.html"), ("All files", "*.*")],
            initialfile=f"health-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.html"
        )

        if file_path:
            try:
                generate_html_report(self.current_result, Path(file_path))
                messagebox.showinfo("Success", f"Report exported to:\n{file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export report:\n{e}")

    def _export_json(self):
        """Export results to JSON."""
        if not self.current_result:
            messagebox.showwarning("Warning", "No results to export. Run a health check first.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=f"health-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
        )

        if file_path:
            try:
                output = {
                    "timestamp": self.current_result.timestamp.isoformat(),
                    "subscription_id": self.current_result.subscription_id,
                    "resource_group": self.current_result.resource_group,
                    "score": self.current_result.score,
                    "resources_scanned": self.current_result.resources_scanned,
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
                        for f in self.current_result.findings
                    ],
                    "ai_analysis": self.current_result.ai_analysis
                }
                Path(file_path).write_text(json.dumps(output, indent=2))
                messagebox.showinfo("Success", f"JSON exported to:\n{file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export JSON:\n{e}")

    def _open_in_browser(self):
        """Open results in browser as HTML."""
        if not self.current_result:
            messagebox.showwarning("Warning", "No results to display. Run a health check first.")
            return

        # Create temp HTML file
        temp_path = Path(__file__).parent / "temp_report.html"
        try:
            generate_html_report(self.current_result, temp_path)
            webbrowser.open(temp_path.as_uri())
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open in browser:\n{e}")

    def _show_about(self):
        """Show about dialog."""
        messagebox.showinfo(
            "About Foundry Health Check",
            "Foundry Health Check v1.0\n\n"
            "Analyzes Azure API Management and AI Foundry\n"
            "configurations against best practices.\n\n"
            "Features:\n"
            "- Automated security and reliability checks\n"
            "- Claude AI-powered recommendations\n"
            "- HTML and JSON report generation\n\n"
            "Created with Claude Code"
        )


def main():
    """Main entry point."""
    root = tk.Tk()

    # Set icon if available
    try:
        # You could add an icon here
        pass
    except Exception:
        pass

    # Apply a theme
    style = ttk.Style()
    if "clam" in style.theme_names():
        style.theme_use("clam")

    app = HealthCheckGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
