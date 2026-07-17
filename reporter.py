import json
import sys

# Try importing rich for premium CLI styling
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.columns import Columns
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# ANSI Color Codes for fallback formatting
RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
WHITE = "\033[97m"

def print_json_report(parsed_data, analysis_results):
    """Outputs the complete parsed and analyzed data as structured JSON."""
    report = {
        'metadata': {
            'subject': parsed_data['subject'],
            'from': parsed_data['from'],
            'to': parsed_data['to'],
            'date': parsed_data['date'],
            'message_id': parsed_data['message_id'],
            'return_path': parsed_data['return_path'],
            'auth': parsed_data['auth']
        },
        'analysis': {
            'score': analysis_results['score'],
            'risk_level': analysis_results['risk_level'],
            'indicators_triggered': analysis_results['indicators'],
            'flagged_links': analysis_results['flagged_links'],
            'suspicious_attachments': analysis_results['suspicious_attachments']
        }
    }
    print(json.dumps(report, indent=2))

def format_risk_level_ansi(risk_level, score):
    if risk_level == 'High Risk':
        return f"{RED}{BOLD}🔥 HIGH RISK (Score: {score}){RESET}"
    elif risk_level == 'Medium Risk':
        return f"{YELLOW}{BOLD}⚠️ MEDIUM RISK (Score: {score}){RESET}"
    else:
        return f"{GREEN}{BOLD}✅ LOW RISK (Score: {score}){RESET}"

def print_fallback_dashboard(parsed_data, analysis, file_path):
    """Fallback terminal dashboard using standard print and ANSI escape codes."""
    print("=" * 80)
    print(f"{BOLD}{CYAN}DEFENSIVE EMAIL HEADER & BODY ANALYZER{RESET}")
    print("=" * 80)
    print(f"{BOLD}File Analyzed:{RESET} {file_path}")
    print(f"{BOLD}Verdict:{RESET} {format_risk_level_ansi(analysis['risk_level'], analysis['score'])}")
    print("-" * 80)
    
    # Envelope Metadata
    print(f"{BOLD}{WHITE}ENVELOPE & HEADERS{RESET}")
    print(f"  {BOLD}Subject:{RESET}     {parsed_data['subject']}")
    print(f"  {BOLD}From:{RESET}        {parsed_data['from']['raw']}")
    print(f"  {BOLD}Return-Path:{RESET} {parsed_data['return_path']['raw'] or '(Not specified)'}")
    print(f"  {BOLD}Date:{RESET}        {parsed_data['date']}")
    
    # Auth Status
    spf_col = GREEN if parsed_data['auth']['spf'] == 'pass' else (RED if parsed_data['auth']['spf'] == 'fail' else YELLOW)
    dkim_col = GREEN if parsed_data['auth']['dkim'] == 'pass' else (RED if parsed_data['auth']['dkim'] == 'fail' else YELLOW)
    print(f"  {BOLD}SPF Status:{RESET}  {spf_col}{parsed_data['auth']['spf'].upper()}{RESET} | {BOLD}DKIM Status:{RESET} {dkim_col}{parsed_data['auth']['dkim'].upper()}{RESET}")
    print("-" * 80)

    # Triggered Indicators
    print(f"{BOLD}{WHITE}SECURITY INDICATORS TRIGGERED ({len(analysis['indicators'])}){RESET}")
    if not analysis['indicators']:
        print(f"  {GREEN}No threats or anomalies detected.{RESET}")
    else:
        for ind in analysis['indicators']:
            sev_color = RED if ind['severity'] == 'High' else YELLOW
            print(f"  [{sev_color}{ind['severity']}{RESET}] {BOLD}{ind['name']}{RESET} (+{ind['score']} pts)")
            print(f"        {ind['description']}")
    print("-" * 80)

    # Flagged Links
    print(f"{BOLD}{WHITE}FLAGGED LINKS ({len(analysis['flagged_links'])}){RESET}")
    if not analysis['flagged_links']:
        print("  No suspicious links found.")
    else:
        for link in analysis['flagged_links']:
            print(f"  • {YELLOW}{link['url']}{RESET}")
            for reason in link['reasons']:
                print(f"    - {reason}")
    print("-" * 80)

    # Attachments
    print(f"{BOLD}{WHITE}ATTACHMENTS ({len(parsed_data['attachments'])}){RESET}")
    if not parsed_data['attachments']:
        print("  No attachments found.")
    else:
        for attach in parsed_data['attachments']:
            is_suspicious = attach in analysis['suspicious_attachments']
            att_col = RED if is_suspicious else GREEN
            susp_flag = f" {RED}{BOLD}[SUSPICIOUS]{RESET}" if is_suspicious else ""
            print(f"  • Name: {att_col}{attach['filename']}{RESET}{susp_flag}")
            print(f"    Type: {attach['content_type']} | Size: {attach['size_bytes']} bytes")
    print("=" * 80)

def print_rich_dashboard(parsed_data, analysis, file_path):
    """Premium visual terminal dashboard utilizing the Rich library."""
    console = Console()
    
    # Title
    console.print(Panel(
        f"[bold cyan]DEFENSIVE EMAIL HEADER & BODY ANALYZER[/bold cyan]\n"
        f"[dim]File path: {file_path}[/dim]",
        box=box.DOUBLE,
        border_style="cyan"
    ))

    # Verdict Banner
    risk_level = analysis['risk_level']
    score = analysis['score']
    if risk_level == 'High Risk':
        verdict_text = Text.assemble(("🔥 HIGH RISK DEVIATION DETECTED", "bold white on red"), f"  [Score: {score}]")
        border_style = "red"
    elif risk_level == 'Medium Risk':
        verdict_text = Text.assemble(("⚠️ SUSPICIOUS INDICATORS FOUND", "bold black on yellow"), f"  [Score: {score}]")
        border_style = "yellow"
    else:
        verdict_text = Text.assemble(("✅ NO HIGH-RISK THREATS IDENTIFIED", "bold white on green"), f"  [Score: {score}]")
        border_style = "green"
        
    console.print(Panel(verdict_text, title="Verdict", border_style=border_style))

    # Grid for Metadata & Auth
    meta_table = Table(show_header=False, box=box.SIMPLE, expand=True)
    meta_table.add_column("Key", style="bold white", width=15)
    meta_table.add_column("Value", style="dim")
    meta_table.add_row("Subject", parsed_data['subject'])
    meta_table.add_row("From", parsed_data['from']['raw'])
    meta_table.add_row("Return-Path", parsed_data['return_path']['raw'] or "[dim]Not Specified[/dim]")
    meta_table.add_row("Date", parsed_data['date'])
    meta_table.add_row("Message-ID", parsed_data['message_id'] or "[dim]Not Specified[/dim]")

    # Auth details
    spf_val = parsed_data['auth']['spf']
    dkim_val = parsed_data['auth']['dkim']
    
    spf_style = "bold green" if spf_val == "pass" else ("bold red" if spf_val == "fail" else "bold yellow")
    dkim_style = "bold green" if dkim_val == "pass" else ("bold red" if dkim_val == "fail" else "bold yellow")
    
    meta_table.add_row("SPF Status", f"[{spf_style}]{spf_val.upper()}[/{spf_style}]")
    meta_table.add_row("DKIM Status", f"[{dkim_style}]{dkim_val.upper()}[/{dkim_style}]")

    console.print(Panel(meta_table, title="Envelope & Security Headers", border_style="cyan"))

    # Security Indicators Table
    ind_table = Table(box=box.ROUNDED, expand=True)
    ind_table.add_column("Severity", width=10, justify="center")
    ind_table.add_column("Indicator", style="bold", width=25)
    ind_table.add_column("Impact", style="bold red", justify="right", width=8)
    ind_table.add_column("Description")

    for ind in analysis['indicators']:
        sev = ind['severity']
        sev_style = "bold red" if sev == "High" else "bold yellow"
        ind_table.add_row(
            f"[{sev_style}]{sev}[/{sev_style}]",
            ind['name'],
            f"+{ind['score']}",
            ind['description']
        )

    if not analysis['indicators']:
        ind_table.add_row("-", "[green]No threat indicators triggered[/green]", "0", "This email looks clean based on current heuristics.")

    console.print(Panel(ind_table, title=f"Security Indicators Triggered ({len(analysis['indicators'])})", border_style="cyan"))

    # Flagged Links Table
    link_table = Table(box=box.ROUNDED, expand=True)
    link_table.add_column("URL", style="yellow")
    link_table.add_column("Flag Reasons", style="bold red")

    for link in analysis['flagged_links']:
        link_table.add_row(
            link['url'],
            "\n".join(link['reasons'])
        )

    if not analysis['flagged_links']:
        link_table.add_row("[green]No suspicious links flagged[/green]", "All domains match claimed sender or whitelisted services.")

    console.print(Panel(link_table, title=f"Suspicious URL Checks ({len(analysis['flagged_links'])} flagged / {len(analysis['all_links_found'])} total)", border_style="cyan"))

    # Attachments Table
    attach_table = Table(box=box.ROUNDED, expand=True)
    attach_table.add_column("Filename", style="bold")
    attach_table.add_column("Content Type")
    attach_table.add_column("Size (Bytes)", justify="right")
    attach_table.add_column("Verdict", justify="center")

    for attach in parsed_data['attachments']:
        is_suspicious = attach in analysis['suspicious_attachments']
        verdict = "[bold red]SUSPICIOUS[/bold red]" if is_suspicious else "[bold green]PASS[/bold green]"
        attach_table.add_row(
            attach['filename'],
            attach['content_type'],
            f"{attach['size_bytes']:,}",
            verdict
        )

    if not parsed_data['attachments']:
        attach_table.add_row("[dim]No attachments found[/dim]", "-", "-", "-")

    console.print(Panel(attach_table, title=f"Attachments ({len(parsed_data['attachments'])})", border_style="cyan"))

def print_dashboard(parsed_data, analysis, file_path):
    """Dispatches rendering to Rich or standard ANSI print depending on availability."""
    if RICH_AVAILABLE:
        print_rich_dashboard(parsed_data, analysis, file_path)
    else:
        print_fallback_dashboard(parsed_data, analysis, file_path)
