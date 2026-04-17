""Command-line interface for the Credential Orchestrator."""
import asyncio
import logging
import sys
import json
from pathlib import Path
from typing import List, Optional, Dict, Any, AsyncGenerator
from datetime import datetime

import click
from rich.console import Console
from rich.progress import (
    Progress, SpinnerColumn, TextColumn, BarColumn, 
    TaskProgressColumn, TimeRemainingColumn
)

from .models import (
    Target, Credential, AttackProfile, ProtocolType,
    AttackStats, AuthResult, AuthResultStatus
)
from .orchestrator import CredentialOrchestrator
from .formatters import get_formatter, OutputFormat
from .auth_handlers import AuthHandlerFactory

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

console = Console()

# Type aliases
CredentialsList = List[Credential]
TargetsList = List[Target]


def load_targets(file_path: str) -> TargetsList:
    """Load targets from a file."""
    targets = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Handle different target formats:
                # 1. host:port
                # 2. protocol://host:port
                # 3. host:port:protocol
                if '://' in line:
                    # Format: protocol://host:port
                    protocol_part, rest = line.split('://', 1)
                    protocol = ProtocolType(protocol_part.lower())
                    if ':' in rest:
                        host, port = rest.rsplit(':', 1)
                        port = int(port)
                    else:
                        host = rest
                        port = 0  # Will be set based on protocol
                else:
                    # Format: host:port:protocol or host:port
                    parts = line.split(':')
                    if len(parts) == 3:
                        host, port, protocol_part = parts
                        protocol = ProtocolType(protocol_part.lower())
                        port = int(port)
                    else:
                        host, port = parts
                        port = int(port)
                        protocol = ProtocolType.SSH  # Default protocol
                
                # Set default ports if not specified
                if port == 0:
                    if protocol == ProtocolType.SSH:
                        port = 22
                    elif protocol == ProtocolType.RDP:
                        port = 3389
                    elif protocol == ProtocolType.LDAP:
                        port = 389
                    elif protocol == ProtocolType.HTTP:
                        port = 80
                    elif protocol == ProtocolType.HTTPS:
                        port = 443
                
                targets.append(Target(
                    host=host,
                    port=port,
                    protocol=protocol
                ))
    except Exception as e:
        console.print(f"[red]Error loading targets: {str(e)}[/]")
        sys.exit(1)
    
    if not targets:
        console.print("[yellow]No valid targets found in the input file.[/]")
        sys.exit(1)
    
    return targets


def load_credentials(
    username_file: Optional[str] = None,
    password_file: Optional[str] = None,
    credentials_file: Optional[str] = None,
    domain: Optional[str] = None
) -> CredentialsList:
    """Load credentials from files."""
    credentials = []
    
    if credentials_file:
        # Load from username:password file
        try:
            with open(credentials_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Handle different formats:
                    # 1. username:password
                    # 2. domain\\username:password
                    # 3. username@domain:password
                    if '\\' in line:
                        # Format: domain\username:password
                        user_pass = line.split('\\', 1)
                        cred_domain = user_pass[0]
                        user_pass = user_pass[1].split(':', 1)
                        if len(user_pass) == 2:
                            username, password = user_pass
                            credentials.append(Credential(
                                username=username,
                                password=password,
                                domain=cred_domain
                            ))
                    elif '@' in line and ':' in line:
                        # Format: username@domain:password
                        user_domain, password = line.split(':', 1)
                        if '@' in user_domain:
                            username, cred_domain = user_domain.split('@', 1)
                            credentials.append(Credential(
                                username=username,
                                password=password,
                                domain=cred_domain
                            ))
                    else:
                        # Format: username:password
                        parts = line.split(':', 1)
                        if len(parts) == 2:
                            username, password = parts
                            credentials.append(Credential(
                                username=username,
                                password=password,
                                domain=domain
                            ))
        except Exception as e:
            console.print(f"[red]Error loading credentials: {str(e)}[/]")
            sys.exit(1)
    elif username_file and password_file:
        # Load from separate username and password files
        try:
            with open(username_file, 'r') as uf, open(password_file, 'r') as pf:
                usernames = [line.strip() for line in uf if line.strip() and not line.startswith('#')]
                passwords = [line.strip() for line in pf if line.strip() and not line.startswith('#')]
                
                for username in usernames:
                    for password in passwords:
                        credentials.append(Credential(
                            username=username,
                            password=password,
                            domain=domain
                        ))
        except Exception as e:
            console.print(f"[red]Error loading credentials: {str(e)}[/]")
            sys.exit(1)
    else:
        console.print("[red]Either --credentials or both --usernames and --passwords must be provided.[/]")
        sys.exit(1)
    
    if not credentials:
        console.print("[yellow]No valid credentials found in the input files.[/]")
        sys.exit(1)
    
    return credentials


def save_results(results: List[Dict[str, Any]], output_file: str, format: OutputFormat):
    """Save results to a file in the specified format."""
    try:
        with open(output_file, 'w') as f:
            if format == OutputFormat.JSON:
                json.dump(results, f, indent=2)
            else:
                for result in results:
                    f.write(f"{result}\n")
        console.print(f"[green]Results saved to {output_file}[/]")
    except Exception as e:
        console.print(f"[red]Error saving results: {str(e)}[/]")


async def run_attack(
    orchestrator: CredentialOrchestrator,
    credentials: CredentialsList,
    output_format: OutputFormat = OutputFormat.TABLE,
    verbose: bool = False,
    output_file: Optional[str] = None
) -> None:
    """Run the attack and display results."""
    formatter = get_formatter(output_format, verbose)
    results = []
    
    # Progress bar setup
    with Progress(
        SpinnerColumn(),
        "•",
        "[progress.description]{task.description}",
        BarColumn(bar_width=None),
        "•",
        TaskProgressColumn(),
        "•",
        TimeRemainingColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Testing credentials...", total=len(credentials))
        
        # Process results as they come in
        async for result in orchestrator.run_attack(credentials):
            formatted = formatter.format_result(result)
            results.append(formatted)
            
            # Update progress
            progress.update(task, advance=1)
            
            # Display result if it's a success or error (in verbose mode)
            if result.status == AuthResultStatus.SUCCESS or (verbose and result.status != AuthResultStatus.FAILURE):
                console.print(formatted)
    
    # Display summary
    summary = formatter.format_summary(
        [r for r in results if isinstance(r, AuthResult)],
        orchestrator.stats
    )
    console.print(summary)
    
    # Save results if output file is specified
    if output_file:
        save_results(results, output_file, output_format)


@click.command()
@click.option('--targets', '-t', required=True, help='File containing target hosts (one per line)')
@click.option('--usernames', '-u', help='File containing usernames (one per line)')
@click.option('--passwords', '-p', help='File containing passwords (one per line)')
@click.option('--credentials', '-c', help='File containing username:password pairs (one per line)')
@click.option('--domain', '-d', help='Domain to use for authentication')
@click.option('--protocol', type=click.Choice([p.value for p in ProtocolType]), 
              default=ProtocolType.SSH.value, help='Authentication protocol')
@click.option('--rate-limit', type=int, default=10, help='Maximum requests per minute')
@click.option('--max-attempts', type=int, default=3, help='Maximum attempts per account')
@click.option('--output', '-o', help='Output file to save results')
@click.option('--format', 'output_format', 
              type=click.Choice([f.value for f in OutputFormat]), 
              default=OutputFormat.TABLE.value, help='Output format')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--stop-on-success', is_flag=True, help='Stop after first successful login')
@click.option('--delay-min', type=float, default=1.0, help='Minimum delay between attempts (seconds)')
@click.option('--delay-max', type=float, default=5.0, help='Maximum delay between attempts (seconds)')
def main(
    targets: str,
    usernames: Optional[str],
    passwords: Optional[str],
    credentials: Optional[str],
    domain: Optional[str],
    protocol: str,
    rate_limit: int,
    max_attempts: int,
    output: Optional[str],
    output_format: str,
    verbose: bool,
    stop_on_success: bool,
    delay_min: float,
    delay_max: float
):
    """Credential Spraying and Brute Force Orchestrator."""
    # Validate inputs
    if not (credentials or (usernames and passwords)):
        console.print("[red]Error: Either --credentials or both --usernames and --passwords must be provided.[/]")
        sys.exit(1)
    
    if delay_min < 0 or delay_max < delay_min:
        console.print("[red]Error: Invalid delay values. delay_min must be >= 0 and delay_max must be >= delay_min.[/]")
        sys.exit(1)
    
    try:
        # Load targets and credentials
        console.print("[blue]Loading targets...[/]")
        targets_list = load_targets(targets)
        
        console.print("[blue]Loading credentials...[/]")
        credentials_list = load_credentials(usernames, passwords, credentials, domain)
        
        # Create attack profile
        profile = AttackProfile(
            name="CLI Attack",
            description="Attack launched from command line",
            protocol=ProtocolType(protocol),
            rate_limit=rate_limit,
            max_attempts_per_account=max_attempts,
            stop_on_first_success=stop_on_success,
            delay_between_attempts=(delay_min, delay_max)
        )
        
        # Initialize orchestrator
        orchestrator = CredentialOrchestrator(profile)
        asyncio.run(orchestrator.add_targets(targets_list))
        
        # Run the attack
        console.print("[green]Starting attack...[/]")
        asyncio.run(
            run_attack(
                orchestrator=orchestrator,
                credentials=credentials_list,
                output_format=OutputFormat(output_format),
                verbose=verbose,
                output_file=output
            )
        )
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Attack interrupted by user.[/]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/]")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
