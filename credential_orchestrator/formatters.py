""Formatters for displaying attack results."""
from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn
from rich.panel import Panel
from rich.text import Text
from rich.box import SIMPLE

from .models import AuthResult, AttackStats, ProtocolType, AuthResultStatus


class OutputFormat(str, Enum):
    """Available output formats."""
    TABLE = "table"
    JSON = "json"
    CSV = "csv"
    SIMPLE = "simple"


class ResultFormatter:
    """Base class for formatting attack results."""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
    
    def format_result(self, result: AuthResult) -> str:
        """Format a single authentication result."""
        raise NotImplementedError
    
    def format_stats(self, stats: AttackStats) -> str:
        """Format attack statistics."""
        raise NotImplementedError
    
    def format_summary(self, results: List[AuthResult], stats: AttackStats) -> str:
        """Format a summary of the attack."""
        raise NotImplementedError


class TableFormatter(ResultFormatter):
    """Formats results as rich tables."""
    
    def __init__(self, verbose: bool = False):
        super().__init__(verbose)
        self.console = Console()
    
    def _get_status_style(self, status: AuthResultStatus) -> str:
        """Get the style for a status."""
        styles = {
            AuthResultStatus.SUCCESS: "green",
            AuthResultStatus.FAILURE: "red",
            AuthResultStatus.LOCKED: "yellow",
            AuthResultStatus.RATE_LIMITED: "magenta",
            AuthResultStatus.ERROR: "red",
            AuthResultStatus.SKIPPED: "dim"
        }
        return styles.get(status, "")
    
    def format_result(self, result: AuthResult) -> str:
        """Format a single authentication result as a table."""
        table = Table(show_header=True, header_style="bold magenta", box=SIMPLE)
        table.add_column("Field", style="cyan")
        table.add_column("Value")
        
        # Basic info
        table.add_row("Target", f"{result.target.host}:{result.target.port} ({result.target.protocol})")
        table.add_row("Username", result.credential.username)
        table.add_row("Status", f"[{self._get_status_style(result.status)}]{result.status.upper()}[/]")
        table.add_row("Response Time", f"{result.response_time:.2f}s")
        
        # Add additional info if verbose
        if self.verbose:
            if result.target.domain:
                table.add_row("Domain", result.target.domain)
            if result.credential.domain:
                table.add_row("Credential Domain", result.credential.domain)
            if result.error:
                table.add_row("Error", result.error)
            if result.response_data:
                table.add_row("Response Data", str(result.response_data))
        
        return table
    
    def format_stats(self, stats: AttackStats) -> str:
        """Format attack statistics as a table."""
        table = Table(show_header=False, box=SIMPLE)
        table.add_column("Metric", style="cyan")
        table.add_column("Value")
        
        duration = stats.duration
        hours, remainder = divmod(int(duration), 3600)
        minutes, seconds = divmod(remainder, 60)
        duration_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        
        table.add_row("Duration", duration_str)
        table.add_row("Total Attempts", str(stats.total_attempts))
        table.add_row("Successful", f"{stats.successful_attempts} ({stats.success_rate:.2f}%)")
        table.add_row("Failed", str(stats.failed_attempts))
        table.add_row("Locked Accounts", str(stats.locked_accounts))
        table.add_row("Rate Limited", str(stats.rate_limited))
        table.add_row("Errors", str(stats.errors))
        table.add_row("Avg. Response Time", f"{stats.avg_response_time:.2f}s")
        
        return table
    
    def format_summary(self, results: List[AuthResult], stats: AttackStats) -> str:
        """Format a summary of the attack."""
        # Create a summary panel
        summary = Panel(
            self.format_stats(stats),
            title="[bold]Attack Summary[/]",
            border_style="green"
        )
        
        # Show successful attempts if any
        successful = [r for r in results if r.status == AuthResultStatus.SUCCESS]
        if successful:
            success_table = Table(
                title="Successful Logins",
                show_header=True,
                header_style="bold green",
                box=SIMPLE
            )
            success_table.add_column("Target")
            success_table.add_column("Username")
            success_table.add_column("Password")
            success_table.add_column("Response Time")
            
            for result in successful:
                success_table.add_row(
                    f"{result.target.host}:{result.target.port}",
                    result.credential.username,
                    result.credential.password,
                    f"{result.response_time:.2f}s"
                )
            
            return f"{summary}\n\n{success_table}"
        
        return str(summary)


class JSONFormatter(ResultFormatter):
    """Formats results as JSON."""
    
    def format_result(self, result: AuthResult) -> str:
        """Format a single authentication result as JSON."""
        import json
        
        data = {
            "timestamp": result.timestamp.isoformat(),
            "target": {
                "host": result.target.host,
                "port": result.target.port,
                "protocol": result.target.protocol,
                "domain": result.target.domain
            },
            "credential": {
                "username": result.credential.username,
                "domain": result.credential.domain,
                "password": result.credential.password
            },
            "status": result.status,
            "response_time": result.response_time,
            "error": result.error,
            "response_data": result.response_data
        }
        
        if not self.verbose:
            # Remove verbose fields
            for field in ["error", "response_data"]:
                if not data[field]:
                    del data[field]
        
        return json.dumps(data, indent=2)
    
    def format_stats(self, stats: AttackStats) -> str:
        """Format attack statistics as JSON."""
        import json
        
        data = {
            "start_time": stats.start_time.isoformat(),
            "end_time": stats.end_time.isoformat() if stats.end_time else None,
            "duration_seconds": stats.duration,
            "total_attempts": stats.total_attempts,
            "successful_attempts": stats.successful_attempts,
            "failed_attempts": stats.failed_attempts,
            "locked_accounts": stats.locked_accounts,
            "rate_limited": stats.rate_limited,
            "errors": stats.errors,
            "avg_response_time": stats.avg_response_time,
            "success_rate": stats.success_rate
        }
        
        return json.dumps(data, indent=2)
    
    def format_summary(self, results: List[AuthResult], stats: AttackStats) -> str:
        """Format a summary of the attack as JSON."""
        import json
        
        successful = [
            {
                "target": f"{r.target.host}:{r.target.port}",
                "username": r.credential.username,
                "password": r.credential.password,
                "response_time": r.response_time
            }
            for r in results if r.status == AuthResultStatus.SUCCESS
        ]
        
        summary = {
            "summary": json.loads(self.format_stats(stats)),
            "successful_logins": successful if successful else []
        }
        
        return json.dumps(summary, indent=2)


class SimpleFormatter(ResultFormatter):
    """Formats results as simple text."""
    
    def format_result(self, result: AuthResult) -> str:
        """Format a single authentication result as simple text."""
        status = result.status.upper()
        if result.status == AuthResultStatus.SUCCESS:
            status = f"[SUCCESS] {status}"
        elif result.status == AuthResultStatus.ERROR:
            status = f"[ERROR] {status}"
        
        output = [
            f"Target: {result.target.host}:{result.target.port} ({result.target.protocol})",
            f"Username: {result.credential.username}",
            f"Status: {status}",
            f"Response Time: {result.response_time:.2f}s"
        ]
        
        if self.verbose:
            if result.target.domain:
                output.append(f"Domain: {result.target.domain}")
            if result.credential.domain:
                output.append(f"Credential Domain: {result.credential.domain}")
            if result.error:
                output.append(f"Error: {result.error}")
            if result.response_data:
                output.append(f"Response Data: {result.response_data}")
        
        return "\n".join(output) + "\n" + ("-" * 50)
    
    def format_stats(self, stats: AttackStats) -> str:
        """Format attack statistics as simple text."""
        duration = stats.duration
        hours, remainder = divmod(int(duration), 3600)
        minutes, seconds = divmod(remainder, 60)
        duration_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        
        return f"""
Attack Statistics:
-----------------
Duration: {duration_str}
Total Attempts: {stats.total_attempts}
Successful: {stats.successful_attempts} ({stats.success_rate:.2f}%)
Failed: {stats.failed_attempts}
Locked Accounts: {stats.locked_accounts}
Rate Limited: {stats.rate_limited}
Errors: {stats.errors}
Avg. Response Time: {stats.avg_response_time:.2f}s
"""
    
    def format_summary(self, results: List[AuthResult], stats: AttackStats) -> str:
        """Format a summary of the attack as simple text."""
        output = ["[SUMMARY]", "=========\n"]
        output.append(self.format_stats(stats))
        
        successful = [r for r in results if r.status == AuthResultStatus.SUCCESS]
        if successful:
            output.append("\n[SUCCESSFUL LOGINS]")
            output.append("==================\n")
            
            for i, result in enumerate(successful, 1):
                output.append(
                    f"{i}. {result.credential.username}:{result.credential.password} "
                    f"@{result.target.host}:{result.target.port} "
                    f"(Response: {result.response_time:.2f}s)"
                )
        
        return "\n".join(output)


def get_formatter(fmt: OutputFormat, verbose: bool = False) -> ResultFormatter:
    """Get a formatter for the specified format."""
    formatters = {
        OutputFormat.TABLE: TableFormatter,
        OutputFormat.JSON: JSONFormatter,
        OutputFormat.SIMPLE: SimpleFormatter,
    }
    
    formatter_class = formatters.get(fmt, TableFormatter)
    return formatter_class(verbose=verbose)
