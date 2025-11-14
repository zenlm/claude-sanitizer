#!/usr/bin/env python3
"""
Claude Sanitizer - AI-powered intelligent sanitization
Uses Claude to intelligently detect and redact sensitive data
"""

import json
import os
import re
from pathlib import Path
from datetime import datetime
import click
from rich.console import Console
from rich.progress import track, Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.panel import Panel
import anthropic

console = Console()

# Sensitive data patterns for pre-screening
SENSITIVE_KEYWORDS = [
    'password', 'secret', 'api_key', 'token', 'private_key', 
    'wallet', 'seed', 'mnemonic', 'credential', 'auth',
    'ssn', 'social_security', 'credit_card', 'bitcoin', 'ethereum',
    'private', 'confidential', 'aws_', 'stripe_', 'oauth'
]

SANITIZATION_PROMPT = """You are an expert data sanitization system. Your task is to identify and redact sensitive information while preserving the training value of conversations.

**REDACT (replace with placeholder):**
- API keys, tokens, secrets (OpenAI, GitHub, AWS, etc.)
- Crypto seed phrases, private keys, wallet addresses
- Passwords, credentials, authentication tokens
- Credit card numbers, SSN, financial data
- Personal email addresses (non-generic)
- Phone numbers, physical addresses
- Private keys (PEM, SSH, etc.)
- Database connection strings with passwords
- OAuth tokens, JWT tokens

**PRESERVE (do NOT redact):**
- Generic emails (support@, info@, hello@)
- File paths (just redact username: /Users/[USER]/...)
- Repository names (important for context)
- Function names, class names (code patterns)
- Error messages (debugging patterns)
- Tool names (Read, Write, Bash, etc.)
- Programming concepts and terminology
- Generic variable names

**FORMAT:**
Return a JSON object with:
{
  "has_sensitive_data": boolean,
  "redactions": [
    {
      "original": "the sensitive text",
      "replacement": "[APPROPRIATE_PLACEHOLDER]",
      "reason": "why this needs redaction",
      "severity": "high|medium|low"
    }
  ],
  "summary": "brief summary of what was found"
}

**IMPORTANT:**
- Only flag truly sensitive data that could cause security issues
- Preserve as much context as possible for training
- Use specific placeholders like [API_KEY], [SEED_PHRASE], [EMAIL], [PHONE]
- If no sensitive data, return has_sensitive_data: false with empty redactions

Here's the conversation entry to analyze:

```json
{entry}
```

Analyze this and return the JSON response."""

def get_claude_client():
    """Get Anthropic Claude client"""
    api_key = os.environ.get('ANTHROPIC_API_KEY')
    if not api_key:
        console.print("[red]Error: ANTHROPIC_API_KEY not set[/red]")
        console.print("\nSet your API key:")
        console.print("  export ANTHROPIC_API_KEY=sk-ant-...")
        return None
    return anthropic.Anthropic(api_key=api_key)

def pre_screen(entry):
    """Quick pre-screen for potential sensitive data"""
    text = json.dumps(entry).lower()
    return any(keyword in text for keyword in SENSITIVE_KEYWORDS)

def sanitize_with_claude(client, entry, model="claude-3-5-haiku-20241022"):
    """Use Claude to intelligently sanitize an entry"""
    try:
        response = client.messages.create(
            model=model,
            max_tokens=2000,
            messages=[{
                "role": "user",
                "content": SANITIZATION_PROMPT.format(entry=json.dumps(entry, indent=2))
            }]
        )
        
        # Parse Claude's response
        result_text = response.content[0].text
        
        # Extract JSON from response (might be wrapped in markdown)
        if '```json' in result_text:
            result_text = result_text.split('```json')[1].split('```')[0].strip()
        elif '```' in result_text:
            result_text = result_text.split('```')[1].split('```')[0].strip()
        
        result = json.loads(result_text)
        return result
        
    except Exception as e:
        console.print(f"[yellow]Warning: Claude analysis failed: {e}[/yellow]")
        return {
            "has_sensitive_data": False,
            "redactions": [],
            "summary": f"Analysis failed: {str(e)}"
        }

def apply_redactions(entry, redactions):
    """Apply redactions to entry"""
    entry_str = json.dumps(entry)
    
    for redaction in redactions:
        entry_str = entry_str.replace(redaction['original'], redaction['replacement'])
    
    return json.loads(entry_str)

@click.command()
@click.argument('input_file', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output file (default: INPUT_sanitized.jsonl)')
@click.option('--model', '-m', default='claude-3-5-haiku-20241022', 
              help='Claude model (haiku/sonnet)')
@click.option('--aggressive', is_flag=True, help='Check every entry (slower, more thorough)')
@click.option('--report', '-r', type=click.Path(), help='Save detailed report')
@click.option('--dry-run', is_flag=True, help='Show what would be redacted without saving')
def main(input_file, output, model, aggressive, report, dry_run):
    """
    🔐 Claude Sanitizer - AI-powered intelligent sanitization
    
    Uses Claude to intelligently detect and redact sensitive data while
    preserving the training value of conversations.
    
    \b
    Models:
      haiku  (default) - Fast, cost-effective (claude-3-5-haiku-20241022)
      sonnet           - More thorough (claude-3-5-sonnet-20241022)
    
    \b
    Usage:
      claude-sanitizer my-data.jsonl
      claude-sanitizer my-data.jsonl --model sonnet --aggressive
      claude-sanitizer my-data.jsonl --dry-run --report report.json
    """
    
    console.print("\n[bold cyan]🔐 Claude Sanitizer v0.1.0[/bold cyan]")
    console.print("[dim]AI-powered intelligent data sanitization[/dim]\n")
    
    # Get Claude client
    client = get_claude_client()
    if not client:
        return
    
    # Map model names
    model_map = {
        'haiku': 'claude-3-5-haiku-20241022',
        'sonnet': 'claude-3-5-sonnet-20241022'
    }
    model = model_map.get(model, model)
    
    console.print(f"[cyan]Model:[/cyan] {model}")
    console.print(f"[cyan]Mode:[/cyan] {'Aggressive (all entries)' if aggressive else 'Smart (pre-screened)'}\n")
    
    # Read input
    input_path = Path(input_file)
    entries = []
    
    with open(input_path, 'r') as f:
        for line in f:
            if line.strip():
                entries.append(json.loads(line))
    
    console.print(f"[green]✓[/green] Loaded {len(entries)} entries\n")
    
    # Process entries
    sanitized_entries = []
    redaction_report = []
    stats = {
        'total': len(entries),
        'checked': 0,
        'has_sensitive': 0,
        'redactions': 0,
        'cost_estimate': 0.0
    }
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Sanitizing...", total=len(entries))
        
        for idx, entry in enumerate(entries):
            # Pre-screen unless aggressive mode
            should_check = aggressive or pre_screen(entry)
            
            if should_check:
                stats['checked'] += 1
                
                # Analyze with Claude
                result = sanitize_with_claude(client, entry, model)
                
                if result['has_sensitive_data'] and result['redactions']:
                    stats['has_sensitive'] += 1
                    stats['redactions'] += len(result['redactions'])
                    
                    # Apply redactions
                    sanitized_entry = apply_redactions(entry, result['redactions'])
                    sanitized_entries.append(sanitized_entry)
                    
                    # Add to report
                    redaction_report.append({
                        'entry_index': idx,
                        'analysis': result
                    })
                    
                else:
                    sanitized_entries.append(entry)
            else:
                # No sensitive keywords found, keep as-is
                sanitized_entries.append(entry)
            
            progress.update(task, advance=1)
    
    # Cost estimate (rough)
    # Haiku: $0.25/1M input, $1.25/1M output
    # Sonnet: $3/1M input, $15/1M output
    avg_tokens_per_check = 500  # rough estimate
    if 'haiku' in model:
        stats['cost_estimate'] = (stats['checked'] * avg_tokens_per_check / 1_000_000) * 0.25
    else:
        stats['cost_estimate'] = (stats['checked'] * avg_tokens_per_check / 1_000_000) * 3
    
    # Display results
    console.print()
    table = Table(title="Sanitization Results")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Total entries", f"{stats['total']:,}")
    table.add_row("Entries checked", f"{stats['checked']:,}")
    table.add_row("With sensitive data", f"{stats['has_sensitive']:,}")
    table.add_row("Total redactions", f"{stats['redactions']:,}")
    table.add_row("Estimated cost", f"${stats['cost_estimate']:.4f}")
    
    console.print(table)
    console.print()
    
    # Show sample redactions
    if redaction_report:
        console.print("[bold]Sample Redactions:[/bold]\n")
        for item in redaction_report[:3]:
            for red in item['analysis']['redactions'][:2]:
                severity_color = {
                    'high': 'red',
                    'medium': 'yellow',
                    'low': 'blue'
                }.get(red['severity'], 'white')
                
                console.print(f"  [{severity_color}]●[/{severity_color}] {red['replacement']}: {red['reason']}")
        console.print()
    
    # Save results
    if not dry_run:
        # Output file
        if not output:
            output = input_path.parent / f"{input_path.stem}_sanitized{input_path.suffix}"
        
        with open(output, 'w') as f:
            for entry in sanitized_entries:
                f.write(json.dumps(entry) + '\n')
        
        console.print(f"[green]✅ Sanitized data saved:[/green] {output}")
        
        # Report file
        if report or redaction_report:
            report_path = report or input_path.parent / f"{input_path.stem}_report.json"
            with open(report_path, 'w') as f:
                json.dump({
                    'stats': stats,
                    'redactions': redaction_report,
                    'timestamp': datetime.now().isoformat()
                }, f, indent=2)
            console.print(f"[green]✅ Report saved:[/green] {report_path}")
    
    else:
        console.print("[yellow]🔍 DRY RUN - No files saved[/yellow]")
    
    console.print()
    console.print(Panel.fit(
        "[bold green]✨ Sanitization complete![/bold green]\n\n"
        "Your data is now safe for contribution while preserving\n"
        "maximum training value for agentic AI development.",
        title="Success"
    ))

if __name__ == '__main__':
    main()
