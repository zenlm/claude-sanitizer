# 🔐 Claude Sanitizer

**AI-powered intelligent data sanitization** - Uses Claude to detect and redact sensitive information while preserving training value.

## 🌟 Why Claude Sanitizer?

**The Problem**: Regex patterns can miss context-dependent sensitive data and might over-redact, removing valuable training information.

**The Solution**: Use Claude's AI to intelligently understand what's truly sensitive vs. what's important training context.

## ✨ Features

**🧠 Intelligent Detection**:
- Uses Claude (Haiku or Sonnet) to analyze conversations
- Understands context (e.g., "password" in code vs. actual password)
- Detects hidden patterns that regex might miss
- Preserves training value while removing risks

**🎯 Smart Pre-Screening**:
- Only checks entries with sensitive keywords
- Optional aggressive mode checks everything
- Cost-effective with Haiku model
- Detailed reporting of all redactions

**🔒 Comprehensive Protection**:
- API keys and tokens (all major platforms)
- Crypto assets (seed phrases, keys, addresses)
- Financial data (credit cards, SSN)
- Personal information (emails, phones)
- Authentication credentials (passwords, keys)

**💎 Preserves Training Value**:
- Keeps file paths (structure important for context)
- Keeps function/class names (code patterns)
- Keeps error messages (debugging patterns)
- Keeps tool names and commands
- Only redacts truly sensitive data

## 🚀 Quick Start

### Installation

```bash
# Using uvx (no install)
uvx claude-sanitizer my-data.jsonl

# Or install globally
uv tool install claude-sanitizer
claude-sanitizer my-data.jsonl

# Or with pip
pip install claude-sanitizer
claude-sanitizer my-data.jsonl
```

### Set API Key

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

### Basic Usage

```bash
# Smart mode (pre-screened, cost-effective)
claude-sanitizer my-data.jsonl

# Aggressive mode (check everything, more thorough)
claude-sanitizer my-data.jsonl --aggressive

# Use Sonnet for better accuracy (more expensive)
claude-sanitizer my-data.jsonl --model sonnet

# Dry run (see what would be redacted)
claude-sanitizer my-data.jsonl --dry-run --report report.json

# Custom output
claude-sanitizer my-data.jsonl --output clean-data.jsonl
```

## 💡 How It Works

### 1. Pre-Screening (Smart Mode)
```
Scan for keywords:
├─ password, secret, api_key, token
├─ wallet, seed, mnemonic, private_key
├─ credit_card, ssn, bitcoin, ethereum
└─ Only check entries with these keywords
```

### 2. AI Analysis
```
Claude analyzes each flagged entry:
├─ Detects: API keys, passwords, crypto data, PII
├─ Preserves: File paths, function names, errors
├─ Returns: Specific redactions with reasons
└─ Severity: High/Medium/Low
```

### 3. Intelligent Redaction
```
Apply specific placeholders:
├─ API keys → [API_KEY]
├─ Seed phrases → [SEED_PHRASE]
├─ Credit cards → [CREDIT_CARD]
├─ Emails → [EMAIL]
└─ Preserve everything else
```

## 📊 Example Output

```
🔐 Claude Sanitizer v0.1.0
AI-powered intelligent data sanitization

Model: claude-3-5-haiku-20241022
Mode: Smart (pre-screened)

✓ Loaded 10,000 entries

Sanitizing... ━━━━━━━━━━━━━━━━━━━━━━━━━ 100%

┌─────────────────────────────────────────┐
│ Sanitization Results                    │
├─────────────────────┬───────────────────┤
│ Total entries       │ 10,000            │
│ Entries checked     │ 342               │
│ With sensitive data │ 47                │
│ Total redactions    │ 89                │
│ Estimated cost      │ $0.0043           │
└─────────────────────┴───────────────────┘

Sample Redactions:

  ● [API_KEY]: GitHub personal access token detected
  ● [SEED_PHRASE]: BIP39 mnemonic seed phrase (12 words)
  ● [AWS_SECRET]: AWS secret access key

✅ Sanitized data saved: my-data_sanitized.jsonl
✅ Report saved: my-data_report.json

╭────────────────────────────────────────────────╮
│            ✨ Sanitization complete!           │
│                                                │
│ Your data is now safe for contribution while  │
│ preserving maximum training value for agentic │
│ AI development.                                │
╰────────────────────────────────────────────────╯
```

## 💰 Cost Estimates

**Haiku (Default)** - Fast & Affordable:
- $0.25 per 1M input tokens
- ~$0.0043 per 10K entries (342 checked)
- Recommended for most use cases

**Sonnet** - Maximum Accuracy:
- $3 per 1M input tokens  
- ~$0.0516 per 10K entries (342 checked)
- Use for high-sensitivity data

## 🔄 Workflow Integration

### Complete Pipeline

```bash
# 1. Extract with claude-collector
uvx claude-collector --output raw-data.jsonl

# 2. Basic sanitization (fast, regex-based)
# Already done by claude-collector

# 3. AI sanitization (intelligent, context-aware)
uvx claude-sanitizer raw-data.jsonl

# 4. Result: raw-data_sanitized.jsonl
# Ready for contribution!
```

### With Zen Agentic Dataset

```bash
# Extract and sanitize
uvx claude-collector --output my-data.jsonl
uvx claude-sanitizer my-data.jsonl --aggressive

# Add to dataset
cp my-data_sanitized.jsonl ~/zen-agentic-dataset/data/USERNAME/training/

# Commit and PR
cd ~/zen-agentic-dataset
git add data/USERNAME/
git commit -m "Add sanitized agentic data"
git push
```

## 📋 What Gets Redacted

**🔐 API Keys & Tokens**:
- ✅ All major platforms (30+ formats)
- ✅ OAuth tokens, JWT
- ✅ AWS credentials

**💰 Financial & Crypto**:
- ✅ Seed phrases (BIP39 detected)
- ✅ Private keys (hex, PEM)
- ✅ Crypto addresses (ETH, BTC)
- ✅ Credit cards, SSN

**🔑 Authentication**:
- ✅ Passwords in any context
- ✅ Database connection strings
- ✅ Private keys

**👤 Personal Data**:
- ✅ Email addresses
- ✅ Phone numbers
- ✅ Physical addresses

## ✅ What Gets Preserved

**Important for Training**:
- ✅ File paths (structure matters)
- ✅ Function/class names
- ✅ Error messages
- ✅ Tool names (Read, Write, Bash)
- ✅ Programming concepts
- ✅ Generic emails (support@, info@)
- ✅ Repository names

## 🎯 Use Cases

**Perfect For**:
- 🌐 Web3/Crypto project contributors
- 💳 E-commerce/Payment developers
- 🏢 Enterprise application teams
- ☁️ Cloud infrastructure developers
- 🔒 Security-conscious contributors

**Scenarios**:
- Sharing Claude Code sessions from work
- Contributing from crypto/blockchain projects
- Datasets with payment integrations
- Any high-sensitivity development data

## 🔬 Advanced Options

```bash
# Check everything (most thorough)
claude-sanitizer data.jsonl --aggressive --model sonnet

# Dry run with detailed report
claude-sanitizer data.jsonl --dry-run --report analysis.json

# Custom output location
claude-sanitizer data.jsonl --output ~/safe/data.jsonl --report ~/safe/report.json

# Different models
claude-sanitizer data.jsonl --model haiku  # Fast, cheap
claude-sanitizer data.jsonl --model sonnet # Thorough, accurate
```

## 🛡️ Security Guarantees

**Multi-Layer Protection**:
1. **Regex patterns** (claude-collector) - Fast, catches obvious patterns
2. **AI analysis** (claude-sanitizer) - Context-aware, catches hidden patterns
3. **Human review** (optional) - Final check before contribution

**Result**: Maximum safety with preserved training value

## 📊 Report Format

The `--report` flag generates a detailed JSON report:

```json
{
  "stats": {
    "total": 10000,
    "checked": 342,
    "has_sensitive": 47,
    "redactions": 89,
    "cost_estimate": 0.0043
  },
  "redactions": [
    {
      "entry_index": 42,
      "analysis": {
        "has_sensitive_data": true,
        "redactions": [
          {
            "original": "sk-ant-abc123...",
            "replacement": "[ANTHROPIC_API_KEY]",
            "reason": "Anthropic API key detected in configuration",
            "severity": "high"
          }
        ],
        "summary": "Found 1 high-severity credential"
      }
    }
  ],
  "timestamp": "2025-11-14T01:30:00Z"
}
```

## 🤝 Contributing

This tool is part of the Zen Agentic Dataset ecosystem:
- **Dataset**: https://github.com/zenlm/zen-agentic-dataset
- **Collector**: https://github.com/hanzoai/claude-collector
- **Sanitizer**: https://github.com/hanzoai/claude-sanitizer

## 📜 License

MIT License - Free for any purpose

## 🙏 Credits

Built by [Hanzo AI](https://hanzo.ai) for the AI development community.

---

**Safe contribution starts with intelligent sanitization** 🔐✨
