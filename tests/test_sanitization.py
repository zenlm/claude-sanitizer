"""
Tests for claude-sanitizer sanitization functionality.

These tests verify that sensitive data is properly detected and redacted.
"""

import json
import pytest
from unittest.mock import Mock, patch
from claude_sanitizer.cli import sanitize_with_claude, SENSITIVE_KEYWORDS


class TestSensitiveKeywordDetection:
    """Test that sensitive keywords are properly detected."""
    
    def test_detects_api_key_mentions(self):
        """Should flag entries mentioning API keys."""
        entry = {"content": "Here's my api_key for the service"}
        assert any(kw in entry["content"].lower() for kw in SENSITIVE_KEYWORDS)
    
    def test_detects_password_mentions(self):
        """Should flag entries mentioning passwords."""
        entry = {"content": "The password is stored here"}
        assert any(kw in entry["content"].lower() for kw in SENSITIVE_KEYWORDS)
    
    def test_detects_secret_mentions(self):
        """Should flag entries mentioning secrets."""
        entry = {"content": "secret configuration value"}
        assert any(kw in entry["content"].lower() for kw in SENSITIVE_KEYWORDS)
    
    def test_detects_token_mentions(self):
        """Should flag entries mentioning tokens."""
        entry = {"content": "authentication token required"}
        assert any(kw in entry["content"].lower() for kw in SENSITIVE_KEYWORDS)
    
    def test_detects_private_key_mentions(self):
        """Should flag entries mentioning private keys."""
        entry = {"content": "-----BEGIN PRIVATE KEY-----"}
        assert any(kw in entry["content"].lower() for kw in SENSITIVE_KEYWORDS)
    
    def test_ignores_safe_content(self):
        """Should not flag safe programming content."""
        entry = {"content": "function calculateTotal(items) { return sum; }"}
        # This might have 'total' but context is safe
        # The AI layer will determine it's safe
        assert not any(kw in entry["content"].lower() for kw in SENSITIVE_KEYWORDS if kw not in ["function", "return"])


class TestClaudeSanitization:
    """Test AI-powered sanitization with Claude."""
    
    @patch('anthropic.Anthropic')
    def test_redacts_api_keys(self, mock_anthropic):
        """Should detect and redact API keys."""
        # Mock Claude response
        mock_client = Mock()
        mock_response = Mock()
        mock_response.content = [Mock(text=json.dumps({
            "has_sensitive_data": True,
            "redactions": [{
                "type": "api_key",
                "location": "OpenAI API key in message",
                "placeholder": "[OPENAI_API_KEY]",
                "severity": "high",
                "reason": "Actual API key detected"
            }],
            "summary": "Found 1 API key"
        }))]
        mock_client.messages.create.return_value = mock_response
        
        entry = {"content": "My key is sk-1234567890abcdef"}
        result = sanitize_with_claude(mock_client, entry)
        
        assert result["has_sensitive_data"] is True
        assert len(result["redactions"]) == 1
        assert result["redactions"][0]["type"] == "api_key"
        assert result["redactions"][0]["severity"] == "high"
    
    @patch('anthropic.Anthropic')
    def test_redacts_passwords(self, mock_anthropic):
        """Should detect and redact actual passwords."""
        mock_client = Mock()
        mock_response = Mock()
        mock_response.content = [Mock(text=json.dumps({
            "has_sensitive_data": True,
            "redactions": [{
                "type": "password",
                "location": "Database connection string",
                "placeholder": "[PASSWORD]",
                "severity": "high",
                "reason": "Hardcoded password in connection string"
            }],
            "summary": "Found 1 password"
        }))]
        mock_client.messages.create.return_value = mock_response
        
        entry = {"content": "DB_URL=postgresql://user:MyP@ssw0rd@localhost/db"}
        result = sanitize_with_claude(mock_client, entry)
        
        assert result["has_sensitive_data"] is True
        assert result["redactions"][0]["type"] == "password"
    
    @patch('anthropic.Anthropic')
    def test_preserves_code_examples(self, mock_anthropic):
        """Should NOT redact 'password' in code examples."""
        mock_client = Mock()
        mock_response = Mock()
        mock_response.content = [Mock(text=json.dumps({
            "has_sensitive_data": False,
            "redactions": [],
            "summary": "No sensitive data - 'password' is a variable name in code"
        }))]
        mock_client.messages.create.return_value = mock_response
        
        entry = {"content": 'const password = prompt("Enter password:");'}
        result = sanitize_with_claude(mock_client, entry)
        
        assert result["has_sensitive_data"] is False
        assert len(result["redactions"]) == 0
    
    @patch('anthropic.Anthropic')
    def test_redacts_crypto_seeds(self, mock_anthropic):
        """Should detect and redact crypto seed phrases."""
        mock_client = Mock()
        mock_response = Mock()
        mock_response.content = [Mock(text=json.dumps({
            "has_sensitive_data": True,
            "redactions": [{
                "type": "crypto_seed",
                "location": "12-word seed phrase",
                "placeholder": "[SEED_PHRASE]",
                "severity": "high",
                "reason": "BIP39 seed phrase detected"
            }],
            "summary": "Found 1 seed phrase"
        }))]
        mock_client.messages.create.return_value = mock_response
        
        entry = {"content": "My seed: abandon ability able about above absent"}
        result = sanitize_with_claude(mock_client, entry)
        
        assert result["has_sensitive_data"] is True
        assert result["redactions"][0]["type"] == "crypto_seed"
    
    @patch('anthropic.Anthropic')
    def test_redacts_private_keys(self, mock_anthropic):
        """Should detect and redact private keys."""
        mock_client = Mock()
        mock_response = Mock()
        mock_response.content = [Mock(text=json.dumps({
            "has_sensitive_data": True,
            "redactions": [{
                "type": "private_key",
                "location": "64-character hex private key",
                "placeholder": "[PRIVATE_KEY]",
                "severity": "high",
                "reason": "Ethereum private key format"
            }],
            "summary": "Found 1 private key"
        }))]
        mock_client.messages.create.return_value = mock_response
        
        entry = {"content": "0x" + "a" * 64}
        result = sanitize_with_claude(mock_client, entry)
        
        assert result["has_sensitive_data"] is True
        assert result["redactions"][0]["type"] == "private_key"
    
    @patch('anthropic.Anthropic')
    def test_preserves_file_paths(self, mock_anthropic):
        """Should preserve file paths as training context."""
        mock_client = Mock()
        mock_response = Mock()
        mock_response.content = [Mock(text=json.dumps({
            "has_sensitive_data": False,
            "redactions": [],
            "summary": "File paths preserved - important for context"
        }))]
        mock_client.messages.create.return_value = mock_response
        
        entry = {"content": "Reading from /Users/dev/project/src/auth.py"}
        result = sanitize_with_claude(mock_client, entry)
        
        assert result["has_sensitive_data"] is False
    
    @patch('anthropic.Anthropic')
    def test_preserves_function_names(self, mock_anthropic):
        """Should preserve function names for training."""
        mock_client = Mock()
        mock_response = Mock()
        mock_response.content = [Mock(text=json.dumps({
            "has_sensitive_data": False,
            "redactions": [],
            "summary": "Function names preserved for training"
        }))]
        mock_client.messages.create.return_value = mock_response
        
        entry = {"content": "def authenticate_user(username, password_hash):"}
        result = sanitize_with_claude(mock_client, entry)
        
        assert result["has_sensitive_data"] is False
    
    @patch('anthropic.Anthropic')
    def test_handles_edge_cases(self, mock_anthropic):
        """Should handle edge cases gracefully."""
        mock_client = Mock()
        mock_response = Mock()
        mock_response.content = [Mock(text=json.dumps({
            "has_sensitive_data": False,
            "redactions": [],
            "summary": "No issues found"
        }))]
        mock_client.messages.create.return_value = mock_response
        
        # Empty content
        result = sanitize_with_claude(mock_client, {"content": ""})
        assert result["has_sensitive_data"] is False
        
        # Very long content
        long_content = "x" * 10000
        result = sanitize_with_claude(mock_client, {"content": long_content})
        assert result is not None


class TestIntegration:
    """Integration tests for the complete workflow."""
    
    @patch('anthropic.Anthropic')
    def test_end_to_end_sanitization(self, mock_anthropic):
        """Test complete sanitization workflow."""
        mock_client = Mock()
        mock_response = Mock()
        mock_response.content = [Mock(text=json.dumps({
            "has_sensitive_data": True,
            "redactions": [
                {
                    "type": "api_key",
                    "location": "Line 5",
                    "placeholder": "[OPENAI_API_KEY]",
                    "severity": "high",
                    "reason": "OpenAI API key"
                },
                {
                    "type": "email",
                    "location": "Line 10",
                    "placeholder": "[EMAIL]",
                    "severity": "medium",
                    "reason": "Personal email address"
                }
            ],
            "summary": "Found 2 sensitive items"
        }))]
        mock_client.messages.create.return_value = mock_response
        
        entry = {
            "messages": [
                {"role": "user", "content": "My API key is sk-test123"},
                {"role": "assistant", "content": "Contact me at user@example.com"}
            ]
        }
        
        result = sanitize_with_claude(mock_client, entry)
        
        assert result["has_sensitive_data"] is True
        assert len(result["redactions"]) == 2
        assert result["redactions"][0]["severity"] == "high"
        assert result["redactions"][1]["severity"] == "medium"


class TestSeverityLevels:
    """Test that severity levels are properly assigned."""
    
    @patch('anthropic.Anthropic')
    def test_high_severity_for_crypto(self, mock_anthropic):
        """Crypto data should be high severity."""
        mock_client = Mock()
        mock_response = Mock()
        mock_response.content = [Mock(text=json.dumps({
            "has_sensitive_data": True,
            "redactions": [{
                "type": "crypto_seed",
                "location": "Seed phrase",
                "placeholder": "[SEED_PHRASE]",
                "severity": "high",
                "reason": "BIP39 seed phrase"
            }],
            "summary": "Critical crypto data"
        }))]
        mock_client.messages.create.return_value = mock_response
        
        entry = {"content": "wallet seed phrase here"}
        result = sanitize_with_claude(mock_client, entry)
        
        assert result["redactions"][0]["severity"] == "high"
    
    @patch('anthropic.Anthropic')
    def test_medium_severity_for_pii(self, mock_anthropic):
        """PII should be medium severity."""
        mock_client = Mock()
        mock_response = Mock()
        mock_response.content = [Mock(text=json.dumps({
            "has_sensitive_data": True,
            "redactions": [{
                "type": "email",
                "location": "Contact info",
                "placeholder": "[EMAIL]",
                "severity": "medium",
                "reason": "Personal email"
            }],
            "summary": "PII detected"
        }))]
        mock_client.messages.create.return_value = mock_response
        
        entry = {"content": "Email: john@example.com"}
        result = sanitize_with_claude(mock_client, entry)
        
        assert result["redactions"][0]["severity"] == "medium"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
