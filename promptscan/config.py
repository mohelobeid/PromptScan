"""Configuration management for PromptScan."""

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional


@dataclass
class ScanConfig:
    """Configuration for a security scan."""

    target_url: str
    api_key: Optional[str] = None
    bearer_token: Optional[str] = None
    timeout: int = 30
    max_retries: int = 3
    payload_dir: Optional[Path] = None
    output_format: str = "console"  # console, json, html
    output_file: Optional[Path] = None
    verbose: bool = False
    custom_headers: Optional[Dict[str, str]] = None

    def __post_init__(self) -> None:
        """Validate configuration after initialization."""
        if not self.target_url:
            raise ValueError("target_url is required")
        
        if self.output_format not in ["console", "json", "html"]:
            raise ValueError(f"Invalid output format: {self.output_format}")
        
        if self.output_format in ["json", "html"] and not self.output_file:
            raise ValueError(f"output_file is required for {self.output_format} format")

    def get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers based on configuration."""
        headers = {}
        
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        
        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        
        if self.custom_headers:
            headers.update(self.custom_headers)
        
        return headers


# Default payload directory
DEFAULT_PAYLOAD_DIR = Path(__file__).parent.parent / "payloads"
