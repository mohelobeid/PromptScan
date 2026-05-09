"""HTTP client for making requests to target APIs."""

import asyncio
from typing import Any, Dict, Optional

import httpx
from rich.console import Console

from promptscan.config import ScanConfig

console = Console()


class HTTPClient:
    """HTTP client with authentication and retry support."""

    def __init__(self, config: ScanConfig) -> None:
        """Initialize HTTP client with configuration.
        
        Args:
            config: Scan configuration containing target URL and auth details
        """
        self.config = config
        self.base_url = config.target_url
        self.headers = self._build_headers()
        self.timeout = httpx.Timeout(config.timeout)

    def _build_headers(self) -> Dict[str, str]:
        """Build request headers including authentication."""
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "PromptScan/1.0.0 Security Scanner",
        }
        headers.update(self.config.get_auth_headers())
        return headers

    async def send_payload(
        self, payload: str, context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Send a payload to the target API and return the response.
        
        Args:
            payload: The prompt injection payload to send
            context: Optional context data for the request
            
        Returns:
            Dictionary containing response data and metadata
        """
        request_data = {"message": payload}
        if context:
            request_data.update(context)

        attempt = 0
        last_error = None

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            while attempt < self.config.max_retries:
                try:
                    response = await client.post(
                        self.base_url,
                        json=request_data,
                        headers=self.headers,
                    )

                    return {
                        "status_code": response.status_code,
                        "response_text": response.text,
                        "response_json": self._safe_json_parse(response.text),
                        "headers": dict(response.headers),
                        "elapsed_ms": response.elapsed.total_seconds() * 1000,
                        "success": response.status_code == 200,
                    }

                except httpx.TimeoutException as e:
                    last_error = f"Request timeout: {str(e)}"
                    attempt += 1
                    if self.config.verbose:
                        console.print(f"[yellow]Timeout on attempt {attempt}, retrying...[/yellow]")
                    await asyncio.sleep(1)

                except httpx.RequestError as e:
                    last_error = f"Request error: {str(e)}"
                    attempt += 1
                    if self.config.verbose:
                        console.print(f"[yellow]Error on attempt {attempt}: {str(e)}[/yellow]")
                    await asyncio.sleep(1)

                except Exception as e:
                    last_error = f"Unexpected error: {str(e)}"
                    break

        # All retries failed
        return {
            "status_code": 0,
            "response_text": "",
            "response_json": None,
            "headers": {},
            "elapsed_ms": 0,
            "success": False,
            "error": last_error,
        }

    def _safe_json_parse(self, text: str) -> Optional[Dict[str, Any]]:
        """Safely parse JSON response text.
        
        Args:
            text: Response text to parse
            
        Returns:
            Parsed JSON dict or None if parsing fails
        """
        try:
            import json
            return json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return None

    async def test_connection(self) -> bool:
        """Test if the target API is reachable.
        
        Returns:
            True if connection successful, False otherwise
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    self.base_url,
                    headers=self.headers,
                )
                return response.status_code < 500
        except Exception as e:
            if self.config.verbose:
                console.print(f"[red]Connection test failed: {str(e)}[/red]")
            return False
