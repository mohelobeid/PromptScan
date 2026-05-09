"""Report generation for scan results."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from jinja2 import Template
from rich.console import Console
from rich.table import Table

from promptscan.analyzer import VulnerabilityMatch
from promptscan.scorer import RiskScorer

console = Console()


class ReportGenerator:
    """Generate reports in various formats."""

    def __init__(self) -> None:
        """Initialize the report generator."""
        self.scorer = RiskScorer()

    def generate_console_report(
        self,
        vulnerabilities: List[VulnerabilityMatch],
        metadata: Dict[str, Any],
        target_url: str,
    ) -> None:
        """Generate and print a console report.
        
        Args:
            vulnerabilities: List of detected vulnerabilities
            metadata: Scan metadata
            target_url: Target URL that was scanned
        """
        # Calculate risk score
        risk_score = self.scorer.calculate_risk_score(
            vulnerabilities, metadata.get("total_payloads", 1)
        )
        severity = self.scorer.get_severity_level(risk_score)

        # Print header
        console.print("\n" + "=" * 70)
        console.print("[bold cyan]PROMPTSCAN SECURITY ASSESSMENT REPORT[/bold cyan]")
        console.print("=" * 70 + "\n")

        # Print summary
        console.print(f"[bold]Target:[/bold] {target_url}")
        console.print(f"[bold]Scan Date:[/bold] {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        console.print(f"[bold]Total Payloads Tested:[/bold] {metadata.get('total_payloads', 0)}")
        console.print(f"[bold]Vulnerabilities Found:[/bold] {len(vulnerabilities)}\n")

        # Print risk score
        risk_color = self._get_severity_color(severity)
        console.print(f"[bold]Risk Score:[/bold] [{risk_color}]{risk_score:.1f}/10.0[/{risk_color}]")
        console.print(f"[bold]Severity Level:[/bold] [{risk_color}]{severity}[/{risk_color}]\n")

        if vulnerabilities:
            # Create vulnerabilities table
            table = Table(title="Detected Vulnerabilities", show_header=True, header_style="bold magenta")
            table.add_column("Type", style="cyan", width=25)
            table.add_column("Severity", width=10)
            table.add_column("Confidence", width=10)
            table.add_column("Evidence", width=30)

            for vuln in vulnerabilities:
                severity_color = self._get_severity_color(vuln.severity)
                table.add_row(
                    vuln.vulnerability_type,
                    f"[{severity_color}]{vuln.severity}[/{severity_color}]",
                    f"{vuln.confidence:.0%}",
                    vuln.evidence[:50] + "..." if len(vuln.evidence) > 50 else vuln.evidence,
                )

            console.print(table)
            console.print()

        # Print recommendation
        recommendation = self.scorer.get_recommendation(risk_score)
        console.print("[bold yellow]Recommendation:[/bold yellow]")
        console.print(f"[white]{recommendation}[/white]\n")

        console.print("=" * 70 + "\n")

    def generate_json_report(
        self,
        vulnerabilities: List[VulnerabilityMatch],
        metadata: Dict[str, Any],
        target_url: str,
        output_file: Path,
    ) -> None:
        """Generate a JSON report.
        
        Args:
            vulnerabilities: List of detected vulnerabilities
            metadata: Scan metadata
            target_url: Target URL that was scanned
            output_file: Path to output file
        """
        risk_score = self.scorer.calculate_risk_score(
            vulnerabilities, metadata.get("total_payloads", 1)
        )
        severity = self.scorer.get_severity_level(risk_score)
        category_scores = self.scorer.calculate_category_scores(vulnerabilities)

        report = {
            "scan_metadata": {
                "target": target_url,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "total_payloads": metadata.get("total_payloads", 0),
                "categories_tested": metadata.get("categories_tested", 0),
                "duration_seconds": metadata.get("duration_seconds", 0),
            },
            "risk_assessment": {
                "risk_score": round(risk_score, 2),
                "severity": severity,
                "recommendation": self.scorer.get_recommendation(risk_score),
            },
            "category_scores": {k: round(v, 2) for k, v in category_scores.items()},
            "vulnerabilities": [
                {
                    "type": vuln.vulnerability_type,
                    "severity": vuln.severity,
                    "confidence": round(vuln.confidence, 2),
                    "payload": vuln.payload_used,
                    "evidence": vuln.evidence,
                    "response_excerpt": vuln.response_excerpt,
                }
                for vuln in vulnerabilities
            ],
            "summary": {
                "total_vulnerabilities": len(vulnerabilities),
                "critical": sum(1 for v in vulnerabilities if v.severity == "CRITICAL"),
                "high": sum(1 for v in vulnerabilities if v.severity == "HIGH"),
                "medium": sum(1 for v in vulnerabilities if v.severity == "MEDIUM"),
                "low": sum(1 for v in vulnerabilities if v.severity == "LOW"),
            },
        }

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        console.print(f"[green]✓ JSON report saved to: {output_file}[/green]")

    def generate_html_report(
        self,
        vulnerabilities: List[VulnerabilityMatch],
        metadata: Dict[str, Any],
        target_url: str,
        output_file: Path,
    ) -> None:
        """Generate an HTML report.
        
        Args:
            vulnerabilities: List of detected vulnerabilities
            metadata: Scan metadata
            target_url: Target URL that was scanned
            output_file: Path to output file
        """
        risk_score = self.scorer.calculate_risk_score(
            vulnerabilities, metadata.get("total_payloads", 1)
        )
        severity = self.scorer.get_severity_level(risk_score)
        category_scores = self.scorer.calculate_category_scores(vulnerabilities)

        # HTML template
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PromptScan Security Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; margin-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; margin-bottom: 15px; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
        .header { text-align: center; margin-bottom: 40px; }
        .metadata { background: #ecf0f1; padding: 20px; border-radius: 5px; margin-bottom: 30px; }
        .metadata-item { margin: 10px 0; }
        .metadata-label { font-weight: bold; color: #2c3e50; }
        .risk-score { text-align: center; padding: 30px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border-radius: 8px; margin: 30px 0; }
        .risk-score-value { font-size: 48px; font-weight: bold; margin: 10px 0; }
        .severity { display: inline-block; padding: 5px 15px; border-radius: 20px; font-weight: bold; color: white; }
        .severity-CRITICAL { background: #e74c3c; }
        .severity-HIGH { background: #e67e22; }
        .severity-MEDIUM { background: #f39c12; }
        .severity-LOW { background: #3498db; }
        .severity-MINIMAL { background: #27ae60; }
        .vuln-table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        .vuln-table th { background: #34495e; color: white; padding: 12px; text-align: left; }
        .vuln-table td { padding: 12px; border-bottom: 1px solid #ecf0f1; }
        .vuln-table tr:hover { background: #f8f9fa; }
        .recommendation { background: #fff3cd; border-left: 4px solid #ffc107; padding: 20px; margin: 20px 0; border-radius: 4px; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .summary-card { background: #f8f9fa; padding: 20px; border-radius: 5px; text-align: center; }
        .summary-card-value { font-size: 32px; font-weight: bold; color: #3498db; }
        .summary-card-label { color: #7f8c8d; margin-top: 10px; }
        .footer { text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #ecf0f1; color: #7f8c8d; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 PromptScan Security Assessment Report</h1>
            <p style="color: #7f8c8d; margin-top: 10px;">Prompt Injection Vulnerability Analysis</p>
        </div>

        <div class="metadata">
            <div class="metadata-item"><span class="metadata-label">Target:</span> {{ target_url }}</div>
            <div class="metadata-item"><span class="metadata-label">Scan Date:</span> {{ scan_date }}</div>
            <div class="metadata-item"><span class="metadata-label">Total Payloads Tested:</span> {{ total_payloads }}</div>
            <div class="metadata-item"><span class="metadata-label">Categories Tested:</span> {{ categories_tested }}</div>
        </div>

        <div class="risk-score">
            <div>Overall Risk Score</div>
            <div class="risk-score-value">{{ risk_score }}/10.0</div>
            <div><span class="severity severity-{{ severity }}">{{ severity }}</span></div>
        </div>

        <h2>📊 Summary</h2>
        <div class="summary-grid">
            <div class="summary-card">
                <div class="summary-card-value">{{ total_vulnerabilities }}</div>
                <div class="summary-card-label">Total Vulnerabilities</div>
            </div>
            <div class="summary-card">
                <div class="summary-card-value" style="color: #e74c3c;">{{ critical_count }}</div>
                <div class="summary-card-label">Critical</div>
            </div>
            <div class="summary-card">
                <div class="summary-card-value" style="color: #e67e22;">{{ high_count }}</div>
                <div class="summary-card-label">High</div>
            </div>
            <div class="summary-card">
                <div class="summary-card-value" style="color: #f39c12;">{{ medium_count }}</div>
                <div class="summary-card-label">Medium</div>
            </div>
            <div class="summary-card">
                <div class="summary-card-value" style="color: #3498db;">{{ low_count }}</div>
                <div class="summary-card-label">Low</div>
            </div>
        </div>

        {% if vulnerabilities %}
        <h2>🚨 Detected Vulnerabilities</h2>
        <table class="vuln-table">
            <thead>
                <tr>
                    <th>Type</th>
                    <th>Severity</th>
                    <th>Confidence</th>
                    <th>Evidence</th>
                </tr>
            </thead>
            <tbody>
                {% for vuln in vulnerabilities %}
                <tr>
                    <td><strong>{{ vuln.vulnerability_type }}</strong></td>
                    <td><span class="severity severity-{{ vuln.severity }}">{{ vuln.severity }}</span></td>
                    <td>{{ (vuln.confidence * 100)|int }}%</td>
                    <td>{{ vuln.evidence[:100] }}{% if vuln.evidence|length > 100 %}...{% endif %}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% else %}
        <p style="text-align: center; color: #27ae60; padding: 20px;">✓ No vulnerabilities detected</p>
        {% endif %}

        <h2>💡 Recommendation</h2>
        <div class="recommendation">
            <p>{{ recommendation }}</p>
        </div>

        <div class="footer">
            <p>Generated by <strong>PromptScan v1.0.0</strong></p>
            <p style="margin-top: 5px;">Professional LLM Security Assessment Tool</p>
        </div>
    </div>
</body>
</html>
        """

        template = Template(html_template)
        html_content = template.render(
            target_url=target_url,
            scan_date=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            total_payloads=metadata.get("total_payloads", 0),
            categories_tested=metadata.get("categories_tested", 0),
            risk_score=f"{risk_score:.1f}",
            severity=severity,
            total_vulnerabilities=len(vulnerabilities),
            critical_count=sum(1 for v in vulnerabilities if v.severity == "CRITICAL"),
            high_count=sum(1 for v in vulnerabilities if v.severity == "HIGH"),
            medium_count=sum(1 for v in vulnerabilities if v.severity == "MEDIUM"),
            low_count=sum(1 for v in vulnerabilities if v.severity == "LOW"),
            vulnerabilities=vulnerabilities,
            recommendation=self.scorer.get_recommendation(risk_score),
        )

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html_content)

        console.print(f"[green]✓ HTML report saved to: {output_file}[/green]")

    def _get_severity_color(self, severity: str) -> str:
        """Get color code for severity level.
        
        Args:
            severity: Severity level string
            
        Returns:
            Rich color code
        """
        colors = {
            "CRITICAL": "red bold",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "blue",
            "MINIMAL": "green",
        }
        return colors.get(severity, "white")
