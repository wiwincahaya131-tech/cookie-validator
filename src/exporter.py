"""
Result exporters for various output formats.
"""

import json
import logging
from pathlib import Path
from typing import List, Optional
from datetime import datetime

from .models import ValidationResult, NormalizedCookie

logger = logging.getLogger(__name__)


class ResultExporter:
    """Export validation results to various formats."""
    
    def __init__(self, output_dir: Optional[Path] = None):
        """
        Initialize exporter.
        
        Args:
            output_dir: Output directory for results
        """
        self.output_dir = output_dir or Path("cookie_validation_results")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories
        self.valid_dir = self.output_dir / "valid_cookies"
        self.invalid_dir = self.output_dir / "invalid_cookies"
        self.results_dir = self.output_dir / "results"
        
        for d in [self.valid_dir, self.invalid_dir, self.results_dir]:
            d.mkdir(parents=True, exist_ok=True)
    
    def export_json(self, results: List[ValidationResult], filename: Optional[str] = None) -> Path:
        """
        Export results as JSON.
        
        Args:
            results: List of validation results
            filename: Optional custom filename
        
        Returns:
            Path to exported file
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"validation_results_{timestamp}.json"
        
        filepath = self.results_dir / filename
        
        data = {
            "timestamp": datetime.now().isoformat(),
            "total_validations": len(results),
            "valid_count": sum(1 for r in results if r.status.value == "VALID"),
            "results": [r.to_dict() for r in results]
        }
        
        filepath.write_text(json.dumps(data, indent=2))
        logger.info(f"Exported JSON results to {filepath}")
        
        return filepath
    
    def export_txt(self, results: List[ValidationResult], filename: Optional[str] = None) -> Path:
        """
        Export results as human-readable TXT.
        
        Args:
            results: List of validation results
            filename: Optional custom filename
        
        Returns:
            Path to exported file
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"validation_results_{timestamp}.txt"
        
        filepath = self.results_dir / filename
        
        lines = [
            "Cookie Validation Results",
            "=" * 80,
            f"Timestamp: {datetime.now().isoformat()}",
            f"Total Validations: {len(results)}",
            f"Valid: {sum(1 for r in results if r.status.value == 'VALID')}",
            f"Invalid: {sum(1 for r in results if r.status.value == 'INVALID')}",
            f"Expired: {sum(1 for r in results if r.status.value == 'EXPIRED')}",
            f"Challenged: {sum(1 for r in results if r.status.value == 'CHALLENGED')}",
            f"Rate Limited: {sum(1 for r in results if r.status.value == 'RATE_LIMITED')}",
            f"Forbidden: {sum(1 for r in results if r.status.value == 'FORBIDDEN')}",
            "",
            "=" * 80,
            "",
        ]
        
        for result in sorted(results, key=lambda r: r.status.value):
            lines.extend(self._format_result_text(result))
            lines.append("")
        
        filepath.write_text("\n".join(lines))
        logger.info(f"Exported TXT results to {filepath}")
        
        return filepath
    
    def save_valid_cookies(self, result: ValidationResult) -> Optional[Path]:
        """
        Save valid cookies to file.
        
        Args:
            result: Validation result
        
        Returns:
            Path to saved file or None
        """
        if result.status.value != "VALID":
            return None
        
        filename = Path(result.cookie_group.file_path).stem + "_valid.json"
        filepath = self.valid_dir / filename
        
        cookies_data = [
            c.to_dict() for c in result.cookie_group.cookies
        ]
        
        filepath.write_text(json.dumps(cookies_data, indent=2))
        logger.info(f"Saved valid cookies to {filepath}")
        
        return filepath
    
    def save_invalid_cookies(self, result: ValidationResult) -> Optional[Path]:
        """
        Save invalid cookies to file.
        
        Args:
            result: Validation result
        
        Returns:
            Path to saved file or None
        """
        if result.status.value == "VALID":
            return None
        
        filename = Path(result.cookie_group.file_path).stem + "_invalid.json"
        filepath = self.invalid_dir / filename
        
        cookies_data = [
            c.to_dict() for c in result.cookie_group.cookies
        ]
        
        filepath.write_text(json.dumps(cookies_data, indent=2))
        logger.info(f"Saved invalid cookies to {filepath}")
        
        return filepath
    
    @staticmethod
    def _format_result_text(result: ValidationResult) -> List[str]:
        """
        Format result as text lines.
        
        Args:
            result: Validation result
        
        Returns:
            List of formatted text lines
        """
        lines = []
        
        # Status line
        status = result.status.value
        file_name = Path(result.cookie_group.file_path).name
        score_str = f"Score: {result.score}/9" if status == "VALID" else f"Score: {result.score}/9"
        
        lines.append(f"[{status:15}] {file_name:40} ({score_str}, {result.elapsed_time:.2f}s)")
        
        # Details
        if result.validation_error:
            lines.append(f"  └─ Error: {result.validation_error}")
        
        if result.login_redirect_detected:
            lines.append("  └─ Detected: Login redirect")
        
        if result.captcha_detected:
            lines.append("  └─ Detected: CAPTCHA")
        
        if result.rate_limit_detected:
            lines.append("  └─ Detected: Rate limit")
        
        if result.endpoint_used:
            lines.append(f"  └─ Endpoint: {result.endpoint_used}")
        
        # Signals
        if result.signals:
            detected_signals = [s for s in result.signals if s.detected]
            if detected_signals:
                lines.append(f"  └─ Signals: {', '.join(s.name for s in detected_signals[:3])}")
        
        return lines
