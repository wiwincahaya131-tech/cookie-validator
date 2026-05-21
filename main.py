"""
Main entry point for Cookie Validator.
DigitalOcean cookie validation tool with GUI folder selection.
"""

import asyncio
import logging
import sys
from pathlib import Path
from typing import List

try:
    import tkinter as tk
    from tkinter.filedialog import askdirectory
    HAS_TK = True
except ImportError:
    HAS_TK = False

from src import (
    CookieParser,
    CookieValidator,
    ResultExporter,
    setup_logging,
)
from src.models import ValidationStatus

logger = logging.getLogger(__name__)


class CookieValidatorApp:
    """Main application class."""
    
    def __init__(self):
        """Initialize application."""
        self.parser = CookieParser()
        self.validator = CookieValidator(max_concurrency=3)
        self.exporter = ResultExporter()
    
    def select_folder(self) -> Path:
        """
        Show folder selection dialog.
        
        Returns:
            Selected folder path
        """
        if not HAS_TK:
            print("Error: tkinter not available. Please install python3-tk")
            folder = input("Enter folder path manually: ").strip()
            return Path(folder)
        
        root = tk.Tk()
        root.withdraw()
        root.attributes('-topmost', True)
        
        folder = askdirectory(title="Select folder with cookie files")
        root.destroy()
        
        if not folder:
            raise ValueError("No folder selected")
        
        return Path(folder)
    
    def find_cookie_files(self, folder: Path) -> List[Path]:
        """
        Find all cookie files in folder (recursive).
        
        Args:
            folder: Root folder to search
        
        Returns:
            List of cookie file paths
        """
        cookie_files = []
        
        # Find .txt files
        cookie_files.extend(folder.rglob("*.txt"))
        
        # Find .json files
        cookie_files.extend(folder.rglob("*.json"))
        
        # Remove duplicates
        cookie_files = list(set(cookie_files))
        
        logger.info(f"Found {len(cookie_files)} cookie files in {folder}")
        
        return sorted(cookie_files)
    
    async def validate_all(self, cookie_files: List[Path]):
        """
        Validate all cookie files.
        
        Args:
            cookie_files: List of cookie file paths
        """
        results = []
        
        print(f"\n{'='*80}")
        print(f"Cookie Validator - Validating {len(cookie_files)} files")
        print(f"{'='*80}\n")
        
        # Parse all files
        cookie_groups = []
        for cookie_file in cookie_files:
            logger.info(f"Parsing {cookie_file.name}...")
            group = self.parser.parse_file(cookie_file)
            if group.cookies:
                cookie_groups.append(group)
            else:
                logger.warning(f"No cookies found in {cookie_file.name}")
        
        logger.info(f"Parsed {len(cookie_groups)} cookie groups")
        print(f"\nValidating {len(cookie_groups)} cookie groups...\n")
        
        # Validate concurrently
        tasks = [self.validator.validate_group(group) for group in cookie_groups]
        results = await asyncio.gather(*tasks)
        
        # Print results
        self._print_results(results)
        
        # Export results
        self._export_results(results)
    
    def _print_results(self, results):
        """
        Print validation results.
        
        Args:
            results: List of validation results
        """
        print(f"\n{'='*80}")
        print("Validation Results")
        print(f"{'='*80}\n")
        
        # Sort by status
        status_order = {
            ValidationStatus.VALID: 0,
            ValidationStatus.PARTIAL_AUTH: 1,
            ValidationStatus.EXPIRED: 2,
            ValidationStatus.CHALLENGED: 3,
            ValidationStatus.RATE_LIMITED: 4,
            ValidationStatus.FORBIDDEN: 5,
            ValidationStatus.INVALID: 6,
            ValidationStatus.NETWORK_ERROR: 7,
        }
        
        sorted_results = sorted(results, key=lambda r: status_order.get(r.status, 99))
        
        for result in sorted_results:
            self._print_result(result)
        
        # Summary
        print(f"\n{'='*80}")
        print("Summary")
        print(f"{'='*80}")
        print(f"Total: {len(results)}")
        print(f"Valid: {sum(1 for r in results if r.status == ValidationStatus.VALID)} ✓")
        print(f"Partial Auth: {sum(1 for r in results if r.status == ValidationStatus.PARTIAL_AUTH)} ⚠")
        print(f"Invalid: {sum(1 for r in results if r.status == ValidationStatus.INVALID)} ✗")
        print(f"Expired: {sum(1 for r in results if r.status == ValidationStatus.EXPIRED)} ⏰")
        print(f"Challenged: {sum(1 for r in results if r.status == ValidationStatus.CHALLENGED)} 🔒")
        print(f"Rate Limited: {sum(1 for r in results if r.status == ValidationStatus.RATE_LIMITED)} 🚫")
        print(f"Forbidden: {sum(1 for r in results if r.status == ValidationStatus.FORBIDDEN)} 🔐")
        print(f"Network Error: {sum(1 for r in results if r.status == ValidationStatus.NETWORK_ERROR)} ❌")
        print()
    
    def _print_result(self, result):
        """
        Print single result with color.
        
        Args:
            result: Validation result
        """
        # Color codes
        colors = {
            ValidationStatus.VALID: '\033[32m',         # Green
            ValidationStatus.INVALID: '\033[31m',        # Red
            ValidationStatus.EXPIRED: '\033[33m',        # Yellow
            ValidationStatus.CHALLENGED: '\033[35m',     # Magenta
            ValidationStatus.PARTIAL_AUTH: '\033[36m',   # Cyan
            ValidationStatus.FORBIDDEN: '\033[31m',      # Red
            ValidationStatus.RATE_LIMITED: '\033[31m',   # Red
            ValidationStatus.NETWORK_ERROR: '\033[31m',  # Red
        }
        
        reset = '\033[0m'
        
        status = result.status
        color = colors.get(status, reset)
        file_name = Path(result.cookie_group.file_path).name
        
        print(f"{color}[{status.value:15}]{reset} {file_name:45} (Score: {result.score}/9, Time: {result.elapsed_time:.2f}s)")
        
        # Details
        if result.validation_error:
            print(f"  └─ Error: {result.validation_error}")
        
        if result.login_redirect_detected:
            print(f"  └─ Detected: Login redirect")
        
        if result.captcha_detected:
            print(f"  └─ Detected: CAPTCHA")
        
        if result.rate_limit_detected:
            print(f"  └─ Detected: Rate limit")
        
        if result.endpoint_used:
            print(f"  └─ Endpoint: {result.endpoint_used}")
        
        # Auth cookies
        auth_cookies = result.cookie_group.get_auth_cookies()
        if auth_cookies:
            print(f"  └─ Auth cookies: {', '.join(c.name for c in auth_cookies[:3])}")
    
    def _export_results(self, results):
        """
        Export validation results.
        
        Args:
            results: List of validation results
        """
        print(f"\nExporting results...\n")
        
        # Export JSON
        json_file = self.exporter.export_json(results)
        print(f"✓ JSON exported to: {json_file}")
        
        # Export TXT
        txt_file = self.exporter.export_txt(results)
        print(f"✓ TXT exported to: {txt_file}")
        
        # Save valid/invalid cookies
        valid_count = 0
        invalid_count = 0
        
        for result in results:
            if self.exporter.save_valid_cookies(result):
                valid_count += 1
            if self.exporter.save_invalid_cookies(result):
                invalid_count += 1
        
        if valid_count > 0:
            print(f"✓ {valid_count} valid cookie groups saved")
        
        if invalid_count > 0:
            print(f"✓ {invalid_count} invalid cookie groups saved")
        
        print(f"\nResults saved to: {self.exporter.output_dir}")


async def main():
    """
    Main entry point.
    """
    # Setup logging
    setup_logging(verbose=False)
    
    app = CookieValidatorApp()
    
    try:
        # Select folder
        print("\n" + "="*80)
        print("DigitalOcean Cookie Validator")
        print("="*80 + "\n")
        
        print("Select folder containing cookie files (.txt or .json)...")
        folder = app.select_folder()
        
        if not folder.exists():
            print(f"Error: Folder not found: {folder}")
            sys.exit(1)
        
        # Find cookie files
        cookie_files = app.find_cookie_files(folder)
        
        if not cookie_files:
            print(f"Error: No cookie files found in {folder}")
            sys.exit(1)
        
        print(f"Found {len(cookie_files)} cookie file(s):\n")
        for f in cookie_files:
            print(f"  - {f.name}")
        
        # Validate
        await app.validate_all(cookie_files)
    
    except KeyboardInterrupt:
        print("\n\nValidation cancelled by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
