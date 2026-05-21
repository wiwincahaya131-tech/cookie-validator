"""
Logging configuration with colors and formatting.
"""

import logging
import sys
from typing import Optional


class ColorFormatter(logging.Formatter):
    """Colored log formatter."""
    
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
    }
    
    RESET = '\033[0m'
    BOLD = '\033[1m'
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record with colors."""
        if sys.stdout.isatty():
            levelname = record.levelname
            color = self.COLORS.get(levelname, self.RESET)
            record.levelname = f"{color}{levelname}{self.RESET}"
        
        return super().format(record)


class StatusFormatter(logging.Formatter):
    """Formatter for status messages."""
    
    COLORS = {
        'VALID': '\033[32m',        # Green
        'INVALID': '\033[31m',      # Red
        'EXPIRED': '\033[33m',      # Yellow
        'CHALLENGED': '\033[35m',   # Magenta
        'PARTIAL_AUTH': '\033[36m', # Cyan
        'FORBIDDEN': '\033[31m',    # Red
        'RATE_LIMITED': '\033[31m', # Red
        'NETWORK_ERROR': '\033[31m', # Red
    }
    
    RESET = '\033[0m'
    BOLD = '\033[1m'
    
    def format(self, record: logging.LogRecord) -> str:
        """Format status message with colors."""
        if hasattr(record, 'status'):
            status = record.status
            color = self.COLORS.get(status, self.RESET)
            record.msg = f"{color}[{status}]{self.RESET} {record.msg}"
        
        return super().format(record)


def setup_logging(verbose: bool = False, log_file: Optional[str] = None) -> None:
    """
    Setup logging configuration.
    
    Args:
        verbose: Enable verbose/debug logging
        log_file: Optional log file path
    """
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    # Format
    if verbose:
        fmt = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    else:
        fmt = '%(levelname)s - %(message)s'
    
    formatter = ColorFormatter(fmt)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # File handler
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)
    
    logger = logging.getLogger(__name__)
    logger.info(f"Logging initialized (verbose: {verbose})")
