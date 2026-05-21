"""
Cookie Validator - Production-grade DigitalOcean cookie validation tool.
"""

__version__ = "1.0.0"
__author__ = "Cookie Validator Team"

from .models import (
    ValidationStatus,
    Provider,
    CookieSource,
    NormalizedCookie,
    CookieGroup,
    ValidationResult,
)
from .parser import CookieParser
from .fingerprint import BrowserFingerprint
from .detector import AuthenticationDetector
from .validator import CookieValidator
from .exporter import ResultExporter
from .logger import setup_logging

__all__ = [
    'ValidationStatus',
    'Provider',
    'CookieSource',
    'NormalizedCookie',
    'CookieGroup',
    'ValidationResult',
    'CookieParser',
    'BrowserFingerprint',
    'AuthenticationDetector',
    'CookieValidator',
    'ResultExporter',
    'setup_logging',
]
