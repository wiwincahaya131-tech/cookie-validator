"""
Data models and schemas for cookie validation.
"""

from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any, List
from enum import Enum
from datetime import datetime


class ValidationStatus(str, Enum):
    """Cookie validation status classifications."""
    VALID = "VALID"
    PARTIAL_AUTH = "PARTIAL_AUTH"
    INVALID = "INVALID"
    EXPIRED = "EXPIRED"
    CHALLENGED = "CHALLENGED"
    FORBIDDEN = "FORBIDDEN"
    RATE_LIMITED = "RATE_LIMITED"
    NETWORK_ERROR = "NETWORK_ERROR"


class Provider(str, Enum):
    """Supported cookie providers."""
    DIGITALOCEAN = "digitalocean"
    UNKNOWN = "unknown"


class CookieSource(str, Enum):
    """Cookie export source type."""
    NETSCAPE_TXT = "netscape_txt"
    JSON_EXPORT = "json_export"
    UNKNOWN = "unknown"


@dataclass
class NormalizedCookie:
    """
    Normalized cookie representation.
    All cookies are normalized to this schema regardless of source format.
    """
    domain: str
    name: str
    value: str
    path: str = "/"
    secure: bool = False
    httpOnly: bool = False
    expires: Optional[int] = None  # Unix timestamp
    sameSite: Optional[str] = None
    
    # Metadata
    source_format: CookieSource = CookieSource.UNKNOWN
    original_line: Optional[str] = None
    parse_error: Optional[str] = None
    
    def __hash__(self):
        return hash((self.domain, self.name))
    
    def __eq__(self, other):
        if not isinstance(other, NormalizedCookie):
            return False
        return self.domain == other.domain and self.name == other.name
    
    def is_expired(self, now: Optional[int] = None) -> bool:
        """Check if cookie is expired."""
        if self.expires is None:
            return False
        if now is None:
            now = int(datetime.now().timestamp())
        return self.expires < now
    
    def is_auth_cookie(self) -> bool:
        """Check if this is likely an authentication cookie."""
        auth_keywords = [
            "session", "auth", "token", "jwt", "sid",
            "remember", "_dc2_session", "digitalocean2_session"
        ]
        return any(kw in self.name.lower() for kw in auth_keywords)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class CookieGroup:
    """Group of cookies from same source file."""
    file_path: str
    cookies: List[NormalizedCookie] = field(default_factory=list)
    source_format: CookieSource = CookieSource.UNKNOWN
    provider: Provider = Provider.UNKNOWN
    root_domain: Optional[str] = None
    parse_errors: List[str] = field(default_factory=list)
    
    def get_auth_cookies(self) -> List[NormalizedCookie]:
        """Get likely authentication cookies."""
        return [c for c in self.cookies if c.is_auth_cookie()]
    
    def get_valid_cookies(self, now: Optional[int] = None) -> List[NormalizedCookie]:
        """Get non-expired cookies."""
        return [c for c in self.cookies if not c.is_expired(now)]


@dataclass
class ValidationSignal:
    """Single authentication signal."""
    name: str
    detected: bool
    score: int  # 0-1
    details: Optional[str] = None


@dataclass
class ValidationResponse:
    """Single HTTP response analysis."""
    url: str
    status_code: int
    headers: Dict[str, str]
    content_snippet: Optional[str] = None
    response_time: float = 0.0
    error: Optional[str] = None


@dataclass
class ValidationResult:
    """Complete validation result for a cookie group."""
    cookie_group: CookieGroup
    status: ValidationStatus
    score: int  # 0-9
    signals: List[ValidationSignal] = field(default_factory=list)
    responses: List[ValidationResponse] = field(default_factory=list)
    
    # Detections
    login_redirect_detected: bool = False
    captcha_detected: bool = False
    rate_limit_detected: bool = False
    anti_bot_detected: bool = False
    
    # Metadata
    endpoint_used: Optional[str] = None
    elapsed_time: float = 0.0
    validation_error: Optional[str] = None
    
    # Debug
    debug_info: Dict[str, Any] = field(default_factory=dict)
    
    def add_signal(self, name: str, detected: bool, details: Optional[str] = None):
        """Add validation signal."""
        self.signals.append(ValidationSignal(
            name=name,
            detected=detected,
            score=1 if detected else 0,
            details=details
        ))
        if detected:
            self.score += 1
    
    def add_response(self, response: ValidationResponse):
        """Add response analysis."""
        self.responses.append(response)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON export."""
        return {
            "file": self.cookie_group.file_path,
            "provider": self.cookie_group.provider.value,
            "status": self.status.value,
            "score": self.score,
            "timestamp": datetime.now().isoformat(),
            "cookies_count": len(self.cookie_group.cookies),
            "auth_cookies_count": len(self.cookie_group.get_auth_cookies()),
            "valid_cookies_count": len(self.cookie_group.get_valid_cookies()),
            "detections": {
                "login_redirect": self.login_redirect_detected,
                "captcha": self.captcha_detected,
                "rate_limit": self.rate_limit_detected,
                "anti_bot": self.anti_bot_detected,
            },
            "endpoint_used": self.endpoint_used,
            "elapsed_time": self.elapsed_time,
            "signals": [
                {
                    "name": s.name,
                    "detected": s.detected,
                    "score": s.score,
                    "details": s.details
                }
                for s in self.signals
            ],
            "responses": [
                {
                    "url": r.url,
                    "status_code": r.status_code,
                    "response_time": r.response_time,
                    "error": r.error
                }
                for r in self.responses
            ],
            "error": self.validation_error
        }
