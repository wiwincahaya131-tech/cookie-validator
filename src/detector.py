"""
Authentication state detection and threat analysis.
Detects login redirects, captchas, challenges, rate limits, etc.
"""

import re
import logging
from typing import Dict, Tuple, Optional, List
from html.parser import HTMLParser

logger = logging.getLogger(__name__)


class AuthenticationDetector:
    """Detect authentication state from responses."""
    
    # Cloudflare challenge indicators
    CLOUDFLARE_PATTERNS = [
        r'cf_clearance',
        r'cf-ray',
        r'cf-mitigated',
        r'challenge-form',
        r'Checking your browser',
        r'Enable JavaScript',
        r'Just a moment',
    ]
    
    # CAPTCHA indicators
    CAPTCHA_PATTERNS = [
        r'recaptcha',
        r'hcaptcha',
        r'turnstile',
        r'captcha',
        r'challenge-form',
        r'verify-human',
    ]
    
    # Login redirect patterns
    LOGIN_REDIRECT_PATTERNS = [
        r'/auth/login',
        r'/login',
        r'/signin',
        r'/account/login',
        r'/user/login',
    ]
    
    # Anti-bot patterns
    ANTI_BOT_PATTERNS = [
        r'bot',
        r'automated',
        r'script',
        r'request denied',
        r'access denied',
        r'forbidden',
    ]
    
    @staticmethod
    def detect_cloudflare_challenge(
        status_code: int,
        headers: Dict[str, str],
        content: Optional[str] = None
    ) -> bool:
        """
        Detect Cloudflare challenge page.
        
        Args:
            status_code: HTTP status code
            headers: Response headers
            content: Response body
        
        Returns:
            True if Cloudflare challenge detected
        """
        # Check for CF-specific headers
        if 'cf-ray' in headers or 'cf-mitigated' in headers:
            logger.debug("Cloudflare challenge detected via headers")
            return True
        
        # Check for Cloudflare challenge statuses
        if status_code in (403, 429, 503):
            if content and any(re.search(pattern, content, re.IGNORECASE) 
                             for pattern in AuthenticationDetector.CLOUDFLARE_PATTERNS):
                logger.debug("Cloudflare challenge detected via content")
                return True
        
        return False
    
    @staticmethod
    def detect_captcha(
        headers: Dict[str, str],
        content: Optional[str] = None
    ) -> Tuple[bool, Optional[str]]:
        """
        Detect CAPTCHA/challenge requirement.
        
        Args:
            headers: Response headers
            content: Response body
        
        Returns:
            Tuple of (detected: bool, type: str)
        """
        if not content:
            return False, None
        
        for pattern in AuthenticationDetector.CAPTCHA_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                if 'recaptcha' in content.lower():
                    logger.debug("reCAPTCHA detected")
                    return True, 'recaptcha'
                elif 'hcaptcha' in content.lower():
                    logger.debug("hCaptcha detected")
                    return True, 'hcaptcha'
                elif 'turnstile' in content.lower():
                    logger.debug("Turnstile detected")
                    return True, 'turnstile'
                else:
                    logger.debug("Generic CAPTCHA detected")
                    return True, 'unknown'
        
        return False, None
    
    @staticmethod
    def detect_login_redirect(
        status_code: int,
        headers: Dict[str, str],
        content: Optional[str] = None
    ) -> bool:
        """
        Detect redirect to login page.
        
        Args:
            status_code: HTTP status code
            headers: Response headers
            content: Response body
        
        Returns:
            True if login redirect detected
        """
        # Check redirect status codes
        if status_code in (301, 302, 303, 307, 308):
            location = headers.get('location', '').lower()
            if any(re.search(pattern, location, re.IGNORECASE) 
                   for pattern in AuthenticationDetector.LOGIN_REDIRECT_PATTERNS):
                logger.debug(f"Login redirect detected to: {location}")
                return True
        
        # Check for login form in content
        if status_code == 200 and content:
            if re.search(r'<form[^>]*login|id=["\'].*login.*["\']', content, re.IGNORECASE):
                logger.debug("Login form detected in response")
                return True
        
        return False
    
    @staticmethod
    def detect_rate_limit(
        status_code: int,
        headers: Dict[str, str]
    ) -> bool:
        """
        Detect rate limiting.
        
        Args:
            status_code: HTTP status code
            headers: Response headers
        
        Returns:
            True if rate limit detected
        """
        # Check status codes
        if status_code in (429, 503):
            logger.debug(f"Rate limit detected via status code: {status_code}")
            return True
        
        # Check rate limit headers
        rate_limit_headers = [
            'retry-after',
            'ratelimit-remaining',
            'x-ratelimit-remaining',
            'x-rate-limit-remaining',
        ]
        
        for header in rate_limit_headers:
            if header in headers:
                logger.debug(f"Rate limit detected via header: {header}")
                return True
        
        return False
    
    @staticmethod
    def detect_authenticated_response(
        status_code: int,
        content: Optional[str] = None
    ) -> Tuple[bool, List[str]]:
        """
        Detect authenticated API response.
        
        Args:
            status_code: HTTP status code
            content: Response body (JSON)
        
        Returns:
            Tuple of (is_authenticated: bool, indicators: List[str])
        """
        indicators = []
        
        if status_code != 200:
            return False, indicators
        
        if not content:
            return False, indicators
        
        content_lower = content.lower()
        
        # Check for account/user data
        auth_indicators = [
            (r'"account"', 'account_data'),
            (r'"user"', 'user_data'),
            (r'"email"', 'email_data'),
            (r'"id".*:', 'user_id'),
            (r'"created_at"', 'created_at'),
            (r'"updated_at"', 'updated_at'),
            (r'"plan"', 'plan_info'),
            (r'"billing', 'billing_info'),
            (r'"projects"', 'projects_data'),
            (r'"droplets"', 'droplets_data'),
        ]
        
        for pattern, name in auth_indicators:
            if re.search(pattern, content, re.IGNORECASE):
                indicators.append(name)
        
        is_authenticated = len(indicators) >= 3  # Need at least 3 indicators
        
        if is_authenticated:
            logger.debug(f"Authenticated response detected with indicators: {indicators}")
        
        return is_authenticated, indicators
    
    @staticmethod
    def detect_anti_bot(
        headers: Dict[str, str],
        content: Optional[str] = None,
        status_code: int = 200
    ) -> bool:
        """
        Detect anti-bot protection pages.
        
        Args:
            headers: Response headers
            content: Response body
            status_code: HTTP status code
        
        Returns:
            True if anti-bot detected
        """
        # Check for anti-bot headers
        anti_bot_headers = [
            'x-akamai-bot-detection',
            'x-cdn-provider',
            'x-protection',
        ]
        
        for header in anti_bot_headers:
            if header in headers:
                logger.debug(f"Anti-bot header detected: {header}")
                return True
        
        if content:
            if any(re.search(pattern, content, re.IGNORECASE) 
                   for pattern in AuthenticationDetector.ANTI_BOT_PATTERNS):
                if status_code in (403, 429, 503):
                    logger.debug("Anti-bot page detected")
                    return True
        
        return False
