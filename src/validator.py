"""
Cookie validation engine with provider-specific strategies.
"""

import asyncio
import logging
import time
from typing import List, Optional, Dict, Any
from abc import ABC, abstractmethod

import httpx

from .models import (
    CookieGroup, ValidationResult, ValidationStatus, ValidationResponse,
    NormalizedCookie
)
from .fingerprint import BrowserFingerprint
from .detector import AuthenticationDetector

logger = logging.getLogger(__name__)


class ProviderValidator(ABC):
    """Base class for provider-specific validators."""
    
    @abstractmethod
    async def validate(self, client: httpx.AsyncClient, cookie_group: CookieGroup) -> ValidationResult:
        """Validate cookies for this provider."""
        pass
    
    @abstractmethod
    def get_endpoints(self) -> List[str]:
        """Get list of endpoints to validate."""
        pass
    
    @abstractmethod
    def get_warmup_urls(self) -> List[str]:
        """Get URLs for session warmup."""
        pass


class DigitalOceanValidator(ProviderValidator):
    """DigitalOcean-specific cookie validator."""
    
    BASE_URL = "https://cloud.digitalocean.com"
    
    def get_endpoints(self) -> List[str]:
        """
        Get DigitalOcean endpoints to validate (priority order).
        
        Returns:
            List of API endpoints
        """
        return [
            "/v2/account",  # Account info API
            "/v2/databases",  # Databases API
            "/api/v2/account",  # Alternative account endpoint
            "/projects",  # Projects page
            "/account",  # Account settings page
        ]
    
    def get_warmup_urls(self) -> List[str]:
        """
        Get URLs for session warmup.
        
        Returns:
            List of URLs to warm up session
        """
        return [
            f"{self.BASE_URL}/",
            f"{self.BASE_URL}/dashboard",
        ]
    
    async def validate(self, client: httpx.AsyncClient, cookie_group: CookieGroup) -> ValidationResult:
        """
        Validate DigitalOcean cookies.
        
        Args:
            client: Async HTTP client with cookies
            cookie_group: Group of cookies to validate
        
        Returns:
            ValidationResult
        """
        result = ValidationResult(
            cookie_group=cookie_group,
            status=ValidationStatus.INVALID,
            score=0
        )
        
        start_time = time.time()
        
        try:
            # Check for critical auth cookies
            auth_cookies = cookie_group.get_auth_cookies()
            if auth_cookies:
                result.add_signal("has_auth_cookie", True, f"Found {len(auth_cookies)} auth cookies")
            else:
                result.add_signal("has_auth_cookie", False, "No auth cookies found")
            
            # Warmup session
            await self._warmup_session(client, result)
            
            # Validate endpoints
            for endpoint in self.get_endpoints():
                url = f"{self.BASE_URL}{endpoint}"
                success = await self._validate_endpoint(client, url, result)
                if success:
                    result.endpoint_used = endpoint
                    break
            
            # Classify result
            result.status = self._classify_status(result)
        
        except Exception as e:
            logger.error(f"Validation error: {e}")
            result.validation_error = str(e)
            result.status = ValidationStatus.NETWORK_ERROR
        
        finally:
            result.elapsed_time = time.time() - start_time
        
        return result
    
    async def _warmup_session(self, client: httpx.AsyncClient, result: ValidationResult) -> None:
        """
        Warmup session with initial requests.
        
        Args:
            client: Async HTTP client
            result: Validation result to update
        """
        logger.debug("Warming up session...")
        
        for url in self.get_warmup_urls():
            try:
                response = await client.get(url, timeout=10, follow_redirects=True)
                logger.debug(f"Warmup request to {url}: {response.status_code}")
            except Exception as e:
                logger.debug(f"Warmup request failed: {e}")
    
    async def _validate_endpoint(self, client: httpx.AsyncClient, url: str, result: ValidationResult) -> bool:
        """
        Validate single endpoint.
        
        Args:
            client: Async HTTP client
            url: URL to validate
            result: Result to update
        
        Returns:
            True if validation successful
        """
        try:
            response = await client.get(
                url,
                timeout=10,
                follow_redirects=False,
                headers=BrowserFingerprint.get_api_headers()
            )
            
            resp_obj = ValidationResponse(
                url=url,
                status_code=response.status_code,
                headers=dict(response.headers),
                response_time=response.elapsed.total_seconds(),
            )
            
            content = response.text[:500] if response.text else None
            resp_obj.content_snippet = content
            
            result.add_response(resp_obj)
            
            # Detect status
            if response.status_code == 401:
                result.add_signal("http_401", True, "Unauthorized")
                return False
            
            if response.status_code == 403:
                result.add_signal("http_403", True, "Forbidden")
                result.status = ValidationStatus.FORBIDDEN
                return False
            
            if response.status_code in (301, 302, 303, 307, 308):
                if AuthenticationDetector.detect_login_redirect(response.status_code, dict(response.headers)):
                    result.login_redirect_detected = True
                    result.add_signal("login_redirect", True, f"Redirect to login")
                    result.status = ValidationStatus.EXPIRED
                    return False
            
            if response.status_code == 429:
                result.rate_limit_detected = True
                result.add_signal("rate_limit", True, "429 Too Many Requests")
                result.status = ValidationStatus.RATE_LIMITED
                return False
            
            if response.status_code == 200:
                # Check for authenticated content
                is_auth, indicators = AuthenticationDetector.detect_authenticated_response(
                    response.status_code, content
                )
                if is_auth:
                    result.add_signal("authenticated_content", True, f"Indicators: {indicators}")
                    result.add_signal("http_200", True, "200 OK")
                    return True
            
            return False
        
        except asyncio.TimeoutError:
            result.add_signal("timeout", True, f"Timeout on {url}")
            return False
        except Exception as e:
            logger.debug(f"Endpoint validation error: {e}")
            result.add_signal("request_error", True, str(e))
            return False
    
    def _classify_status(self, result: ValidationResult) -> ValidationStatus:
        """
        Classify validation status based on signals.
        
        Args:
            result: Validation result with signals
        
        Returns:
            Classified ValidationStatus
        """
        if result.login_redirect_detected:
            return ValidationStatus.EXPIRED
        
        if result.captcha_detected:
            return ValidationStatus.CHALLENGED
        
        if result.rate_limit_detected:
            return ValidationStatus.RATE_LIMITED
        
        if result.status == ValidationStatus.FORBIDDEN:
            return ValidationStatus.FORBIDDEN
        
        if result.score >= 6:
            return ValidationStatus.VALID
        elif result.score >= 4:
            return ValidationStatus.PARTIAL_AUTH
        else:
            return ValidationStatus.INVALID


class CookieValidator:
    """Main cookie validation coordinator."""
    
    def __init__(self, max_concurrency: int = 3):
        """
        Initialize validator.
        
        Args:
            max_concurrency: Max concurrent validations
        """
        self.max_concurrency = max_concurrency
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self.validators: Dict[str, ProviderValidator] = {
            'digitalocean': DigitalOceanValidator(),
        }
    
    async def validate_group(self, cookie_group: CookieGroup) -> ValidationResult:
        """
        Validate a cookie group.
        
        Args:
            cookie_group: Group of cookies to validate
        
        Returns:
            ValidationResult
        """
        async with self.semaphore:
            # Get provider validator
            provider_name = cookie_group.provider.value
            validator = self.validators.get(provider_name)
            
            if not validator:
                logger.warning(f"No validator for provider: {provider_name}")
                result = ValidationResult(
                    cookie_group=cookie_group,
                    status=ValidationStatus.INVALID,
                    score=0,
                    validation_error=f"No validator for provider: {provider_name}"
                )
                return result
            
            # Create client with cookies
            cookies_dict = self._cookies_to_dict(cookie_group.cookies)
            
            async with httpx.AsyncClient(
                cookies=cookies_dict,
                timeout=10.0,
                limits=httpx.Limits(max_connections=10),
                http2=True,
                follow_redirects=True,
                headers=BrowserFingerprint.get_realistic_headers()
            ) as client:
                return await validator.validate(client, cookie_group)
    
    @staticmethod
    def _cookies_to_dict(cookies: List[NormalizedCookie]) -> Dict[str, str]:
        """
        Convert NormalizedCookie list to httpx-compatible dict.
        
        Args:
            cookies: List of normalized cookies
        
        Returns:
            Dict of name->value for httpx
        """
        return {cookie.name: cookie.value for cookie in cookies}
