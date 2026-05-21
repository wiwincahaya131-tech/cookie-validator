"""
Browser fingerprinting and request profile generation.
Produces realistic, consistent browser profiles.
"""

import random
from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class BrowserProfile:
    """Stable browser profile for consistent requests."""
    user_agent: str
    sec_ch_ua: str
    sec_ch_ua_platform: str
    sec_ch_ua_mobile: str
    accept_language: str
    
    def to_headers(self) -> Dict[str, str]:
        """Convert profile to HTTP headers."""
        return {
            'User-Agent': self.user_agent,
            'Sec-CH-UA': self.sec_ch_ua,
            'Sec-CH-UA-Platform': self.sec_ch_ua_platform,
            'Sec-CH-UA-Mobile': self.sec_ch_ua_mobile,
            'Accept-Language': self.accept_language,
        }


class BrowserFingerprint:
    """Generate realistic browser profiles."""
    
    # Chrome versions with their CH-UA values
    CHROME_VERSIONS = [
        {
            'version': '131.0.6778.264',
            'ua': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.264 Safari/537.36',
            'sec_ch_ua': '"Google Chrome";v="131", "Chromium";v="131", "Not.A/Brand";v="24"',
        },
        {
            'version': '130.0.6723.116',
            'ua': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.116 Safari/537.36',
            'sec_ch_ua': '"Google Chrome";v="130", "Chromium";v="130", "Not.A/Brand";v="24"',
        },
        {
            'version': '129.0.6668.100',
            'ua': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.100 Safari/537.36',
            'sec_ch_ua': '"Google Chrome";v="129", "Chromium";v="129", "Not.A/Brand";v="24"',
        },
    ]
    
    PLATFORMS = [
        ('Windows NT 10.0; Win64; x64', '"Windows"', 'false'),
        ('Macintosh; Intel Mac OS X 10_15_7', '"macOS"', 'false'),
        ('X11; Linux x86_64', '"Linux"', 'false'),
    ]
    
    ACCEPT_LANGUAGES = [
        'en-US,en;q=0.9',
        'en-US,en;q=0.9,id;q=0.8',
        'en;q=0.9,en-US;q=0.8',
    ]
    
    @staticmethod
    def get_stable_profile(seed: Optional[str] = None) -> BrowserProfile:
        """
        Generate stable browser profile.
        Can be seeded for reproducibility.
        
        Args:
            seed: Optional seed for reproducible profiles
        
        Returns:
            BrowserProfile instance
        """
        if seed:
            random.seed(seed)
        
        chrome = random.choice(BrowserFingerprint.CHROME_VERSIONS)
        platform_ua, platform_ch, mobile = random.choice(BrowserFingerprint.PLATFORMS)
        lang = random.choice(BrowserFingerprint.ACCEPT_LANGUAGES)
        
        # Rebuild UA with selected platform
        base_ua = f'Mozilla/5.0 ({platform_ua}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome["version"]} Safari/537.36'
        
        profile = BrowserProfile(
            user_agent=base_ua,
            sec_ch_ua=chrome['sec_ch_ua'],
            sec_ch_ua_platform=platform_ch,
            sec_ch_ua_mobile=mobile,
            accept_language=lang,
        )
        
        return profile
    
    @staticmethod
    def get_realistic_headers(seed: Optional[str] = None) -> Dict[str, str]:
        """
        Get complete realistic HTTP headers.
        
        Args:
            seed: Optional seed for reproducibility
        
        Returns:
            Dict of HTTP headers
        """
        profile = BrowserFingerprint.get_stable_profile(seed)
        
        headers = {
            # Browser identification
            'User-Agent': profile.user_agent,
            'Sec-CH-UA': profile.sec_ch_ua,
            'Sec-CH-UA-Platform': profile.sec_ch_ua_platform,
            'Sec-CH-UA-Mobile': profile.sec_ch_ua_mobile,
            
            # Language and encoding
            'Accept-Language': profile.accept_language,
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            
            # Fetch metadata
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            
            # Network and cache
            'Cache-Control': 'max-age=0',
            'Upgrade-Insecure-Requests': '1',
            
            # Standard headers
            'Connection': 'keep-alive',
            'DNT': '1',
        }
        
        return headers
    
    @staticmethod
    def get_api_headers(seed: Optional[str] = None) -> Dict[str, str]:
        """
        Get headers optimized for API requests.
        
        Args:
            seed: Optional seed for reproducibility
        
        Returns:
            Dict of HTTP headers
        """
        profile = BrowserFingerprint.get_stable_profile(seed)
        
        headers = {
            'User-Agent': profile.user_agent,
            'Accept': 'application/json',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': profile.accept_language,
            'Sec-CH-UA': profile.sec_ch_ua,
            'Sec-CH-UA-Mobile': profile.sec_ch_ua_mobile,
            'Sec-CH-UA-Platform': profile.sec_ch_ua_platform,
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-site',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
        }
        
        return headers
