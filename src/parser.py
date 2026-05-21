"""
Robust cookie parser supporting multiple formats.
Netscape TXT, Cookie-Editor, EditThisCookie, Chromium exports, and JSON.
"""

import re
import json
import logging
from typing import List, Tuple, Optional, Dict, Any
from pathlib import Path
from datetime import datetime

from .models import NormalizedCookie, CookieGroup, CookieSource, Provider

logger = logging.getLogger(__name__)


class CookieParser:
    """Parse cookies from various formats."""
    
    # Netscape format: domain flag path secure expiry name value
    # Tab-separated with optional #HttpOnly_ prefix
    NETSCAPE_PATTERN = re.compile(
        r'^(?:#HttpOnly_)?'  # Optional #HttpOnly_ prefix
        r'([^\t]+)\t'  # domain
        r'(TRUE|FALSE)\t'  # flag (domain match)
        r'([^\t]+)\t'  # path
        r'(TRUE|FALSE)\t'  # secure
        r'([^\t]+)\t'  # expiry (unix timestamp)
        r'([^\t]+)\t'  # name
        r'(.*)$',  # value (rest of line)
        re.IGNORECASE
    )
    
    AUTH_COOKIE_PATTERNS = [
        r'_digitalocean.*session',
        r'_digitalocean.*remember',
        r'auth.*token',
        r'session.*id',
        r'jwt',
        r'sid',
        r'access.*token',
        r'refresh.*token',
    ]
    
    @staticmethod
    def detect_format(content: str) -> CookieSource:
        """
        Detect cookie file format based on structure.
        
        Returns:
            CookieSource enum indicating detected format
        """
        lines = content.strip().split('\n')
        
        # Check for JSON format
        try:
            json.loads(content)
            return CookieSource.JSON_EXPORT
        except (json.JSONDecodeError, ValueError):
            pass
        
        # Check for Netscape format (7+ tab-separated columns)
        netscape_count = 0
        for line in lines:
            if line.strip().startswith('#') or not line.strip():
                continue
            
            # Count tabs - Netscape format has 6-7 tabs
            tab_count = line.count('\t')
            if tab_count >= 6:
                netscape_count += 1
        
        if netscape_count >= len([l for l in lines if l.strip() and not l.startswith('#')]) * 0.7:
            return CookieSource.NETSCAPE_TXT
        
        return CookieSource.UNKNOWN
    
    @staticmethod
    def parse_netscape_line(line: str) -> Optional[NormalizedCookie]:
        """
        Parse single Netscape format cookie line.
        
        Format: domain flag path secure expiry name value
        Example:
            .digitalocean.com  TRUE  /  FALSE  1779460867  notice_behavior  implied,us
            #HttpOnly_cloud.digitalocean.com  FALSE  /  TRUE  1779460867  _digitalocean2_session_v4  ...
        """
        line = line.strip()
        
        # Skip comments and empty lines
        if not line or line.startswith('#Secure_') or (line.startswith('#') and not line.startswith('#HttpOnly_')):
            return None
        
        try:
            match = CookieParser.NETSCAPE_PATTERN.match(line)
            if not match:
                logger.debug(f"Netscape pattern not matched: {line[:80]}")
                return None
            
            domain = match.group(1).strip()
            # flag = match.group(2)  # TRUE/FALSE for domain match
            path = match.group(3).strip() or "/"
            secure = match.group(4).upper() == 'TRUE'
            expires_str = match.group(5).strip()
            name = match.group(6).strip()
            value = match.group(7).strip()
            
            # Parse expiry
            expires = None
            if expires_str and expires_str != '0':
                try:
                    expires = int(expires_str)
                except ValueError:
                    logger.debug(f"Invalid expiry timestamp: {expires_str}")
            
            # Detect HttpOnly from original line
            http_only = line.startswith('#HttpOnly_')
            
            cookie = NormalizedCookie(
                domain=domain,
                name=name,
                value=value,
                path=path,
                secure=secure,
                httpOnly=http_only,
                expires=expires,
                source_format=CookieSource.NETSCAPE_TXT,
                original_line=line
            )
            
            logger.debug(f"Parsed Netscape cookie: {name}@{domain}")
            return cookie
        
        except Exception as e:
            logger.warning(f"Error parsing Netscape cookie: {e}")
            return None
    
    @staticmethod
    def parse_json_format(content: str) -> List[NormalizedCookie]:
        """
        Parse JSON cookie export (Chrome/Firefox/EditThisCookie format).
        
        Expected format:
            [{
                "domain": ".digitalocean.com",
                "name": "notice_behavior",
                "value": "implied,us",
                "path": "/",
                "secure": false,
                "httpOnly": false,
                "expires": 1779460867,
                "sameSite": "None"
            }]
        """
        cookies = []
        
        try:
            data = json.loads(content)
            if not isinstance(data, list):
                logger.warning("JSON is not a list of cookies")
                return cookies
            
            for item in data:
                if not isinstance(item, dict):
                    continue
                
                try:
                    cookie = NormalizedCookie(
                        domain=item.get('domain', '').strip(),
                        name=item.get('name', '').strip(),
                        value=item.get('value', '').strip(),
                        path=item.get('path', '/').strip() or '/',
                        secure=bool(item.get('secure', False)),
                        httpOnly=bool(item.get('httpOnly', False)),
                        expires=int(item.get('expires')) if item.get('expires') else None,
                        sameSite=item.get('sameSite'),
                        source_format=CookieSource.JSON_EXPORT,
                        original_line=json.dumps(item)
                    )
                    
                    if cookie.domain and cookie.name:
                        cookies.append(cookie)
                        logger.debug(f"Parsed JSON cookie: {cookie.name}@{cookie.domain}")
                
                except Exception as e:
                    logger.warning(f"Error parsing JSON cookie item: {e}")
                    continue
        
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON format: {e}")
        
        return cookies
    
    @classmethod
    def parse_file(cls, file_path: Path) -> CookieGroup:
        """
        Parse cookie file (auto-detect format).
        
        Args:
            file_path: Path to cookie file
        
        Returns:
            CookieGroup with parsed cookies
        """
        group = CookieGroup(file_path=str(file_path))
        
        try:
            content = file_path.read_text(encoding='utf-8')
        except UnicodeDecodeError:
            try:
                content = file_path.read_text(encoding='latin-1')
            except Exception as e:
                logger.error(f"Cannot read file {file_path}: {e}")
                group.parse_errors.append(f"File read error: {e}")
                return group
        
        # Detect format
        format_type = cls.detect_format(content)
        group.source_format = format_type
        logger.info(f"Detected format for {file_path.name}: {format_type.value}")
        
        if format_type == CookieSource.JSON_EXPORT:
            group.cookies = cls.parse_json_format(content)
        
        elif format_type == CookieSource.NETSCAPE_TXT:
            for line in content.split('\n'):
                cookie = cls.parse_netscape_line(line)
                if cookie:
                    group.cookies.append(cookie)
        
        else:
            logger.warning(f"Unknown format for {file_path.name}, attempting Netscape parse")
            for line in content.split('\n'):
                cookie = cls.parse_netscape_line(line)
                if cookie:
                    group.cookies.append(cookie)
        
        # Detect provider from domains
        group.provider = cls.detect_provider(group.cookies)
        group.root_domain = cls.extract_root_domain(group.cookies)
        
        logger.info(f"Parsed {len(group.cookies)} cookies from {file_path.name} (provider: {group.provider.value})")
        
        return group
    
    @staticmethod
    def detect_provider(cookies: List[NormalizedCookie]) -> Provider:
        """
        Detect provider from cookie domains.
        
        Args:
            cookies: List of parsed cookies
        
        Returns:
            Provider enum
        """
        domains = {c.domain.lower() for c in cookies}
        
        digitalocean_domains = {
            'digitalocean.com', 'cloud.digitalocean.com',
            '.digitalocean.com', '.cloud.digitalocean.com'
        }
        
        if any(d in domains or d.endswith('.digitalocean.com') for d in domains):
            return Provider.DIGITALOCEAN
        
        return Provider.UNKNOWN
    
    @staticmethod
    def extract_root_domain(cookies: List[NormalizedCookie]) -> Optional[str]:
        """
        Extract root domain from cookie domains.
        
        Args:
            cookies: List of cookies
        
        Returns:
            Root domain (e.g., 'digitalocean.com')
        """
        if not cookies:
            return None
        
        domains = {c.domain.lstrip('.') for c in cookies}
        
        for domain in domains:
            if 'digitalocean' in domain:
                # Extract root domain
                parts = domain.split('.')
                if len(parts) >= 2:
                    return '.'.join(parts[-2:])
        
        return None
