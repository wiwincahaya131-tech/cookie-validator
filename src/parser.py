"""
Robust cookie parser supporting multiple formats.
Netscape TXT, Cookie-Editor, EditThisCookie, Chromium exports, and JSON.
"""

import re
import json
import logging
import time
from typing import List, Tuple, Optional, Dict, Any
from pathlib import Path
from datetime import datetime

from .models import NormalizedCookie, CookieGroup, CookieSource, Provider

logger = logging.getLogger(__name__)


class CookieParser:
    """Parse cookies from various formats."""
    
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
        # Count lines that match Netscape structure
        netscape_count = 0
        data_line_count = 0
        
        for line in lines:
            line_stripped = line.strip()
            
            # Skip empty lines and comment-only lines
            if not line_stripped or (line_stripped.startswith('#') and not line_stripped.startswith('#HttpOnly_')):
                continue
            
            data_line_count += 1
            
            # Remove #HttpOnly_ prefix for analysis
            if line_stripped.startswith('#HttpOnly_'):
                line_stripped = line_stripped[10:]
            
            # Count tabs - Netscape format has 6-7 tabs (7+ columns)
            tab_count = line_stripped.count('\t')
            
            if tab_count >= 6:
                # Further validate structure
                parts = line_stripped.split('\t')
                if len(parts) >= 7:
                    try:
                        # Validate key fields
                        domain = parts[0]
                        flag = parts[1].upper()
                        path = parts[2]
                        secure = parts[3].upper()
                        expiry = parts[4]
                        
                        # Check validity
                        if (domain and 
                            flag in ('TRUE', 'FALSE') and 
                            secure in ('TRUE', 'FALSE') and 
                            expiry.isdigit()):
                            netscape_count += 1
                    except (IndexError, ValueError):
                        pass
        
        # If more than 50% of data lines match Netscape structure
        if data_line_count > 0 and netscape_count >= data_line_count * 0.5:
            logger.debug(f"Detected Netscape format ({netscape_count}/{data_line_count} valid)")
            return CookieSource.NETSCAPE_TXT
        
        logger.debug(f"Format not clearly identified (netscape: {netscape_count}/{data_line_count})")
        return CookieSource.UNKNOWN
    
    @staticmethod
    def parse_netscape_line(line: str, now: Optional[int] = None) -> Optional[NormalizedCookie]:
        """
        Parse single Netscape format cookie line.
        
        Format: domain flag path secure expiry name value
        Example:
            .digitalocean.com	TRUE	/	FALSE	1779460867	notice_behavior	implied,us
            #HttpOnly_cloud.digitalocean.com	FALSE	/	TRUE	1779460867	_digitalocean2_session_v4	...
        """
        line = line.strip()
        
        if not line:
            return None
        
        # Skip non-HttpOnly comments
        if line.startswith('#') and not line.startswith('#HttpOnly_'):
            return None
        
        # Detect and remove #HttpOnly_ prefix
        http_only = False
        if line.startswith('#HttpOnly_'):
            http_only = True
            line = line[10:]  # Remove #HttpOnly_ prefix
        
        try:
            # Split by TAB character
            parts = line.split('\t')
            
            if len(parts) < 7:
                logger.debug(f"Netscape line has insufficient columns ({len(parts)}/7): {line[:50]}")
                return None
            
            domain = parts[0].strip()
            flag = parts[1].strip().upper()
            path = parts[2].strip() or "/"
            secure = parts[3].strip().upper()
            expires_str = parts[4].strip()
            name = parts[5].strip()
            value = '\t'.join(parts[6:]).strip()  # Value might contain tabs
            
            # Validate structure
            if not domain or not name:
                logger.debug(f"Missing domain or name")
                return None
            
            if flag not in ('TRUE', 'FALSE'):
                logger.debug(f"Invalid flag: {flag}")
                return None
            
            if secure not in ('TRUE', 'FALSE'):
                logger.debug(f"Invalid secure flag: {secure}")
                return None
            
            if not expires_str.isdigit():
                logger.debug(f"Invalid expiry: {expires_str}")
                return None
            
            # Parse expiry timestamp
            expires = int(expires_str)
            
            # Check if cookie is already expired
            if now is None:
                now = int(time.time())
            
            if expires < now and expires > 0:  # 0 = session cookie
                logger.debug(f"Cookie expired: {name} (expires: {datetime.fromtimestamp(expires)})")
                return None
            
            cookie = NormalizedCookie(
                domain=domain,
                name=name,
                value=value,
                path=path,
                secure=secure == 'TRUE',
                httpOnly=http_only,
                expires=expires if expires > 0 else None,
                source_format=CookieSource.NETSCAPE_TXT,
                original_line=line
            )
            
            logger.debug(f"Parsed Netscape cookie: {name}@{domain}")
            return cookie
        
        except Exception as e:
            logger.debug(f"Error parsing Netscape cookie line: {e} | Line: {line[:80]}")
            return None
    
    @staticmethod
    def parse_json_format(content: str, now: Optional[int] = None) -> List[NormalizedCookie]:
        """
        Parse JSON cookie export (Chrome/Firefox/EditThisCookie format).
        
        Expected format:
            [{\n                "domain": ".digitalocean.com",
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
        
        if now is None:
            now = int(time.time())
        
        try:
            data = json.loads(content)
            if not isinstance(data, list):
                logger.warning("JSON is not a list of cookies")
                return cookies
            
            for item in data:
                if not isinstance(item, dict):
                    continue
                
                try:
                    # Check expiry
                    expires = item.get('expires')
                    if isinstance(expires, (int, float)) and expires < now:
                        logger.debug(f"Cookie expired (JSON): {item.get('name')}")
                        continue
                    
                    domain = (item.get('domain') or '').strip()
                    name = (item.get('name') or '').strip()
                    value = (item.get('value') or '').strip()
                    
                    if not (domain and name and value):
                        logger.debug(f"JSON cookie missing fields")
                        continue
                    
                    cookie = NormalizedCookie(
                        domain=domain,
                        name=name,
                        value=value,
                        path=(item.get('path') or '/').strip() or '/',
                        secure=bool(item.get('secure', False)),
                        httpOnly=bool(item.get('httpOnly', False)),
                        expires=int(expires) if isinstance(expires, (int, float)) else None,
                        sameSite=item.get('sameSite'),
                        source_format=CookieSource.JSON_EXPORT,
                        original_line=json.dumps(item)
                    )
                    
                    cookies.append(cookie)
                    logger.debug(f"Parsed JSON cookie: {name}@{domain}")
                
                except Exception as e:
                    logger.debug(f"Error parsing JSON cookie item: {e}")
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
        now = int(time.time())
        group = CookieGroup(file_path=str(file_path))
        
        try:
            # Try UTF-8 first, fallback to latin-1
            try:
                content = file_path.read_text(encoding='utf-8')
            except UnicodeDecodeError:
                try:
                    content = file_path.read_text(encoding='latin-1')
                except Exception as e:
                    logger.error(f"Cannot read file {file_path}: {e}")
                    group.parse_errors.append(f"File read error: {e}")
                    return group
        except Exception as e:
            logger.error(f"Cannot read file {file_path}: {e}")
            group.parse_errors.append(f"File read error: {e}")
            return group
        
        # Detect format
        format_type = cls.detect_format(content)
        group.source_format = format_type
        logger.info(f"Detected format for {file_path.name}: {format_type.value}")
        
        if format_type == CookieSource.JSON_EXPORT:
            group.cookies = cls.parse_json_format(content, now)
        
        elif format_type == CookieSource.NETSCAPE_TXT:
            for line in content.split('\n'):
                cookie = cls.parse_netscape_line(line, now)
                if cookie:
                    group.cookies.append(cookie)
        
        else:
            # Unknown format - try Netscape as fallback
            logger.warning(f"Unknown format for {file_path.name}, attempting Netscape parse")
            for line in content.split('\n'):
                cookie = cls.parse_netscape_line(line, now)
                if cookie:
                    group.cookies.append(cookie)
        
        # Detect provider from domains
        group.provider = cls.detect_provider(group.cookies)
        group.root_domain = cls.extract_root_domain(group.cookies)
        
        logger.info(f"Parsed {len(group.cookies)} cookies from {file_path.name} "
                   f"(provider: {group.provider.value}, format: {format_type.value})")
        
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
        
        # DigitalOcean indicators
        do_indicators = {
            'digitalocean.com', 'cloud.digitalocean.com',
            '.digitalocean.com', '.cloud.digitalocean.com'
        }
        
        for domain in domains:
            if any(ind in domain for ind in do_indicators):
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
