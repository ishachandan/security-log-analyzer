"""
Log Normalization Module
Handles timestamp normalization and field standardization
"""
from datetime import datetime
from typing import Dict, Any, Optional
import re


class LogNormalizer:
    """Normalizes log entries to standard format"""
    
    # Standard timestamp formats to try
    TIMESTAMP_FORMATS = [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d %H:%M:%S.%f",
        "%b %d %H:%M:%S",
        "%d/%b/%Y:%H:%M:%S %z",
        "%Y/%m/%d %H:%M:%S",
    ]
    
    # Severity level mapping
    SEVERITY_MAP = {
        'emergency': 'critical',
        'emerg': 'critical',
        'alert': 'critical',
        'crit': 'critical',
        'critical': 'critical',
        'err': 'high',
        'error': 'high',
        'warn': 'medium',
        'warning': 'medium',
        'notice': 'low',
        'info': 'low',
        'informational': 'low',
        'debug': 'low',
    }
    
    def normalize(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize a log entry to standard format"""
        normalized = {
            'timestamp': self.normalize_timestamp(log_entry.get('timestamp')),
            'source_ip': self.normalize_ip(log_entry.get('source_ip')),
            'destination_ip': self.normalize_ip(log_entry.get('destination_ip')),
            'log_type': self.normalize_log_type(log_entry.get('log_type')),
            'severity': self.normalize_severity(log_entry.get('severity')),
            'message': self.normalize_message(log_entry.get('message')),
            'raw': log_entry.get('raw', ''),
        }
        
        # Add optional fields if present
        optional_fields = ['hostname', 'process', 'http_status', 'http_method']
        for field in optional_fields:
            if field in log_entry and log_entry[field]:
                normalized[field] = log_entry[field]
        
        return normalized
    
    def normalize_timestamp(self, timestamp: Any) -> str:
        """Normalize timestamp to ISO 8601 UTC format"""
        if not timestamp:
            return datetime.utcnow().isoformat() + 'Z'
        
        if isinstance(timestamp, datetime):
            return timestamp.isoformat() + 'Z'
        
        if isinstance(timestamp, str):
            # Try parsing with known formats
            for fmt in self.TIMESTAMP_FORMATS:
                try:
                    dt = datetime.strptime(timestamp, fmt)
                    return dt.isoformat() + 'Z'
                except ValueError:
                    continue
            
            # Try parsing with dateutil if available
            try:
                from dateutil import parser
                dt = parser.parse(timestamp)
                return dt.isoformat() + 'Z'
            except:
                pass
        
        # Default to current time
        return datetime.utcnow().isoformat() + 'Z'
    
    def normalize_ip(self, ip: Optional[str]) -> Optional[str]:
        """Normalize IP address"""
        if not ip:
            return None
        
        # Basic IPv4 validation with range check
        ip_pattern = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$')
        if ip_pattern.match(str(ip)):
            # Validate each octet is 0-255
            octets = str(ip).split('.')
            if all(0 <= int(octet) <= 255 for octet in octets):
                return str(ip)
        
        # IPv6 basic check
        if ':' in str(ip):
            return str(ip)
        
        return None
    
    def normalize_log_type(self, log_type: Optional[str]) -> str:
        """Normalize log type to standard categories"""
        if not log_type:
            return 'custom'
        
        log_type_lower = str(log_type).lower()
        
        # Map to standard types
        type_map = {
            'auth': 'auth',
            'authentication': 'auth',
            'login': 'auth',
            'http': 'http',
            'web': 'http',
            'access': 'http',
            'system': 'system',
            'syslog': 'system',
            'security': 'auth',
            'firewall': 'auth',
        }
        
        for key, value in type_map.items():
            if key in log_type_lower:
                return value
        
        return 'custom'
    
    def normalize_severity(self, severity: Optional[str]) -> str:
        """Normalize severity to standard levels"""
        if not severity:
            return 'info'
        
        severity_lower = str(severity).lower()
        
        # Direct mapping
        if severity_lower in self.SEVERITY_MAP:
            return self.SEVERITY_MAP[severity_lower]
        
        # Numeric severity (0-7 syslog style)
        if severity_lower.isdigit():
            level = int(severity_lower)
            if level <= 2:
                return 'critical'
            elif level == 3:
                return 'high'
            elif level == 4:
                return 'medium'
            else:
                return 'low'
        
        # Default
        return 'info'
    
    def normalize_message(self, message: Any) -> str:
        """Normalize message field"""
        if not message:
            return ''
        
        # Convert to string and clean
        msg = str(message).strip()
        
        # Remove excessive whitespace
        msg = re.sub(r'\s+', ' ', msg)
        
        return msg
    
    def validate(self, log_entry: Dict[str, Any]) -> bool:
        """Validate that log entry has required fields"""
        required_fields = ['timestamp', 'message']
        
        for field in required_fields:
            if field not in log_entry or not log_entry[field]:
                return False
        
        return True
