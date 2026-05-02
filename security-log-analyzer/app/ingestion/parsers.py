"""
Log Parsers for Multiple Formats
Supports: JSON, Syslog, CSV, Apache, Nginx
"""
import json
import re
import csv
from datetime import datetime
from typing import Dict, List, Optional, Any
from io import StringIO
import hashlib


class BaseParser:
    """Base class for all log parsers"""
    
    def __init__(self):
        self.supported_formats = []
    
    def parse(self, log_line: str) -> Optional[Dict[str, Any]]:
        """Parse a single log line"""
        raise NotImplementedError
    
    def parse_batch(self, log_lines: List[str]) -> List[Dict[str, Any]]:
        """Parse multiple log lines"""
        results = []
        for line in log_lines:
            try:
                parsed = self.parse(line.strip())
                if parsed:
                    results.append(parsed)
            except Exception as e:
                # Log parsing error but continue
                print(f"Error parsing line: {e}")
                continue
        return results


class JSONParser(BaseParser):
    """Parser for JSON formatted logs"""
    
    def __init__(self):
        super().__init__()
        self.supported_formats = ['json']
    
    def parse(self, log_line: str) -> Optional[Dict[str, Any]]:
        """Parse JSON log line"""
        if not log_line.strip():
            return None
        
        try:
            data = json.loads(log_line)
            
            # Extract common fields
            parsed = {
                'timestamp': self._extract_timestamp(data),
                'source_ip': self._extract_field(data, ['source_ip', 'src_ip', 'client_ip', 'ip']),
                'destination_ip': self._extract_field(data, ['dest_ip', 'dst_ip', 'server_ip']),
                'log_type': self._extract_field(data, ['log_type', 'type', 'category']) or 'custom',
                'severity': self._extract_field(data, ['severity', 'level', 'priority']) or 'info',
                'message': self._extract_field(data, ['message', 'msg', 'text']) or str(data),
                'raw': log_line
            }
            
            return parsed
            
        except json.JSONDecodeError:
            return None
    
    def _extract_timestamp(self, data: Dict) -> str:
        """Extract and normalize timestamp"""
        timestamp_fields = ['timestamp', 'time', '@timestamp', 'datetime', 'date']
        
        for field in timestamp_fields:
            if field in data:
                return self._normalize_timestamp(data[field])
        
        # Default to current time if no timestamp found
        return datetime.utcnow().isoformat() + 'Z'
    
    def _extract_field(self, data: Dict, field_names: List[str]) -> Optional[str]:
        """Extract field by trying multiple possible names"""
        for field in field_names:
            if field in data:
                return str(data[field])
        return None
    
    def _normalize_timestamp(self, timestamp: Any) -> str:
        """Normalize timestamp to ISO format UTC"""
        if isinstance(timestamp, str):
            # Try parsing various formats
            formats = [
                "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%d %H:%M:%S.%f",
            ]
            
            for fmt in formats:
                try:
                    dt = datetime.strptime(timestamp, fmt)
                    return dt.isoformat() + 'Z'
                except ValueError:
                    continue
        
        # If all else fails, return current time
        return datetime.utcnow().isoformat() + 'Z'


class SyslogParser(BaseParser):
    """Parser for Syslog formatted logs"""
    
    # Syslog pattern: <priority>timestamp hostname process[pid]: message
    SYSLOG_PATTERN = re.compile(
        r'^(?:<(?P<priority>\d+)>)?'
        r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+'
        r'(?P<message>.+)$'
    )
    
    def __init__(self):
        super().__init__()
        self.supported_formats = ['syslog']
    
    def parse(self, log_line: str) -> Optional[Dict[str, Any]]:
        """Parse syslog format"""
        if not log_line.strip():
            return None
        
        match = self.SYSLOG_PATTERN.match(log_line)
        
        if match:
            groups = match.groupdict()
            
            # Determine severity from priority
            priority = int(groups.get('priority') or 13)
            severity = self._priority_to_severity(priority)
            
            # Extract IPs from message
            source_ip = self._extract_ip(groups['message'])
            
            parsed = {
                'timestamp': self._normalize_syslog_timestamp(groups['timestamp']),
                'source_ip': source_ip,
                'destination_ip': None,
                'log_type': 'system',
                'severity': severity,
                'message': groups['message'],
                'hostname': groups['hostname'],
                'process': groups['process'],
                'raw': log_line
            }
            
            return parsed
        
        return None
    
    def _priority_to_severity(self, priority: int) -> str:
        """Convert syslog priority to severity level"""
        severity_level = priority % 8
        
        severity_map = {
            0: 'critical',  # Emergency
            1: 'critical',  # Alert
            2: 'critical',  # Critical
            3: 'high',      # Error
            4: 'medium',    # Warning
            5: 'low',       # Notice
            6: 'low',       # Informational
            7: 'low'        # Debug
        }
        
        return severity_map.get(severity_level, 'info')
    
    def _normalize_syslog_timestamp(self, timestamp: str) -> str:
        """Normalize syslog timestamp to ISO format"""
        try:
            # Syslog format: "Mar 29 10:30:45"
            current_year = datetime.now().year
            dt = datetime.strptime(f"{current_year} {timestamp}", "%Y %b %d %H:%M:%S")
            return dt.isoformat() + 'Z'
        except ValueError:
            return datetime.utcnow().isoformat() + 'Z'
    
    def _extract_ip(self, text: str) -> Optional[str]:
        """Extract IP address from text"""
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        match = ip_pattern.search(text)
        return match.group(0) if match else None


class CSVParser(BaseParser):
    """Parser for CSV formatted logs"""
    
    def __init__(self, headers: Optional[List[str]] = None):
        super().__init__()
        self.supported_formats = ['csv']
        self.headers = headers
    
    def parse(self, log_line: str) -> Optional[Dict[str, Any]]:
        """Parse CSV log line"""
        if not log_line.strip():
            return None
        
        try:
            reader = csv.reader(StringIO(log_line))
            row = next(reader)
            
            if self.headers:
                data = dict(zip(self.headers, row))
            else:
                # Auto-detect common CSV formats
                data = self._auto_map_fields(row)
            
            parsed = {
                'timestamp': self._extract_timestamp(data),
                'source_ip': data.get('source_ip') or data.get('src_ip'),
                'destination_ip': data.get('dest_ip') or data.get('dst_ip'),
                'log_type': data.get('log_type') or 'custom',
                'severity': data.get('severity') or 'info',
                'message': data.get('message') or ','.join(row),
                'raw': log_line
            }
            
            return parsed
            
        except Exception:
            return None
    
    def _auto_map_fields(self, row: List[str]) -> Dict[str, str]:
        """Auto-map CSV fields based on common patterns"""
        # Simple heuristic: timestamp, ip, message
        data = {}
        
        if len(row) >= 3:
            data['timestamp'] = row[0]
            data['source_ip'] = row[1] if self._is_ip(row[1]) else None
            data['message'] = row[-1]
        
        return data
    
    def _is_ip(self, text: str) -> bool:
        """Check if text is an IP address"""
        ip_pattern = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$')
        return bool(ip_pattern.match(text))
    
    def _extract_timestamp(self, data: Dict) -> str:
        """Extract timestamp from CSV data"""
        timestamp = data.get('timestamp') or data.get('time')
        if timestamp:
            return self._normalize_timestamp(timestamp)
        return datetime.utcnow().isoformat() + 'Z'
    
    def _normalize_timestamp(self, timestamp: str) -> str:
        """Normalize timestamp to ISO format"""
        formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%d/%b/%Y:%H:%M:%S",
        ]
        
        for fmt in formats:
            try:
                dt = datetime.strptime(timestamp.split()[0], fmt)
                return dt.isoformat() + 'Z'
            except ValueError:
                continue
        
        return datetime.utcnow().isoformat() + 'Z'


class ApacheParser(BaseParser):
    """Parser for Apache access logs"""
    
    # Apache Common Log Format
    APACHE_PATTERN = re.compile(
        r'^(?P<ip>\S+)\s+'
        r'(?P<ident>\S+)\s+'
        r'(?P<user>\S+)\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<request>[^"]*)"\s+'
        r'(?P<status>\d+)\s+'
        r'(?P<size>\S+)'
    )
    
    def __init__(self):
        super().__init__()
        self.supported_formats = ['apache']
    
    def parse(self, log_line: str) -> Optional[Dict[str, Any]]:
        """Parse Apache log format"""
        if not log_line.strip():
            return None
        
        match = self.APACHE_PATTERN.match(log_line)
        
        if match:
            groups = match.groupdict()
            
            # Determine severity from HTTP status
            status = int(groups['status'])
            severity = self._status_to_severity(status)
            
            parsed = {
                'timestamp': self._normalize_apache_timestamp(groups['timestamp']),
                'source_ip': groups['ip'],
                'destination_ip': None,
                'log_type': 'http',
                'severity': severity,
                'message': groups['request'],
                'http_status': status,
                'http_method': self._extract_method(groups['request']),
                'raw': log_line
            }
            
            return parsed
        
        return None
    
    def _status_to_severity(self, status: int) -> str:
        """Convert HTTP status to severity"""
        if status >= 500:
            return 'high'
        elif status >= 400:
            return 'medium'
        elif status >= 300:
            return 'low'
        else:
            return 'info'
    
    def _normalize_apache_timestamp(self, timestamp: str) -> str:
        """Normalize Apache timestamp to ISO format"""
        try:
            # Apache format: "29/Mar/2026:10:30:45 +0000"
            dt = datetime.strptime(timestamp.split()[0], "%d/%b/%Y:%H:%M:%S")
            return dt.isoformat() + 'Z'
        except ValueError:
            return datetime.utcnow().isoformat() + 'Z'
    
    def _extract_method(self, request: str) -> Optional[str]:
        """Extract HTTP method from request"""
        parts = request.split()
        return parts[0] if parts else None


class NginxParser(ApacheParser):
    """Parser for Nginx access logs (similar to Apache)"""
    
    def __init__(self):
        super().__init__()
        self.supported_formats = ['nginx']


def generate_log_hash(log_data: Dict[str, Any]) -> str:
    """Generate hash for deduplication"""
    # Create hash from timestamp + message + source_ip
    hash_string = f"{log_data.get('timestamp', '')}{log_data.get('message', '')}{log_data.get('source_ip', '')}"
    return hashlib.md5(hash_string.encode()).hexdigest()
