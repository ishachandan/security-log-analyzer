"""
Query Filter Extraction Module
Extracts structured filters from natural language queries
"""
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import re


class FilterExtractor:
    """Extracts filters from natural language queries"""
    
    def __init__(self):
        """Initialize filter extractor"""
        # Severity keywords
        self.severity_keywords = {
            'critical': ['critical', 'severe', 'emergency'],
            'high': ['high', 'important', 'serious'],
            'medium': ['medium', 'moderate', 'warning'],
            'low': ['low', 'minor', 'info', 'informational']
        }
        
        # Log type keywords
        self.log_type_keywords = {
            'auth': ['auth', 'authentication', 'login', 'ssh', 'password'],
            'http': ['http', 'web', 'access', 'request', 'api'],
            'system': ['system', 'kernel', 'service', 'daemon'],
        }
        
        # Time keywords
        self.time_patterns = {
            'last_minutes': r'last\s+(\d+)\s+minutes?',
            'last_hours': r'last\s+(\d+)\s+hours?',
            'last_days': r'last\s+(\d+)\s+days?',
            'today': r'\btoday\b',
            'recent': r'\brecent\b',
        }
    
    def extract_filters(self, query: str) -> Dict[str, Any]:
        """
        Extract all filters from query
        
        Args:
            query: Natural language query string
            
        Returns:
            Dictionary with extracted filters
        """
        query_lower = query.lower()
        filters = {}
        
        # Extract severity
        severity = self._extract_severity(query_lower)
        if severity:
            filters['severity'] = severity
        
        # Extract log type
        log_type = self._extract_log_type(query_lower)
        if log_type:
            filters['log_type'] = log_type
        
        # Extract IP addresses
        ips = self._extract_ips(query)
        if ips:
            filters['source_ip'] = ips[0]  # Use first IP found
            filters['all_ips'] = ips
        
        # Extract time range
        time_filter = self._extract_time_range(query_lower)
        if time_filter:
            filters['time_range'] = time_filter
        
        return filters
    
    def _extract_severity(self, query: str) -> Optional[str]:
        """Extract severity level from query"""
        for severity, keywords in self.severity_keywords.items():
            if any(keyword in query for keyword in keywords):
                return severity
        return None
    
    def _extract_log_type(self, query: str) -> Optional[str]:
        """Extract log type from query"""
        for log_type, keywords in self.log_type_keywords.items():
            if any(keyword in query for keyword in keywords):
                return log_type
        return None
    
    def _extract_ips(self, query: str) -> List[str]:
        """Extract IP addresses from query"""
        # IPv4 pattern
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, query)
        
        # Validate IPs
        valid_ips = []
        for ip in ips:
            parts = ip.split('.')
            if all(0 <= int(part) <= 255 for part in parts):
                valid_ips.append(ip)
        
        return valid_ips
    
    def _extract_time_range(self, query: str) -> Optional[Dict[str, str]]:
        """Extract time range from query"""
        now = datetime.utcnow()
        
        # Check for "last X minutes"
        match = re.search(self.time_patterns['last_minutes'], query)
        if match:
            minutes = int(match.group(1))
            start_time = now - timedelta(minutes=minutes)
            return {
                'start': start_time.isoformat() + 'Z',
                'end': now.isoformat() + 'Z',
                'description': f'last {minutes} minutes'
            }
        
        # Check for "last X hours"
        match = re.search(self.time_patterns['last_hours'], query)
        if match:
            hours = int(match.group(1))
            start_time = now - timedelta(hours=hours)
            return {
                'start': start_time.isoformat() + 'Z',
                'end': now.isoformat() + 'Z',
                'description': f'last {hours} hours'
            }
        
        # Check for "last X days"
        match = re.search(self.time_patterns['last_days'], query)
        if match:
            days = int(match.group(1))
            start_time = now - timedelta(days=days)
            return {
                'start': start_time.isoformat() + 'Z',
                'end': now.isoformat() + 'Z',
                'description': f'last {days} days'
            }
        
        # Check for "today"
        if re.search(self.time_patterns['today'], query):
            start_time = now.replace(hour=0, minute=0, second=0, microsecond=0)
            return {
                'start': start_time.isoformat() + 'Z',
                'end': now.isoformat() + 'Z',
                'description': 'today'
            }
        
        # Check for "recent"
        if re.search(self.time_patterns['recent'], query):
            start_time = now - timedelta(hours=1)  # Default: last hour
            return {
                'start': start_time.isoformat() + 'Z',
                'end': now.isoformat() + 'Z',
                'description': 'recent (last hour)'
            }
        
        return None
    
    def build_where_clause(self, filters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build ChromaDB where clause from filters
        
        Args:
            filters: Extracted filters
            
        Returns:
            ChromaDB where clause
        """
        where = {}
        
        if 'severity' in filters:
            where['severity'] = filters['severity']
        
        if 'source_ip' in filters:
            where['source_ip'] = filters['source_ip']
        
        if 'log_type' in filters:
            where['log_type'] = filters['log_type']
        
        return where if where else None
    
    def apply_time_filter(
        self,
        results: List[Dict[str, Any]],
        time_range: Dict[str, str]
    ) -> List[Dict[str, Any]]:
        """
        Apply time range filter to results
        
        Args:
            results: Query results
            time_range: Time range filter
            
        Returns:
            Filtered results
        """
        if not time_range:
            return results
        
        start_time = datetime.fromisoformat(time_range['start'].replace('Z', '+00:00'))
        end_time = datetime.fromisoformat(time_range['end'].replace('Z', '+00:00'))
        
        filtered = []
        for result in results:
            metadata = result.get('metadata', {})
            timestamp_str = metadata.get('timestamp', '')
            
            if timestamp_str:
                try:
                    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                    if start_time <= timestamp <= end_time:
                        filtered.append(result)
                except:
                    # If timestamp parsing fails, include the result
                    filtered.append(result)
            else:
                # If no timestamp, include the result
                filtered.append(result)
        
        return filtered
    
    def get_filter_summary(self, filters: Dict[str, Any]) -> str:
        """
        Generate human-readable filter summary
        
        Args:
            filters: Extracted filters
            
        Returns:
            Summary string
        """
        if not filters:
            return "No filters applied"
        
        parts = []
        
        if 'severity' in filters:
            parts.append(f"severity={filters['severity']}")
        
        if 'log_type' in filters:
            parts.append(f"type={filters['log_type']}")
        
        if 'source_ip' in filters:
            parts.append(f"IP={filters['source_ip']}")
        
        if 'time_range' in filters:
            parts.append(f"time={filters['time_range']['description']}")
        
        return ", ".join(parts)
