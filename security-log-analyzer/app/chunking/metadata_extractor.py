"""
Metadata Extraction Module
Extracts rich metadata from log chunks for enhanced retrieval
"""
from typing import Dict, List, Any, Set
import re
from collections import Counter


class MetadataExtractor:
    """Extracts and enriches metadata from log chunks"""
    
    # Common security patterns
    ATTACK_PATTERNS = {
        'sql_injection': r'(union|select|insert|update|delete|drop|exec|script)',
        'xss': r'(<script|javascript:|onerror=|onload=)',
        'path_traversal': r'(\.\./|\.\.\\)',
        'command_injection': r'(;|\||&|`|\$\()',
        'brute_force': r'(failed.*login|authentication.*failed|invalid.*password)',
    }
    
    # HTTP status categories
    HTTP_STATUS_CATEGORIES = {
        'success': range(200, 300),
        'redirect': range(300, 400),
        'client_error': range(400, 500),
        'server_error': range(500, 600)
    }
    
    def extract_security_indicators(
        self,
        chunk: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Extract security-related indicators from chunk
        
        Returns indicators like:
        - Potential attack types
        - Suspicious patterns
        - Anomaly scores
        """
        text = chunk.get('text', '')
        logs = chunk.get('logs', [])
        
        indicators = {
            'attack_types': [],
            'suspicious_patterns': [],
            'anomaly_score': 0,
            'threat_level': 'low'
        }
        
        # Check for attack patterns
        for attack_type, pattern in self.ATTACK_PATTERNS.items():
            if re.search(pattern, text, re.IGNORECASE):
                indicators['attack_types'].append(attack_type)
                indicators['anomaly_score'] += 10
        
        # Check for repeated failed attempts
        failed_count = sum(1 for log in logs if 'fail' in log.get('message', '').lower())
        if failed_count >= 3:
            indicators['suspicious_patterns'].append('multiple_failures')
            indicators['anomaly_score'] += 15
        
        # Check for unusual ports
        unusual_ports = self._extract_unusual_ports(text)
        if unusual_ports:
            indicators['suspicious_patterns'].append('unusual_ports')
            indicators['anomaly_score'] += 5
        
        # Determine threat level
        if indicators['anomaly_score'] >= 20:
            indicators['threat_level'] = 'high'
        elif indicators['anomaly_score'] >= 10:
            indicators['threat_level'] = 'medium'
        else:
            indicators['threat_level'] = 'low'
        
        return indicators
    
    def extract_http_metadata(
        self,
        chunk: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Extract HTTP-specific metadata"""
        logs = chunk.get('logs', [])
        
        http_metadata = {
            'methods': [],
            'status_codes': [],
            'status_categories': [],
            'endpoints': [],
            'user_agents': []
        }
        
        for log in logs:
            if log.get('log_type') == 'http':
                # HTTP method
                if log.get('http_method'):
                    http_metadata['methods'].append(log['http_method'])
                
                # Status code
                if log.get('http_status'):
                    status = log['http_status']
                    http_metadata['status_codes'].append(status)
                    
                    # Categorize status
                    for category, status_range in self.HTTP_STATUS_CATEGORIES.items():
                        if status in status_range:
                            http_metadata['status_categories'].append(category)
                            break
                
                # Extract endpoint from message
                endpoint = self._extract_endpoint(log.get('message', ''))
                if endpoint:
                    http_metadata['endpoints'].append(endpoint)
        
        # Get unique values and counts
        http_metadata['methods'] = list(set(http_metadata['methods']))
        http_metadata['status_codes'] = list(set(http_metadata['status_codes']))
        http_metadata['status_categories'] = list(set(http_metadata['status_categories']))
        http_metadata['endpoints'] = list(set(http_metadata['endpoints']))
        
        return http_metadata
    
    def extract_network_metadata(
        self,
        chunk: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Extract network-related metadata"""
        logs = chunk.get('logs', [])
        metadata = chunk.get('metadata', {})
        
        network_metadata = {
            'unique_source_ips': len(metadata.get('source_ips', [])),
            'unique_dest_ips': len(metadata.get('destination_ips', [])),
            'ip_diversity': 0,
            'geographic_indicators': []
        }
        
        # Calculate IP diversity (simple metric)
        total_ips = network_metadata['unique_source_ips'] + network_metadata['unique_dest_ips']
        if total_ips > 0:
            network_metadata['ip_diversity'] = total_ips / len(logs) if logs else 0
        
        # Check for private vs public IPs
        source_ips = metadata.get('source_ips', [])
        private_ips = [ip for ip in source_ips if self._is_private_ip(ip)]
        public_ips = [ip for ip in source_ips if not self._is_private_ip(ip)]
        
        network_metadata['private_ip_count'] = len(private_ips)
        network_metadata['public_ip_count'] = len(public_ips)
        
        return network_metadata
    
    def extract_temporal_metadata(
        self,
        chunk: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Extract time-based metadata"""
        metadata = chunk.get('metadata', {})
        time_range = metadata.get('time_range', {})
        
        temporal_metadata = {
            'duration_seconds': 0,
            'time_of_day': None,
            'is_business_hours': False,
            'is_weekend': False
        }
        
        if time_range and time_range.get('start') and time_range.get('end'):
            try:
                from datetime import datetime
                start = datetime.fromisoformat(time_range['start'].replace('Z', '+00:00'))
                end = datetime.fromisoformat(time_range['end'].replace('Z', '+00:00'))
                
                # Duration
                duration = (end - start).total_seconds()
                temporal_metadata['duration_seconds'] = duration
                
                # Time of day
                hour = start.hour
                if 6 <= hour < 12:
                    temporal_metadata['time_of_day'] = 'morning'
                elif 12 <= hour < 18:
                    temporal_metadata['time_of_day'] = 'afternoon'
                elif 18 <= hour < 22:
                    temporal_metadata['time_of_day'] = 'evening'
                else:
                    temporal_metadata['time_of_day'] = 'night'
                
                # Business hours (9 AM - 5 PM, Mon-Fri)
                temporal_metadata['is_business_hours'] = (
                    9 <= hour < 17 and start.weekday() < 5
                )
                
                # Weekend
                temporal_metadata['is_weekend'] = start.weekday() >= 5
                
            except:
                pass
        
        return temporal_metadata
    
    def enrich_chunk(
        self,
        chunk: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Enrich chunk with all metadata
        
        Adds:
        - Security indicators
        - HTTP metadata (if applicable)
        - Network metadata
        - Temporal metadata
        
        Preserves existing metadata fields
        """
        enriched = chunk.copy()
        
        # Preserve existing metadata
        existing_metadata = enriched.get('metadata', {}).copy()
        
        # Extract all metadata types
        security = self.extract_security_indicators(chunk)
        http = self.extract_http_metadata(chunk)
        network = self.extract_network_metadata(chunk)
        temporal = self.extract_temporal_metadata(chunk)
        
        # Merge with existing metadata (preserve original fields)
        enriched['metadata'] = {
            **existing_metadata,  # Keep original fields
            'security': security,
            'http': http,
            'network': network,
            'temporal': temporal
        }
        
        return enriched
    
    def _extract_endpoint(self, message: str) -> str:
        """Extract HTTP endpoint from message"""
        # Pattern: "METHOD /endpoint HTTP/version"
        pattern = r'(GET|POST|PUT|DELETE|PATCH)\s+([^\s]+)\s+HTTP'
        match = re.search(pattern, message)
        return match.group(2) if match else None
    
    def _extract_unusual_ports(self, text: str) -> List[int]:
        """Extract unusual port numbers"""
        # Common unusual ports
        unusual_ports = []
        port_pattern = r':(\d{4,5})\b'
        matches = re.findall(port_pattern, text)
        
        for port_str in matches:
            port = int(port_str)
            # Ports outside common ranges
            if port > 1024 and port not in [8080, 8443, 3000, 5000]:
                unusual_ports.append(port)
        
        return unusual_ports
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private"""
        if not ip:
            return False
        
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            
            first = int(parts[0])
            second = int(parts[1])
            
            # Private IP ranges
            if first == 10:
                return True
            if first == 172 and 16 <= second <= 31:
                return True
            if first == 192 and second == 168:
                return True
            if first == 127:  # Localhost
                return True
            
            return False
        except:
            return False
