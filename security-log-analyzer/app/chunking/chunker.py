"""
Semantic Chunking Module
Groups logs into chunks with metadata for efficient embedding and retrieval
"""
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict


class LogChunker:
    """Chunks logs semantically with metadata"""
    
    def __init__(
        self,
        chunk_size: int = 500,
        time_window_minutes: int = 5,
        max_logs_per_chunk: int = 10
    ):
        """
        Initialize chunker
        
        Args:
            chunk_size: Target character size for chunks
            time_window_minutes: Time window for grouping logs
            max_logs_per_chunk: Maximum logs per chunk
        """
        self.chunk_size = chunk_size
        self.time_window_minutes = time_window_minutes
        self.max_logs_per_chunk = max_logs_per_chunk
    
    def chunk_by_time_window(
        self,
        logs: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Chunk logs by time window
        Groups logs that occur within the same time window
        """
        if not logs:
            return []
        
        # Sort logs by timestamp
        sorted_logs = sorted(logs, key=lambda x: x.get('timestamp', ''))
        
        chunks = []
        current_chunk_logs = []
        current_window_start = None
        
        for log in sorted_logs:
            timestamp_str = log.get('timestamp', '')
            
            try:
                log_time = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            except:
                # If timestamp parsing fails, add to current chunk
                current_chunk_logs.append(log)
                continue
            
            # Start new window if needed
            if current_window_start is None:
                current_window_start = log_time
                current_chunk_logs = [log]
            else:
                time_diff = (log_time - current_window_start).total_seconds() / 60
                
                # Check if log fits in current window
                if time_diff <= self.time_window_minutes and len(current_chunk_logs) < self.max_logs_per_chunk:
                    current_chunk_logs.append(log)
                else:
                    # Create chunk from current logs
                    if current_chunk_logs:
                        chunk = self._create_chunk(current_chunk_logs)
                        chunks.append(chunk)
                    
                    # Start new window
                    current_window_start = log_time
                    current_chunk_logs = [log]
        
        # Add final chunk
        if current_chunk_logs:
            chunk = self._create_chunk(current_chunk_logs)
            chunks.append(chunk)
        
        return chunks
    
    def chunk_by_log_type(
        self,
        logs: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Chunk logs by log type
        Groups logs of the same type together
        """
        if not logs:
            return []
        
        # Group by log type
        type_groups = defaultdict(list)
        for log in logs:
            log_type = log.get('log_type', 'custom')
            type_groups[log_type].append(log)
        
        chunks = []
        
        # Create chunks for each type
        for log_type, type_logs in type_groups.items():
            # Further chunk by time window within each type
            type_chunks = self.chunk_by_time_window(type_logs)
            chunks.extend(type_chunks)
        
        return chunks
    
    def chunk_by_severity(
        self,
        logs: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Chunk logs by severity level
        Groups logs of similar severity together
        """
        if not logs:
            return []
        
        # Group by severity
        severity_groups = defaultdict(list)
        for log in logs:
            severity = log.get('severity', 'low')
            severity_groups[severity].append(log)
        
        chunks = []
        
        # Create chunks for each severity
        for severity, severity_logs in severity_groups.items():
            # Further chunk by time window within each severity
            severity_chunks = self.chunk_by_time_window(severity_logs)
            chunks.extend(severity_chunks)
        
        return chunks
    
    def chunk_by_source_ip(
        self,
        logs: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Chunk logs by source IP
        Groups logs from the same source together
        """
        if not logs:
            return []
        
        # Group by source IP
        ip_groups = defaultdict(list)
        for log in logs:
            source_ip = log.get('source_ip', 'unknown')
            ip_groups[source_ip].append(log)
        
        chunks = []
        
        # Create chunks for each IP
        for source_ip, ip_logs in ip_groups.items():
            # Further chunk by time window within each IP
            ip_chunks = self.chunk_by_time_window(ip_logs)
            chunks.extend(ip_chunks)
        
        return chunks
    
    def chunk_adaptive(
        self,
        logs: List[Dict[str, Any]],
        strategy: str = 'time'
    ) -> List[Dict[str, Any]]:
        """
        Adaptive chunking based on strategy
        
        Args:
            logs: List of normalized logs
            strategy: Chunking strategy ('time', 'type', 'severity', 'ip', 'hybrid')
        """
        if strategy == 'time':
            return self.chunk_by_time_window(logs)
        elif strategy == 'type':
            return self.chunk_by_log_type(logs)
        elif strategy == 'severity':
            return self.chunk_by_severity(logs)
        elif strategy == 'ip':
            return self.chunk_by_source_ip(logs)
        elif strategy == 'hybrid':
            # Hybrid: group by type first, then by time
            return self.chunk_by_log_type(logs)
        else:
            # Default to time-based
            return self.chunk_by_time_window(logs)
    
    def _create_chunk(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Create a chunk with metadata from logs
        
        Returns chunk with:
        - text: Combined log messages
        - metadata: Aggregated metadata
        - logs: Original log entries
        """
        if not logs:
            return {}
        
        # Combine messages
        messages = [log.get('message', '') for log in logs]
        combined_text = ' | '.join(messages)
        
        # Truncate if too long
        if len(combined_text) > self.chunk_size:
            combined_text = combined_text[:self.chunk_size] + '...'
        
        # Extract metadata
        metadata = self._extract_metadata(logs)
        
        return {
            'text': combined_text,
            'metadata': metadata,
            'logs': logs,
            'chunk_size': len(combined_text),
            'log_count': len(logs)
        }
    
    def _extract_metadata(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract aggregated metadata from logs"""
        if not logs:
            return {}
        
        # Collect unique values
        source_ips = set()
        dest_ips = set()
        log_types = set()
        severities = set()
        timestamps = []
        occurrence_counts = []
        
        for log in logs:
            if log.get('source_ip'):
                source_ips.add(log['source_ip'])
            if log.get('destination_ip'):
                dest_ips.add(log['destination_ip'])
            if log.get('log_type'):
                log_types.add(log['log_type'])
            if log.get('severity'):
                severities.add(log['severity'])
            if log.get('timestamp'):
                timestamps.append(log['timestamp'])
            if log.get('occurrence_count'):
                occurrence_counts.append(log['occurrence_count'])
        
        # Determine time range
        time_range = None
        if timestamps:
            timestamps.sort()
            time_range = {
                'start': timestamps[0],
                'end': timestamps[-1]
            }
        
        # Determine dominant severity
        severity_priority = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
        dominant_severity = max(severities, key=lambda s: severity_priority.get(s, 0)) if severities else 'info'
        
        # Calculate total occurrences
        total_occurrences = sum(occurrence_counts) if occurrence_counts else len(logs)
        max_occurrence = max(occurrence_counts) if occurrence_counts else 1
        
        return {
            'source_ips': list(source_ips),
            'destination_ips': list(dest_ips),
            'log_types': list(log_types),
            'severities': list(severities),
            'dominant_severity': dominant_severity,
            'time_range': time_range,
            'log_count': len(logs),
            'total_occurrences': total_occurrences,
            'max_occurrence_count': max_occurrence,
            'has_critical': 'critical' in severities,
            'has_high': 'high' in severities,
            'occurrence_count': max_occurrence  # For backward compatibility
        }
    
    def get_chunk_stats(self, chunks: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get statistics about chunks"""
        if not chunks:
            return {
                'total_chunks': 0,
                'total_logs': 0,
                'avg_logs_per_chunk': 0,
                'avg_chunk_size': 0
            }
        
        total_logs = sum(chunk.get('log_count', 0) for chunk in chunks)
        total_size = sum(chunk.get('chunk_size', 0) for chunk in chunks)
        
        return {
            'total_chunks': len(chunks),
            'total_logs': total_logs,
            'avg_logs_per_chunk': total_logs / len(chunks) if chunks else 0,
            'avg_chunk_size': total_size / len(chunks) if chunks else 0,
            'min_logs_per_chunk': min(chunk.get('log_count', 0) for chunk in chunks),
            'max_logs_per_chunk': max(chunk.get('log_count', 0) for chunk in chunks)
        }
