"""
Log Deduplication Module
Tracks frequency of duplicate log entries instead of removing them
"""
import hashlib
from typing import Dict, Any, Tuple
from datetime import datetime, timedelta


class LogDeduplicator:
    """Tracks frequency of log entries for attack detection"""
    
    def __init__(self, window_minutes: int = 5, max_cache_size: int = 10000):
        """
        Initialize deduplicator
        
        Args:
            window_minutes: Time window for frequency tracking (default 5 minutes)
            max_cache_size: Maximum number of hashes to keep in memory
        """
        self.window_minutes = window_minutes
        self.max_cache_size = max_cache_size
        # Store: hash -> (count, first_seen, last_seen)
        self.frequency_map: Dict[str, Tuple[int, datetime, datetime]] = {}
    
    def track_and_get_count(self, log_entry: Dict[str, Any]) -> int:
        """
        Track log entry and return its frequency count
        
        Args:
            log_entry: Normalized log entry
            
        Returns:
            Count of how many times this log has been seen in the time window
        """
        # Generate hash for this log entry
        log_hash = self.generate_hash(log_entry)
        
        # Clean old entries
        self._clean_old_entries()
        
        current_time = datetime.utcnow()
        
        # Check if we've seen this hash recently
        if log_hash in self.frequency_map:
            count, first_seen, _ = self.frequency_map[log_hash]
            new_count = count + 1
            self.frequency_map[log_hash] = (new_count, first_seen, current_time)
            return new_count
        else:
            # First time seeing this log
            self.frequency_map[log_hash] = (1, current_time, current_time)
            
            # Enforce max cache size
            if len(self.frequency_map) > self.max_cache_size:
                self._trim_cache()
            
            return 1
    
    def is_duplicate(self, log_entry: Dict[str, Any]) -> bool:
        """
        DEPRECATED: Now we track frequency instead of blocking duplicates
        Returns False to allow all logs through
        """
        # Track the log but don't block it
        self.track_and_get_count(log_entry)
        return False  # Never block duplicates
    
    def generate_hash(self, log_entry: Dict[str, Any]) -> str:
        """
        Generate unique hash for log entry
        
        Uses timestamp, message, source_ip, and log_type for uniqueness
        """
        hash_components = [
            str(log_entry.get('timestamp', '')),
            str(log_entry.get('message', '')),
            str(log_entry.get('source_ip', '')),
            str(log_entry.get('log_type', '')),
        ]
        
        hash_string = '|'.join(hash_components)
        return hashlib.sha256(hash_string.encode()).hexdigest()
    
    def _clean_old_entries(self):
        """Remove entries older than the time window"""
        cutoff_time = datetime.utcnow() - timedelta(minutes=self.window_minutes)
        
        # Remove old entries
        self.frequency_map = {
            hash_val: (count, first_seen, last_seen)
            for hash_val, (count, first_seen, last_seen) in self.frequency_map.items()
            if last_seen > cutoff_time
        }
    
    def _trim_cache(self):
        """Trim cache to max size by removing oldest entries"""
        if len(self.frequency_map) <= self.max_cache_size:
            return
        
        # Sort by last_seen timestamp and keep only the most recent
        sorted_entries = sorted(
            self.frequency_map.items(),
            key=lambda x: x[1][2],  # Sort by last_seen (index 2)
            reverse=True
        )
        
        self.frequency_map = dict(sorted_entries[:self.max_cache_size])
    
    def clear(self):
        """Clear all cached hashes"""
        self.frequency_map.clear()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get deduplication statistics"""
        total_logs = sum(count for count, _, _ in self.frequency_map.values())
        unique_logs = len(self.frequency_map)
        
        return {
            'unique_patterns': unique_logs,
            'total_occurrences': total_logs,
            'max_cache_size': self.max_cache_size,
            'window_minutes': self.window_minutes,
        }
