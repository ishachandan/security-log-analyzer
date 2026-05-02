"""
Log Ingestion Engine
Main orchestrator for log parsing, normalization, and deduplication
"""
from typing import List, Dict, Any, Optional
from .parsers import (
    JSONParser, SyslogParser, CSVParser,
    ApacheParser, NginxParser
)
from .normalizer import LogNormalizer
from .deduplicator import LogDeduplicator


class IngestionEngine:
    """Main log ingestion engine"""
    
    def __init__(self):
        """Initialize ingestion engine with parsers"""
        self.parsers = {
            'json': JSONParser(),
            'syslog': SyslogParser(),
            'csv': CSVParser(),
            'apache': ApacheParser(),
            'nginx': NginxParser(),
        }
        
        self.normalizer = LogNormalizer()
        self.deduplicator = LogDeduplicator()
        
        self.stats = {
            'total_processed': 0,
            'successful': 0,
            'failed': 0,
            'duplicates': 0,
        }
    
    def ingest(
        self,
        logs: List[Any],  # Can be strings or dicts
        log_format: str = 'auto'
    ) -> Dict[str, Any]:
        """
        Ingest and process log entries
        
        Args:
            logs: List of log lines (strings) or log objects (dicts) to process
            log_format: Format of logs ('json', 'syslog', 'csv', 'apache', 'nginx', 'auto')
            
        Returns:
            Dictionary with processed logs and statistics
        """
        processed_logs = []
        failed_logs = []
        duplicate_count = 0
        
        for log_entry in logs:
            self.stats['total_processed'] += 1
            
            try:
                # Handle dict input (structured JSON objects)
                if isinstance(log_entry, dict):
                    # Already a dict, just normalize it
                    normalized = self.normalizer.normalize(log_entry)
                else:
                    # String input - parse it
                    if log_format == 'auto':
                        parsed = self._auto_parse(log_entry)
                    else:
                        parser = self.parsers.get(log_format)
                        if not parser:
                            raise ValueError(f"Unsupported format: {log_format}")
                        parsed = parser.parse(log_entry)
                    
                    if not parsed:
                        failed_logs.append({
                            'line': str(log_entry),
                            'error': 'Failed to parse'
                        })
                        self.stats['failed'] += 1
                        continue
                    
                    # Normalize
                    normalized = self.normalizer.normalize(parsed)
                
                # Validate
                if not self.normalizer.validate(normalized):
                    failed_logs.append({
                        'line': str(log_entry),
                        'error': 'Validation failed'
                    })
                    self.stats['failed'] += 1
                    continue
                
                # Track frequency (don't remove duplicates)
                count = self.deduplicator.track_and_get_count(normalized)
                
                # Add count metadata
                normalized['occurrence_count'] = count
                
                # Track if this is a duplicate for stats
                if count > 1:
                    duplicate_count += 1
                    self.stats['duplicates'] += 1
                
                # Add to processed logs (always add, even if duplicate)
                processed_logs.append(normalized)
                self.stats['successful'] += 1
                
            except Exception as e:
                failed_logs.append({
                    'line': str(log_entry),
                    'error': str(e)
                })
                self.stats['failed'] += 1
        
        return {
            'status': 'success',
            'processed': len(processed_logs),
            'failed': len(failed_logs),
            'duplicates': duplicate_count,
            'logs': processed_logs,
            'errors': failed_logs if failed_logs else None
        }
    
    def _auto_parse(self, log_line: str) -> Optional[Dict[str, Any]]:
        """
        Auto-detect log format and parse
        
        Tries parsers in order: JSON, Syslog, Apache, CSV
        
        Args:
            log_line: String log line to parse
        """
        # Ensure we have a string
        if not isinstance(log_line, str):
            return None
        
        log_line = log_line.strip()
        
        if not log_line:
            return None
        
        # Try JSON first (most structured)
        if log_line.startswith('{'):
            result = self.parsers['json'].parse(log_line)
            if result:
                return result
        
        # Try Syslog pattern
        result = self.parsers['syslog'].parse(log_line)
        if result:
            return result
        
        # Try Apache/Nginx pattern
        result = self.parsers['apache'].parse(log_line)
        if result:
            return result
        
        # Try CSV as last resort
        result = self.parsers['csv'].parse(log_line)
        if result:
            return result
        
        return None
    
    def ingest_file(self, file_path: str, log_format: str = 'auto') -> Dict[str, Any]:
        """
        Ingest logs from a file
        
        Args:
            file_path: Path to log file
            log_format: Format of logs
            
        Returns:
            Ingestion results
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                logs = [line.strip() for line in f if line.strip()]
            
            return self.ingest(logs, log_format)
            
        except Exception as e:
            return {
                'status': 'error',
                'message': f"Failed to read file: {str(e)}",
                'processed': 0,
                'failed': 0,
                'duplicates': 0,
                'logs': [],
                'errors': [{'error': str(e)}]
            }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get ingestion statistics"""
        return {
            **self.stats,
            'deduplication': self.deduplicator.get_stats()
        }
    
    def reset_stats(self):
        """Reset statistics counters"""
        self.stats = {
            'total_processed': 0,
            'successful': 0,
            'failed': 0,
            'duplicates': 0,
        }
        self.deduplicator.clear()
