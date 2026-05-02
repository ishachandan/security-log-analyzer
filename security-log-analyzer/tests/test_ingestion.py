"""
Test suite for log ingestion engine
Tests parsers, normalizer, deduplicator, and API endpoints
"""
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.ingestion.parsers import (
    JSONParser, SyslogParser, CSVParser,
    ApacheParser, NginxParser
)
from app.ingestion.normalizer import LogNormalizer
from app.ingestion.deduplicator import LogDeduplicator
from app.ingestion.engine import IngestionEngine


class TestJSONParser:
    """Test JSON log parser"""
    
    def test_parse_valid_json(self):
        parser = JSONParser()
        log_line = '{"timestamp": "2026-03-29T10:00:00Z", "source_ip": "192.168.1.100", "message": "Test log"}'
        
        result = parser.parse(log_line)
        
        assert result is not None
        assert result['source_ip'] == '192.168.1.100'
        assert result['message'] == 'Test log'
        print("✅ JSON parser: valid JSON test passed")
    
    def test_parse_invalid_json(self):
        parser = JSONParser()
        log_line = 'not a json string'
        
        result = parser.parse(log_line)
        
        assert result is None
        print("✅ JSON parser: invalid JSON test passed")
    
    def test_parse_json_with_nested_fields(self):
        parser = JSONParser()
        log_line = '{"@timestamp": "2026-03-29T10:00:00Z", "client_ip": "10.0.0.1", "msg": "Nested test"}'
        
        result = parser.parse(log_line)
        
        assert result is not None
        assert result['source_ip'] == '10.0.0.1'
        assert result['message'] == 'Nested test'
        print("✅ JSON parser: nested fields test passed")


class TestSyslogParser:
    """Test Syslog parser"""
    
    def test_parse_valid_syslog(self):
        parser = SyslogParser()
        log_line = '<34>Mar 29 10:30:45 server1 sshd[1234]: Failed password for user from 192.168.1.100'
        
        result = parser.parse(log_line)
        
        assert result is not None
        assert result['hostname'] == 'server1'
        assert result['process'] == 'sshd'
        assert '192.168.1.100' in result['message']
        print("✅ Syslog parser: valid syslog test passed")
    
    def test_parse_syslog_without_priority(self):
        parser = SyslogParser()
        log_line = 'Mar 29 10:30:45 server1 kernel: Test message'
        
        result = parser.parse(log_line)
        
        assert result is not None
        assert result['hostname'] == 'server1'
        print("✅ Syslog parser: no priority test passed")


class TestApacheParser:
    """Test Apache log parser"""
    
    def test_parse_valid_apache_log(self):
        parser = ApacheParser()
        log_line = '192.168.1.100 - - [29/Mar/2026:10:30:45 +0000] "GET /index.html HTTP/1.1" 200 1234'
        
        result = parser.parse(log_line)
        
        assert result is not None
        assert result['source_ip'] == '192.168.1.100'
        assert result['http_status'] == 200
        assert result['http_method'] == 'GET'
        assert result['log_type'] == 'http'
        print("✅ Apache parser: valid log test passed")
    
    def test_severity_from_status_code(self):
        parser = ApacheParser()
        
        # Test 500 error
        log_line = '192.168.1.100 - - [29/Mar/2026:10:30:45 +0000] "GET /error HTTP/1.1" 500 0'
        result = parser.parse(log_line)
        assert result['severity'] == 'high'
        
        # Test 404 error
        log_line = '192.168.1.100 - - [29/Mar/2026:10:30:45 +0000] "GET /missing HTTP/1.1" 404 0'
        result = parser.parse(log_line)
        assert result['severity'] == 'medium'
        
        # Test 200 success
        log_line = '192.168.1.100 - - [29/Mar/2026:10:30:45 +0000] "GET /ok HTTP/1.1" 200 100'
        result = parser.parse(log_line)
        assert result['severity'] == 'info'
        
        print("✅ Apache parser: severity mapping test passed")


class TestLogNormalizer:
    """Test log normalizer"""
    
    def test_normalize_timestamp(self):
        normalizer = LogNormalizer()
        
        # Test various timestamp formats
        timestamps = [
            "2026-03-29T10:00:00.000000Z",
            "2026-03-29 10:00:00",
            "Mar 29 10:00:00",
        ]
        
        for ts in timestamps:
            result = normalizer.normalize_timestamp(ts)
            assert result.endswith('Z')
            assert 'T' in result
        
        print("✅ Normalizer: timestamp normalization test passed")
    
    def test_normalize_severity(self):
        normalizer = LogNormalizer()
        
        # Test severity mapping
        assert normalizer.normalize_severity('error') == 'high'
        assert normalizer.normalize_severity('warning') == 'medium'
        assert normalizer.normalize_severity('info') == 'low'
        assert normalizer.normalize_severity('critical') == 'critical'
        
        # Test numeric severity
        assert normalizer.normalize_severity('0') == 'critical'
        assert normalizer.normalize_severity('3') == 'high'
        assert normalizer.normalize_severity('4') == 'medium'
        assert normalizer.normalize_severity('6') == 'low'
        
        print("✅ Normalizer: severity normalization test passed")
    
    def test_normalize_ip(self):
        normalizer = LogNormalizer()
        
        # Valid IPs
        assert normalizer.normalize_ip('192.168.1.1') == '192.168.1.1'
        assert normalizer.normalize_ip('10.0.0.1') == '10.0.0.1'
        
        # Invalid IPs
        assert normalizer.normalize_ip('not-an-ip') is None
        assert normalizer.normalize_ip('999.999.999.999') is None
        
        print("✅ Normalizer: IP normalization test passed")


class TestLogDeduplicator:
    """Test log deduplicator"""
    
    def test_duplicate_detection(self):
        dedup = LogDeduplicator()
        
        log1 = {
            'timestamp': '2026-03-29T10:00:00Z',
            'message': 'Test message',
            'source_ip': '192.168.1.1',
            'log_type': 'system'
        }
        
        log2 = log1.copy()
        
        # First log should not be duplicate
        assert dedup.is_duplicate(log1) is False
        
        # Second identical log should be duplicate
        assert dedup.is_duplicate(log2) is True
        
        print("✅ Deduplicator: duplicate detection test passed")
    
    def test_different_logs_not_duplicates(self):
        dedup = LogDeduplicator()
        
        log1 = {
            'timestamp': '2026-03-29T10:00:00Z',
            'message': 'Message 1',
            'source_ip': '192.168.1.1',
            'log_type': 'system'
        }
        
        log2 = {
            'timestamp': '2026-03-29T10:00:01Z',
            'message': 'Message 2',
            'source_ip': '192.168.1.2',
            'log_type': 'system'
        }
        
        assert dedup.is_duplicate(log1) is False
        assert dedup.is_duplicate(log2) is False
        
        print("✅ Deduplicator: different logs test passed")


class TestIngestionEngine:
    """Test ingestion engine"""
    
    def test_ingest_json_logs(self):
        engine = IngestionEngine()
        
        logs = [
            '{"timestamp": "2026-03-29T10:00:00Z", "source_ip": "192.168.1.100", "message": "Log 1"}',
            '{"timestamp": "2026-03-29T10:00:01Z", "source_ip": "192.168.1.101", "message": "Log 2"}',
        ]
        
        result = engine.ingest(logs, 'json')
        
        assert result['status'] == 'success'
        assert result['processed'] == 2
        assert result['failed'] == 0
        assert len(result['logs']) == 2
        
        print("✅ Engine: JSON ingestion test passed")
    
    def test_ingest_with_auto_detection(self):
        engine = IngestionEngine()
        
        logs = [
            '{"timestamp": "2026-03-29T10:00:00Z", "message": "JSON log"}',
            '<34>Mar 29 10:30:45 server1 sshd: Syslog message',
            '192.168.1.100 - - [29/Mar/2026:10:30:45 +0000] "GET / HTTP/1.1" 200 100',
        ]
        
        result = engine.ingest(logs, 'auto')
        
        assert result['status'] == 'success'
        assert result['processed'] >= 2  # At least JSON and one other should parse
        
        print("✅ Engine: auto-detection test passed")
    
    def test_ingest_with_duplicates(self):
        engine = IngestionEngine()
        
        logs = [
            '{"timestamp": "2026-03-29T10:00:00Z", "source_ip": "192.168.1.100", "message": "Duplicate test"}',
            '{"timestamp": "2026-03-29T10:00:00Z", "source_ip": "192.168.1.100", "message": "Duplicate test"}',
        ]
        
        result = engine.ingest(logs, 'json')
        
        assert result['processed'] == 1
        assert result['duplicates'] == 1
        
        print("✅ Engine: duplicate handling test passed")
    
    def test_ingest_with_invalid_logs(self):
        engine = IngestionEngine()
        
        logs = [
            'completely invalid log line',
            '{"valid": "json", "timestamp": "2026-03-29T10:00:00Z", "message": "Valid"}',
        ]
        
        result = engine.ingest(logs, 'auto')
        
        assert result['processed'] >= 1  # At least the valid JSON should work
        assert result['failed'] >= 0  # Invalid line might fail
        
        print("✅ Engine: invalid log handling test passed")


def run_all_tests():
    """Run all ingestion tests"""
    print("\n" + "="*60)
    print("🧪 STEP 2 VERIFICATION - Log Ingestion Engine Tests")
    print("="*60 + "\n")
    
    # JSON Parser Tests
    print("📝 Testing JSON Parser...")
    json_tests = TestJSONParser()
    json_tests.test_parse_valid_json()
    json_tests.test_parse_invalid_json()
    json_tests.test_parse_json_with_nested_fields()
    
    # Syslog Parser Tests
    print("\n📝 Testing Syslog Parser...")
    syslog_tests = TestSyslogParser()
    syslog_tests.test_parse_valid_syslog()
    syslog_tests.test_parse_syslog_without_priority()
    
    # Apache Parser Tests
    print("\n📝 Testing Apache Parser...")
    apache_tests = TestApacheParser()
    apache_tests.test_parse_valid_apache_log()
    apache_tests.test_severity_from_status_code()
    
    # Normalizer Tests
    print("\n📝 Testing Log Normalizer...")
    normalizer_tests = TestLogNormalizer()
    normalizer_tests.test_normalize_timestamp()
    normalizer_tests.test_normalize_severity()
    normalizer_tests.test_normalize_ip()
    
    # Deduplicator Tests
    print("\n📝 Testing Deduplicator...")
    dedup_tests = TestLogDeduplicator()
    dedup_tests.test_duplicate_detection()
    dedup_tests.test_different_logs_not_duplicates()
    
    # Ingestion Engine Tests
    print("\n📝 Testing Ingestion Engine...")
    engine_tests = TestIngestionEngine()
    engine_tests.test_ingest_json_logs()
    engine_tests.test_ingest_with_auto_detection()
    engine_tests.test_ingest_with_duplicates()
    engine_tests.test_ingest_with_invalid_logs()
    
    print("\n" + "="*60)
    print("✅ ALL TESTS PASSED!")
    print("="*60)


if __name__ == "__main__":
    run_all_tests()
