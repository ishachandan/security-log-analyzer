"""
Test suite for LLM analysis
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.llm.analyzer import LogAnalyzer


class TestLogAnalyzer:
    """Test LLM log analyzer"""
    
    def test_initialization(self):
        analyzer = LogAnalyzer()
        
        assert analyzer.model_name == "phi"
        assert analyzer.base_url == "http://localhost:11434"
        print("✅ Analyzer initialization test passed")
    
    def test_analyze_logs(self):
        analyzer = LogAnalyzer()
        
        query = "failed login attempts"
        logs = [
            {
                'text': 'Failed login attempt from 192.168.1.100',
                'metadata': {'severity': 'high', 'log_type': 'auth'}
            },
            {
                'text': 'Failed login attempt from 192.168.1.100',
                'metadata': {'severity': 'high', 'log_type': 'auth'}
            },
            {
                'text': 'Failed login attempt from 192.168.1.100',
                'metadata': {'severity': 'high', 'log_type': 'auth'}
            }
        ]
        
        result = analyzer.analyze_logs(query, logs)
        
        assert 'summary' in result
        assert 'threat_detected' in result
        assert 'severity' in result
        assert 'supporting_logs' in result
        assert 'recommendations' in result
        assert isinstance(result['threat_detected'], bool)
        print("✅ Analyze logs test passed")
    
    def test_analyze_empty_logs(self):
        analyzer = LogAnalyzer()
        
        result = analyzer.analyze_logs("test query", [])
        
        assert result['summary'] == 'No logs found matching the query.'
        assert result['threat_detected'] is False
        print("✅ Empty logs analysis test passed")
    
    def test_detect_anomalies(self):
        analyzer = LogAnalyzer()
        
        logs = [
            {
                'text': 'Unusual port scan detected',
                'metadata': {'severity': 'high'}
            },
            {
                'text': 'Multiple failed login attempts',
                'metadata': {'severity': 'high'}
            }
        ]
        
        result = analyzer.detect_anomalies(logs)
        
        assert 'anomalies_detected' in result
        assert 'anomaly_count' in result
        assert 'analysis' in result
        assert isinstance(result['anomalies_detected'], bool)
        print("✅ Anomaly detection test passed")
    
    def test_classify_threat(self):
        analyzer = LogAnalyzer()
        
        log_text = "Failed login attempt from 192.168.1.100"
        metadata = {'severity': 'high'}
        
        result = analyzer.classify_threat(log_text, metadata)
        
        assert 'threat_level' in result
        assert 'reasoning' in result
        assert result['threat_level'] in ['critical', 'high', 'medium', 'low']
        print("✅ Threat classification test passed")
    
    def test_generate_summary(self):
        analyzer = LogAnalyzer()
        
        logs = [
            {
                'text': 'System startup completed',
                'metadata': {'severity': 'info'}
            },
            {
                'text': 'Service started successfully',
                'metadata': {'severity': 'info'}
            }
        ]
        
        summary = analyzer.generate_summary(logs, focus="system")
        
        assert isinstance(summary, str)
        assert len(summary) > 0
        print("✅ Summary generation test passed")
    
    def test_prepare_context(self):
        analyzer = LogAnalyzer()
        
        logs = [
            {
                'text': 'Log entry 1',
                'metadata': {'severity': 'high'}
            },
            {
                'text': 'Log entry 2',
                'metadata': {'severity': 'low'}
            }
        ]
        
        context = analyzer._prepare_context(logs, max_length=500)
        
        assert isinstance(context, str)
        assert 'Log 1' in context
        assert 'Log 2' in context
        print("✅ Context preparation test passed")
    
    def test_parse_analysis(self):
        analyzer = LogAnalyzer()
        
        response = "HIGH severity threat detected. Multiple failed login attempts indicate potential brute force attack. Recommend blocking source IP."
        logs = [{'text': 'Failed login', 'metadata': {}}]
        
        result = analyzer._parse_analysis(response, logs)
        
        assert result['threat_detected'] is True
        assert result['severity'] == 'high'
        assert len(result['supporting_logs']) > 0
        print("✅ Analysis parsing test passed")


def run_all_tests():
    """Run all LLM tests"""
    print("\n" + "="*60)
    print("🧪 STEP 7 VERIFICATION - LLM Analysis Tests")
    print("="*60 + "\n")
    
    print("📝 Testing LogAnalyzer...")
    analyzer_tests = TestLogAnalyzer()
    analyzer_tests.test_initialization()
    analyzer_tests.test_analyze_logs()
    analyzer_tests.test_analyze_empty_logs()
    analyzer_tests.test_detect_anomalies()
    analyzer_tests.test_classify_threat()
    analyzer_tests.test_generate_summary()
    analyzer_tests.test_prepare_context()
    analyzer_tests.test_parse_analysis()
    
    print("\n" + "="*60)
    print("✅ ALL TESTS PASSED!")
    print("="*60)


if __name__ == "__main__":
    run_all_tests()
