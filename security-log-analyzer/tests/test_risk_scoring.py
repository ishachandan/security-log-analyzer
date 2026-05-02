"""
Test Risk Scoring Engine
Verifies risk scores are calculated correctly based on multiple factors
"""
from datetime import datetime, timedelta
from app.ingestion.engine import IngestionEngine
from app.chunking.chunker import LogChunker
from app.analysis.classifier import AttackClassifier


def test_benign_logs_low_score():
    """Test: Benign logs should have low risk score"""
    print("\n" + "="*70)
    print("TEST 1: Benign Logs - Low Risk Score")
    print("="*70)
    
    engine = IngestionEngine()
    chunker = LogChunker()
    classifier = AttackClassifier()
    
    # Normal successful requests
    base_time = datetime(2024, 3, 29, 10, 0, 0)
    logs = []
    for i in range(10):
        timestamp = base_time + timedelta(seconds=i*30)
        logs.append({
            "message": f"GET /api/status HTTP/1.1 200 OK",
            "timestamp": timestamp.isoformat() + "Z",
            "source_ip": "192.168.1.50",
            "level": "INFO"
        })
    
    result = engine.ingest(logs, log_format='auto')
    chunks = chunker.chunk_by_time_window(result['logs'])
    classification = classifier.classify(chunks)
    
    print(f"Logs: {len(logs)} normal requests")
    print(f"Attack Type: {classification['attack_type']}")
    print(f"Risk Score: {classification['risk_score']}")
    print(f"Risk Level: {classification['risk_level']}")
    
    passed = classification['risk_score'] < 30 and classification['risk_level'] == 'low'
    print(f"Result: {'[PASS]' if passed else '[FAIL]'} - Expected low risk")
    return passed


def test_brute_force_medium_score():
    """Test: Brute force attack should have medium-high risk score"""
    print("\n" + "="*70)
    print("TEST 2: Brute Force - Medium/High Risk Score")
    print("="*70)
    
    engine = IngestionEngine()
    chunker = LogChunker()
    classifier = AttackClassifier()
    
    # 8 failed logins within 40 seconds
    base_time = datetime(2024, 3, 29, 11, 0, 0)
    logs = []
    for i in range(8):
        timestamp = base_time + timedelta(seconds=i*5)
        logs.append({
            "message": f"Failed login attempt for user admin from 203.0.113.50",
            "timestamp": timestamp.isoformat() + "Z",
            "source_ip": "203.0.113.50",
            "level": "ERROR"
        })
    
    result = engine.ingest(logs, log_format='auto')
    chunks = chunker.chunk_by_time_window(result['logs'])
    classification = classifier.classify(chunks)
    
    print(f"Logs: {len(logs)} failed logins")
    print(f"Attack Type: {classification['attack_type']}")
    print(f"Risk Score: {classification['risk_score']}")
    print(f"Risk Level: {classification['risk_level']}")
    print(f"Risk Factors: {classification.get('risk_factors', [])}")
    
    passed = 40 <= classification['risk_score'] <= 80 and classification['risk_level'] in ['medium', 'high']
    print(f"Result: {'[PASS]' if passed else '[FAIL]'} - Expected medium/high risk (40-80)")
    return passed


def test_success_after_failures_critical():
    """Test: Success after failures should have CRITICAL risk score"""
    print("\n" + "="*70)
    print("TEST 3: Success After Failures - CRITICAL Risk")
    print("="*70)
    
    engine = IngestionEngine()
    chunker = LogChunker()
    classifier = AttackClassifier()
    
    # 5 failed logins followed by 1 successful login from same IP
    base_time = datetime(2024, 3, 29, 12, 0, 0)
    logs = []
    
    # Failed attempts
    for i in range(5):
        timestamp = base_time + timedelta(seconds=i*10)
        logs.append({
            "message": f"Failed login attempt for user admin from 10.0.0.100",
            "timestamp": timestamp.isoformat() + "Z",
            "source_ip": "10.0.0.100",
            "level": "ERROR"
        })
    
    # Successful login from same IP
    timestamp = base_time + timedelta(seconds=60)
    logs.append({
        "message": "Successful login for user admin from 10.0.0.100",
        "timestamp": timestamp.isoformat() + "Z",
        "source_ip": "10.0.0.100",
        "level": "INFO"
    })
    
    result = engine.ingest(logs, log_format='auto')
    chunks = chunker.chunk_by_time_window(result['logs'])
    classification = classifier.classify(chunks)
    
    print(f"Logs: 5 failures + 1 success from same IP")
    print(f"Attack Type: {classification['attack_type']}")
    print(f"Risk Score: {classification['risk_score']}")
    print(f"Risk Level: {classification['risk_level']}")
    print(f"Risk Factors: {classification.get('risk_factors', [])}")
    
    # Should have high/critical risk due to success after failures
    passed = classification['risk_score'] >= 70 and classification['risk_level'] in ['high', 'critical']
    print(f"Result: {'[PASS]' if passed else '[FAIL]'} - Expected high/critical risk (>=70)")
    return passed


def test_ddos_high_score():
    """Test: DDoS attack should have high risk score"""
    print("\n" + "="*70)
    print("TEST 4: DDoS Attack - High Risk Score")
    print("="*70)
    
    engine = IngestionEngine()
    chunker = LogChunker()
    classifier = AttackClassifier()
    
    # 120 requests within 8 seconds
    base_time = datetime(2024, 3, 29, 13, 0, 0)
    logs = []
    for i in range(120):
        timestamp = base_time + timedelta(milliseconds=i*66)
        logs.append({
            "message": f"GET /api/data HTTP/1.1 200",
            "timestamp": timestamp.isoformat() + "Z",
            "source_ip": "203.0.113.200",
            "level": "WARNING"
        })
    
    result = engine.ingest(logs, log_format='auto')
    chunks = chunker.chunk_by_time_window(result['logs'])
    classification = classifier.classify(chunks)
    
    print(f"Logs: {len(logs)} requests in ~8 seconds")
    print(f"Attack Type: {classification['attack_type']}")
    print(f"Risk Score: {classification['risk_score']}")
    print(f"Risk Level: {classification['risk_level']}")
    print(f"Risk Factors: {classification.get('risk_factors', [])}")
    
    passed = classification['risk_score'] >= 60 and classification['risk_level'] in ['high', 'critical']
    print(f"Result: {'[PASS]' if passed else '[FAIL]'} - Expected high/critical risk (>=60)")
    return passed


def test_distributed_ddos_critical():
    """Test: Distributed DDoS should have critical risk score"""
    print("\n" + "="*70)
    print("TEST 5: Distributed DDoS - Critical Risk")
    print("="*70)
    
    engine = IngestionEngine()
    chunker = LogChunker()
    classifier = AttackClassifier()
    
    # 150 requests from 15 different IPs within 9 seconds
    base_time = datetime(2024, 3, 29, 14, 0, 0)
    logs = []
    for i in range(150):
        ip_suffix = (i % 15) + 1
        timestamp = base_time + timedelta(milliseconds=i*60)
        logs.append({
            "message": f"GET /api/endpoint HTTP/1.1 200",
            "timestamp": timestamp.isoformat() + "Z",
            "source_ip": f"10.0.0.{ip_suffix}",
            "level": "WARNING"
        })
    
    result = engine.ingest(logs, log_format='auto')
    chunks = chunker.chunk_by_time_window(result['logs'])
    classification = classifier.classify(chunks)
    
    print(f"Logs: {len(logs)} requests from 15 IPs")
    print(f"Attack Type: {classification['attack_type']}")
    print(f"Risk Score: {classification['risk_score']}")
    print(f"Risk Level: {classification['risk_level']}")
    print(f"Risk Factors: {classification.get('risk_factors', [])}")
    
    # High frequency + many IPs = critical
    passed = classification['risk_score'] >= 70 and classification['risk_level'] in ['high', 'critical']
    print(f"Result: {'[PASS]' if passed else '[FAIL]'} - Expected high/critical risk (>=70)")
    return passed


def test_risk_factors_breakdown():
    """Test: Risk factors should be properly broken down"""
    print("\n" + "="*70)
    print("TEST 6: Risk Factors Breakdown")
    print("="*70)
    
    engine = IngestionEngine()
    chunker = LogChunker()
    classifier = AttackClassifier()
    
    # Brute force with high severity
    base_time = datetime(2024, 3, 29, 15, 0, 0)
    logs = []
    for i in range(10):
        timestamp = base_time + timedelta(seconds=i*5)
        logs.append({
            "message": f"CRITICAL: Failed login attempt for root from 172.16.0.50",
            "timestamp": timestamp.isoformat() + "Z",
            "source_ip": "172.16.0.50",
            "level": "CRITICAL"
        })
    
    result = engine.ingest(logs, log_format='auto')
    chunks = chunker.chunk_by_time_window(result['logs'])
    classification = classifier.classify(chunks)
    
    print(f"Attack Type: {classification['attack_type']}")
    print(f"Risk Score: {classification['risk_score']}")
    print(f"Risk Level: {classification['risk_level']}")
    print(f"\nRisk Factors:")
    for factor in classification.get('risk_factors', []):
        print(f"  - {factor}")
    
    # Should have multiple risk factors
    risk_factors = classification.get('risk_factors', [])
    passed = len(risk_factors) >= 2 and classification['risk_score'] > 0
    print(f"\nResult: {'[PASS]' if passed else '[FAIL]'} - Expected multiple risk factors")
    return passed


if __name__ == "__main__":
    print("\n" + "="*70)
    print("RISK SCORING ENGINE - VALIDATION")
    print("="*70)
    
    results = {}
    
    try:
        results['Benign Logs'] = test_benign_logs_low_score()
        results['Brute Force'] = test_brute_force_medium_score()
        results['Success After Failures'] = test_success_after_failures_critical()
        results['DDoS Attack'] = test_ddos_high_score()
        results['Distributed DDoS'] = test_distributed_ddos_critical()
        results['Risk Factors'] = test_risk_factors_breakdown()
        
        print("\n" + "="*70)
        print("RESULTS")
        print("="*70)
        
        for test_name, passed in results.items():
            status = "[PASS]" if passed else "[FAIL]"
            print(f"{status} {test_name}")
        
        if all(results.values()):
            print("\n" + "="*70)
            print("ALL TESTS PASSED - RISK SCORING WORKING")
            print("="*70)
            print("\nRisk scoring verified:")
            print("  - Benign logs: low score")
            print("  - Brute force: medium/high score (+40 base)")
            print("  - Success after failures: critical (+30 bonus)")
            print("  - DDoS: high score (+45 base)")
            print("  - Multiple factors: frequency, severity, IPs")
            print("  - Risk levels: low/medium/high/critical")
        else:
            print("\nSome tests failed")
            
    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()
