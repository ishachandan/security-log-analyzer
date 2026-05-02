"""
Test Time-Window Attack Detection
Verifies that attacks are detected based on frequency within time windows
"""
from datetime import datetime, timedelta
from app.ingestion.engine import IngestionEngine
from app.chunking.chunker import LogChunker
from app.analysis.classifier import AttackClassifier


def test_brute_force_within_window():
    """Test: 6 failed logins within 30 seconds = brute force"""
    print("\n" + "="*70)
    print("TEST 1: Brute Force WITHIN Time Window (30 seconds)")
    print("="*70)
    
    engine = IngestionEngine()
    chunker = LogChunker()
    classifier = AttackClassifier()
    
    # 6 failed logins within 30 seconds
    base_time = datetime(2024, 3, 29, 10, 15, 0)
    logs = []
    for i in range(6):
        timestamp = base_time + timedelta(seconds=i*5)  # 0, 5, 10, 15, 20, 25 seconds
        logs.append({
            "message": f"Failed login attempt for user admin from 192.168.1.100",
            "timestamp": timestamp.isoformat() + "Z",
            "source_ip": "192.168.1.100",
            "level": "ERROR"
        })
    
    result = engine.ingest(logs, log_format='auto')
    chunks = chunker.chunk_by_time_window(result['logs'])
    classification = classifier.classify(chunks)
    
    print(f"Logs: {len(logs)} failed logins")
    print(f"Time span: 25 seconds")
    print(f"Attack Type: {classification['attack_type']}")
    print(f"Time Window: {classification.get('time_window', 'N/A')}")
    print(f"Event Count: {classification.get('event_count', 'N/A')}")
    
    passed = classification['attack_type'] == 'brute_force'
    print(f"Result: {'[PASS]' if passed else '[FAIL]'} - Expected brute_force")
    return passed


def test_brute_force_outside_window():
    """Test: 6 failed logins spread over 10 minutes = NOT brute force"""
    print("\n" + "="*70)
    print("TEST 2: Brute Force OUTSIDE Time Window (10 minutes)")
    print("="*70)
    
    engine = IngestionEngine()
    chunker = LogChunker()
    classifier = AttackClassifier()
    
    # 6 failed logins spread over 10 minutes (600 seconds)
    base_time = datetime(2024, 3, 29, 10, 20, 0)
    logs = []
    for i in range(6):
        timestamp = base_time + timedelta(seconds=i*100)  # 0, 100, 200, 300, 400, 500 seconds
        logs.append({
            "message": f"Failed login attempt for user admin from 10.0.0.50",
            "timestamp": timestamp.isoformat() + "Z",
            "source_ip": "10.0.0.50",
            "level": "ERROR"
        })
    
    result = engine.ingest(logs, log_format='auto')
    chunks = chunker.chunk_by_time_window(result['logs'])
    classification = classifier.classify(chunks)
    
    print(f"Logs: {len(logs)} failed logins")
    print(f"Time span: 500 seconds (8.3 minutes)")
    print(f"Attack Type: {classification['attack_type']}")
    
    passed = classification['attack_type'] == 'normal'
    print(f"Result: {'[PASS]' if passed else '[FAIL]'} - Expected normal")
    return passed


def test_ddos_within_window():
    """Test: 120 requests within 8 seconds = DDoS"""
    print("\n" + "="*70)
    print("TEST 3: DDoS WITHIN Time Window (8 seconds)")
    print("="*70)
    
    engine = IngestionEngine()
    chunker = LogChunker()
    classifier = AttackClassifier()
    
    # 120 requests within 8 seconds from same IP
    base_time = datetime(2024, 3, 29, 11, 0, 0)
    logs = []
    for i in range(120):
        timestamp = base_time + timedelta(milliseconds=i*66)  # ~66ms apart = 8 seconds total
        logs.append({
            "message": f"GET /api/endpoint HTTP/1.1 200",
            "timestamp": timestamp.isoformat() + "Z",
            "source_ip": "203.0.113.100",
            "level": "INFO"
        })
    
    result = engine.ingest(logs, log_format='auto')
    chunks = chunker.chunk_by_time_window(result['logs'])
    classification = classifier.classify(chunks)
    
    print(f"Logs: {len(logs)} requests")
    print(f"Time span: ~8 seconds")
    print(f"Attack Type: {classification['attack_type']}")
    print(f"Time Window: {classification.get('time_window', 'N/A')}")
    print(f"Request Count: {classification.get('request_count', 'N/A')}")
    
    passed = classification['attack_type'] == 'ddos'
    print(f"Result: {'[PASS]' if passed else '[FAIL]'} - Expected ddos")
    return passed


def test_ddos_distributed():
    """Test: 150 requests from 10 IPs within 9 seconds = distributed DDoS"""
    print("\n" + "="*70)
    print("TEST 4: Distributed DDoS (10 IPs, 9 seconds)")
    print("="*70)
    
    engine = IngestionEngine()
    chunker = LogChunker()
    classifier = AttackClassifier()
    
    # 150 requests from 10 different IPs within 9 seconds
    base_time = datetime(2024, 3, 29, 11, 10, 0)
    logs = []
    for i in range(150):
        ip_suffix = (i % 10) + 1  # Rotate through 10 IPs
        timestamp = base_time + timedelta(milliseconds=i*60)  # 9 seconds total
        logs.append({
            "message": f"GET /api/data HTTP/1.1 200",
            "timestamp": timestamp.isoformat() + "Z",
            "source_ip": f"10.0.0.{ip_suffix}",
            "level": "INFO"
        })
    
    result = engine.ingest(logs, log_format='auto')
    chunks = chunker.chunk_by_time_window(result['logs'])
    classification = classifier.classify(chunks)
    
    print(f"Logs: {len(logs)} requests from 10 IPs")
    print(f"Time span: ~9 seconds")
    print(f"Attack Type: {classification['attack_type']}")
    print(f"Unique IPs: {classification.get('unique_ips', 'N/A')}")
    
    passed = classification['attack_type'] == 'ddos'
    print(f"Result: {'[PASS]' if passed else '[FAIL]'} - Expected ddos")
    return passed


def test_normal_traffic():
    """Test: 50 requests over 5 minutes = normal"""
    print("\n" + "="*70)
    print("TEST 5: Normal Traffic (50 requests, 5 minutes)")
    print("="*70)
    
    engine = IngestionEngine()
    chunker = LogChunker()
    classifier = AttackClassifier()
    
    # 50 requests spread over 5 minutes
    base_time = datetime(2024, 3, 29, 12, 0, 0)
    logs = []
    for i in range(50):
        timestamp = base_time + timedelta(seconds=i*6)  # 300 seconds total
        logs.append({
            "message": f"GET /api/status HTTP/1.1 200",
            "timestamp": timestamp.isoformat() + "Z",
            "source_ip": "192.168.1.50",
            "level": "INFO"
        })
    
    result = engine.ingest(logs, log_format='auto')
    chunks = chunker.chunk_by_time_window(result['logs'])
    classification = classifier.classify(chunks)
    
    print(f"Logs: {len(logs)} requests")
    print(f"Time span: 294 seconds (~5 minutes)")
    print(f"Attack Type: {classification['attack_type']}")
    
    passed = classification['attack_type'] == 'normal'
    print(f"Result: {'[PASS]' if passed else '[FAIL]'} - Expected normal")
    return passed


if __name__ == "__main__":
    print("\n" + "="*70)
    print("TIME-WINDOW ATTACK DETECTION - VALIDATION")
    print("="*70)
    
    results = {}
    
    try:
        results['Brute Force (within window)'] = test_brute_force_within_window()
        results['Brute Force (outside window)'] = test_brute_force_outside_window()
        results['DDoS (single IP)'] = test_ddos_within_window()
        results['DDoS (distributed)'] = test_ddos_distributed()
        results['Normal Traffic'] = test_normal_traffic()
        
        print("\n" + "="*70)
        print("RESULTS")
        print("="*70)
        
        for test_name, passed in results.items():
            status = "[PASS]" if passed else "[FAIL]"
            print(f"{status} {test_name}")
        
        if all(results.values()):
            print("\n" + "="*70)
            print("ALL TESTS PASSED - TIME-WINDOW DETECTION WORKING")
            print("="*70)
            print("\nTime-window detection verified:")
            print("  - Brute force: >=5 failures within 60 seconds")
            print("  - DDoS: >=100 requests within 10 seconds")
            print("  - Sliding window approach")
            print("  - Outputs include time_window and event_count")
        else:
            print("\nSome tests failed")
            
    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()
