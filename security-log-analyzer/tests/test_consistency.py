"""
Test System-Wide Consistency
Verifies that classification, risk scoring, and LLM output are consistent
"""
from datetime import datetime, timedelta
from app.ingestion.engine import IngestionEngine
from app.chunking.chunker import LogChunker
from app.analysis.classifier import AttackClassifier
from app.llm.analyzer import LogAnalyzer


def test_normal_logs_consistency():
    """Test: Single successful login should have consistent normal classification"""
    print("\n" + "="*70)
    print("TEST 1: Normal Logs - Consistency Check")
    print("="*70)
    
    engine = IngestionEngine()
    chunker = LogChunker()
    classifier = AttackClassifier()
    llm_analyzer = LogAnalyzer()
    
    # Single successful login
    base_time = datetime(2024, 3, 29, 10, 0, 0)
    logs = [{
        "message": "Successful login for user john from 192.168.1.50",
        "timestamp": base_time.isoformat() + "Z",
        "source_ip": "192.168.1.50",
        "level": "INFO"
    }]
    
    result = engine.ingest(logs, log_format='auto')
    chunks = chunker.chunk_by_time_window(result['logs'])
    
    # Get classification with risk
    classification = classifier.classify(chunks, use_llm=False)
    
    # Get LLM analysis
    analysis = llm_analyzer.analyze_logs(
        query="check login activity",
        retrieved_logs=chunks,
        attack_type=classification['attack_type'],
        risk_score=classification.get('risk_score'),
        risk_level=classification.get('risk_level')
    )
    
    print(f"Attack Type: {analysis['attack_type']}")
    print(f"Threat Detected: {analysis['threat_detected']}")
    print(f"Risk Score: {analysis['risk_score']}")
    print(f"Risk Level: {analysis['risk_level']}")
    print(f"Severity: {analysis['severity']}")
    print(f"Summary: {analysis['summary'][:80]}...")
    
    # Validate consistency
    checks = []
    checks.append(("attack_type == 'normal'", analysis['attack_type'] == 'normal'))
    checks.append(("threat_detected == False", analysis['threat_detected'] == False))
    checks.append(("risk_score < 10", analysis['risk_score'] < 10))
    checks.append(("risk_level == 'low'", analysis['risk_level'] == 'low'))
    checks.append(("severity == 'low'", analysis['severity'] == 'low'))
    checks.append(("summary doesn't mention attack", 'attack' not in analysis['summary'].lower()))
    
    print(f"\nConsistency Checks:")
    for check_name, passed in checks:
        status = "[PASS]" if passed else "[FAIL]"
        print(f"  {status} {check_name}")
    
    all_passed = all(check[1] for check in checks)
    print(f"\nResult: {'[PASS]' if all_passed else '[FAIL]'} - All consistency checks")
    return all_passed


def test_brute_force_consistency():
    """Test: Brute force should have consistent high-risk classification"""
    print("\n" + "="*70)
    print("TEST 2: Brute Force - Consistency Check")
    print("="*70)
    
    engine = IngestionEngine()
    chunker = LogChunker()
    classifier = AttackClassifier()
    llm_analyzer = LogAnalyzer()
    
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
    
    # Get classification with risk
    classification = classifier.classify(chunks, use_llm=False)
    
    # Get LLM analysis
    analysis = llm_analyzer.analyze_logs(
        query="check failed logins",
        retrieved_logs=chunks,
        attack_type=classification['attack_type'],
        risk_score=classification.get('risk_score'),
        risk_level=classification.get('risk_level')
    )
    
    print(f"Attack Type: {analysis['attack_type']}")
    print(f"Threat Detected: {analysis['threat_detected']}")
    print(f"Risk Score: {analysis['risk_score']}")
    print(f"Risk Level: {analysis['risk_level']}")
    print(f"Severity: {analysis['severity']}")
    print(f"Summary: {analysis['summary'][:80]}...")
    
    # Validate consistency
    checks = []
    checks.append(("attack_type == 'brute_force'", analysis['attack_type'] == 'brute_force'))
    checks.append(("threat_detected == True", analysis['threat_detected'] == True))
    checks.append(("risk_score >= 40", analysis['risk_score'] >= 40))
    checks.append(("risk_level in ['medium', 'high']", analysis['risk_level'] in ['medium', 'high']))
    checks.append(("severity == risk_level", analysis['severity'] == analysis['risk_level']))
    
    print(f"\nConsistency Checks:")
    for check_name, passed in checks:
        status = "[PASS]" if passed else "[FAIL]"
        print(f"  {status} {check_name}")
    
    all_passed = all(check[1] for check in checks)
    print(f"\nResult: {'[PASS]' if all_passed else '[FAIL]'} - All consistency checks")
    return all_passed


def test_success_after_failure_consistency():
    """Test: Success after failures should have critical risk"""
    print("\n" + "="*70)
    print("TEST 3: Success After Failures - Consistency Check")
    print("="*70)
    
    engine = IngestionEngine()
    chunker = LogChunker()
    classifier = AttackClassifier()
    llm_analyzer = LogAnalyzer()
    
    # 5 failures + 1 success from same IP
    base_time = datetime(2024, 3, 29, 12, 0, 0)
    logs = []
    
    for i in range(5):
        timestamp = base_time + timedelta(seconds=i*10)
        logs.append({
            "message": f"Failed login attempt for user admin from 10.0.0.100",
            "timestamp": timestamp.isoformat() + "Z",
            "source_ip": "10.0.0.100",
            "level": "ERROR"
        })
    
    timestamp = base_time + timedelta(seconds=60)
    logs.append({
        "message": "Successful login for user admin from 10.0.0.100",
        "timestamp": timestamp.isoformat() + "Z",
        "source_ip": "10.0.0.100",
        "level": "INFO"
    })
    
    result = engine.ingest(logs, log_format='auto')
    chunks = chunker.chunk_by_time_window(result['logs'])
    
    # Get classification with risk
    classification = classifier.classify(chunks, use_llm=False)
    
    # Get LLM analysis
    analysis = llm_analyzer.analyze_logs(
        query="check login activity",
        retrieved_logs=chunks,
        attack_type=classification['attack_type'],
        risk_score=classification.get('risk_score'),
        risk_level=classification.get('risk_level')
    )
    
    print(f"Attack Type: {analysis['attack_type']}")
    print(f"Threat Detected: {analysis['threat_detected']}")
    print(f"Risk Score: {analysis['risk_score']}")
    print(f"Risk Level: {analysis['risk_level']}")
    print(f"Severity: {analysis['severity']}")
    print(f"Risk Factors: {classification.get('risk_factors', [])}")
    
    # Validate consistency
    checks = []
    checks.append(("attack_type == 'brute_force'", analysis['attack_type'] == 'brute_force'))
    checks.append(("threat_detected == True", analysis['threat_detected'] == True))
    checks.append(("risk_score >= 70", analysis['risk_score'] >= 70))
    checks.append(("risk_level in ['high', 'critical']", analysis['risk_level'] in ['high', 'critical']))
    checks.append(("severity == risk_level", analysis['severity'] == analysis['risk_level']))
    checks.append(("has success_after_failure factor", any('success after' in str(f).lower() for f in classification.get('risk_factors', []))))
    
    print(f"\nConsistency Checks:")
    for check_name, passed in checks:
        status = "[PASS]" if passed else "[FAIL]"
        print(f"  {status} {check_name}")
    
    all_passed = all(check[1] for check in checks)
    print(f"\nResult: {'[PASS]' if all_passed else '[FAIL]'} - All consistency checks")
    return all_passed


def test_llm_cannot_override():
    """Test: LLM cannot override rule-based classification"""
    print("\n" + "="*70)
    print("TEST 4: LLM Cannot Override Classification")
    print("="*70)
    
    engine = IngestionEngine()
    chunker = LogChunker()
    classifier = AttackClassifier()
    llm_analyzer = LogAnalyzer()
    
    # Clear brute force attack
    base_time = datetime(2024, 3, 29, 13, 0, 0)
    logs = []
    for i in range(10):
        timestamp = base_time + timedelta(seconds=i*5)
        logs.append({
            "message": f"Failed SSH login for root from 172.16.0.50",
            "timestamp": timestamp.isoformat() + "Z",
            "source_ip": "172.16.0.50",
            "level": "CRITICAL"
        })
    
    result = engine.ingest(logs, log_format='auto')
    chunks = chunker.chunk_by_time_window(result['logs'])
    
    # Get rule-based classification
    classification = classifier.classify(chunks, use_llm=False)
    
    print(f"Rule-based classification: {classification['attack_type']}")
    print(f"Rule-based risk: {classification.get('risk_score')}")
    
    # Get LLM analysis (it should NOT change attack_type)
    analysis = llm_analyzer.analyze_logs(
        query="analyze these logs",
        retrieved_logs=chunks,
        attack_type=classification['attack_type'],
        risk_score=classification.get('risk_score'),
        risk_level=classification.get('risk_level')
    )
    
    print(f"After LLM analysis: {analysis['attack_type']}")
    print(f"After LLM risk: {analysis['risk_score']}")
    
    # Validate LLM didn't override
    checks = []
    checks.append(("attack_type unchanged", analysis['attack_type'] == classification['attack_type']))
    checks.append(("risk_score unchanged", analysis['risk_score'] == classification.get('risk_score')))
    checks.append(("risk_level unchanged", analysis['risk_level'] == classification.get('risk_level')))
    checks.append(("threat_detected consistent", analysis['threat_detected'] == (analysis['attack_type'] != 'normal')))
    
    print(f"\nConsistency Checks:")
    for check_name, passed in checks:
        status = "[PASS]" if passed else "[FAIL]"
        print(f"  {status} {check_name}")
    
    all_passed = all(check[1] for check in checks)
    print(f"\nResult: {'[PASS]' if all_passed else '[FAIL]'} - LLM cannot override")
    return all_passed


if __name__ == "__main__":
    print("\n" + "="*70)
    print("SYSTEM-WIDE CONSISTENCY - VALIDATION")
    print("="*70)
    
    results = {}
    
    try:
        results['Normal Logs'] = test_normal_logs_consistency()
        results['Brute Force'] = test_brute_force_consistency()
        results['Success After Failures'] = test_success_after_failure_consistency()
        results['LLM Cannot Override'] = test_llm_cannot_override()
        
        print("\n" + "="*70)
        print("RESULTS")
        print("="*70)
        
        for test_name, passed in results.items():
            status = "[PASS]" if passed else "[FAIL]"
            print(f"{status} {test_name}")
        
        if all(results.values()):
            print("\n" + "="*70)
            print("ALL TESTS PASSED - SYSTEM CONSISTENCY ENFORCED")
            print("="*70)
            print("\nConsistency verified:")
            print("  - attack_type from rule-based classifier only")
            print("  - risk_score from risk engine only")
            print("  - LLM provides explanation only")
            print("  - severity aligned with risk_level")
            print("  - threat_detected matches attack_type")
            print("  - No contradictions in responses")
        else:
            print("\nSome tests failed")
            
    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()
