"""
Test Output Validation Layer
Verifies LLM output validation, repair, and fallback mechanisms
"""
from app.llm.output_validator import OutputValidator


def test_valid_response_passes():
    """Test 1: Valid response passes validation"""
    print("\n" + "="*70)
    print("TEST 1: Valid Response Passes Validation")
    print("="*70)
    
    validator = OutputValidator()
    
    valid_response = {
        'summary': 'Detected brute force attack from IP 192.168.1.100',
        'severity': 'high',
        'threat_detected': True,
        'evidence': ['Failed login attempt 1', 'Failed login attempt 2'],
        'recommendations': ['Block IP', 'Enable MFA']
    }
    
    is_valid, errors = validator.validate(valid_response)
    
    print(f"Response: {valid_response}")
    print(f"Valid: {is_valid}")
    print(f"Errors: {errors}")
    
    passed = is_valid and len(errors) == 0
    print(f"\nResult: {'[PASS]' if passed else '[FAIL]'} - Valid response accepted")
    return passed


def test_missing_required_field():
    """Test 2: Missing required field is caught"""
    print("\n" + "="*70)
    print("TEST 2: Missing Required Field Caught")
    print("="*70)
    
    validator = OutputValidator()
    
    invalid_response = {
        'summary': 'Some summary',
        'severity': 'high',
        'threat_detected': True,
        # Missing 'evidence' and 'recommendations'
    }
    
    is_valid, errors = validator.validate(invalid_response)
    
    print(f"Response: {invalid_response}")
    print(f"Valid: {is_valid}")
    print(f"Errors: {errors}")
    
    passed = not is_valid and len(errors) > 0 and any('evidence' in str(e).lower() for e in errors)
    print(f"\nResult: {'[PASS]' if passed else '[FAIL]'} - Missing fields detected")
    return passed


def test_invalid_enum_value():
    """Test 3: Invalid enum value is caught"""
    print("\n" + "="*70)
    print("TEST 3: Invalid Enum Value Caught")
    print("="*70)
    
    validator = OutputValidator()
    
    invalid_response = {
        'summary': 'Some summary',
        'severity': 'extreme',  # Invalid - should be low/medium/high/critical
        'threat_detected': True,
        'evidence': ['Evidence 1'],
        'recommendations': ['Recommendation 1']
    }
    
    is_valid, errors = validator.validate(invalid_response)
    
    print(f"Response: {invalid_response}")
    print(f"Valid: {is_valid}")
    print(f"Errors: {errors}")
    
    passed = not is_valid and any('severity' in str(e).lower() and 'extreme' in str(e).lower() for e in errors)
    print(f"\nResult: {'[PASS]' if passed else '[FAIL]'} - Invalid enum detected")
    return passed


def test_broken_json_repair():
    """Test 4: Broken JSON with extra text is successfully repaired"""
    print("\n" + "="*70)
    print("TEST 4: Broken JSON Repair")
    print("="*70)
    
    validator = OutputValidator()
    
    # JSON with extra text before and trailing comma
    broken_json = """
    Here is my analysis:
    {
        "summary": "Detected suspicious activity",
        "severity": "high",
        "threat_detected": true,
        "evidence": ["Evidence 1", "Evidence 2",],
        "recommendations": ["Rec 1"]
    }
    That's my conclusion.
    """
    
    print(f"Broken JSON:\n{broken_json[:100]}...")
    
    repaired = validator.repair(broken_json)
    
    print(f"\nRepaired: {repaired is not None}")
    if repaired:
        print(f"Repaired response: {repaired}")
        is_valid, errors = validator.validate(repaired)
        print(f"Valid after repair: {is_valid}")
        print(f"Errors: {errors}")
    
    passed = repaired is not None and validator.validate(repaired)[0]
    print(f"\nResult: {'[PASS]' if passed else '[FAIL]'} - JSON successfully repaired")
    return passed


def test_unrecoverable_response_fallback():
    """Test 5: Completely unrecoverable response triggers fallback"""
    print("\n" + "="*70)
    print("TEST 5: Unrecoverable Response Fallback")
    print("="*70)
    
    validator = OutputValidator()
    
    # Completely broken response
    broken_response = "This is not JSON at all! Just random text with no structure."
    
    print(f"Broken response: {broken_response}")
    
    repaired = validator.repair(broken_response)
    
    print(f"Repair result: {repaired}")
    
    if repaired is None:
        # Use fallback
        classifier_result = {
            'attack_type': 'brute_force',
            'confidence': 0.9,
            'reason': 'Detected 8 failed login attempts'
        }
        risk_result = {
            'risk_score': 65,
            'risk_level': 'high'
        }
        retrieved_logs = [
            {'text': 'Failed login from 192.168.1.100'},
            {'text': 'Failed login from 192.168.1.100'}
        ]
        
        fallback_response = validator.fallback(classifier_result, risk_result, retrieved_logs)
        
        print(f"\nFallback response: {fallback_response}")
        print(f"Attack type: {fallback_response.get('attack_type')}")
        print(f"Risk score: {fallback_response.get('risk_score')}")
        print(f"Fallback used: {fallback_response.get('fallback_used')}")
        
        is_valid, errors = validator.validate(fallback_response)
        print(f"Valid: {is_valid}")
        
        passed = repaired is None and is_valid and fallback_response.get('fallback_used') == True
    else:
        passed = False
    
    print(f"\nResult: {'[PASS]' if passed else '[FAIL]'} - Fallback triggered correctly")
    return passed


def test_fallback_no_contradictions():
    """Test 6: Fallback output has no contradictions"""
    print("\n" + "="*70)
    print("TEST 6: Fallback Output Consistency")
    print("="*70)
    
    validator = OutputValidator()
    
    # Test multiple scenarios
    test_cases = [
        {
            'name': 'Normal classification',
            'classifier': {'attack_type': 'normal', 'confidence': 0.8, 'reason': 'No threats'},
            'risk': {'risk_score': 5, 'risk_level': 'low'},
            'expected_threat': False,
            'expected_severity': 'low'
        },
        {
            'name': 'Brute force high risk',
            'classifier': {'attack_type': 'brute_force', 'confidence': 0.9, 'reason': '10 failures'},
            'risk': {'risk_score': 75, 'risk_level': 'high'},
            'expected_threat': True,
            'expected_severity': 'high'
        },
        {
            'name': 'DDoS critical risk',
            'classifier': {'attack_type': 'ddos', 'confidence': 0.95, 'reason': '200 requests'},
            'risk': {'risk_score': 85, 'risk_level': 'critical'},
            'expected_threat': True,
            'expected_severity': 'critical'
        }
    ]
    
    all_passed = True
    
    for test_case in test_cases:
        print(f"\n  Testing: {test_case['name']}")
        
        fallback = validator.fallback(
            test_case['classifier'],
            test_case['risk'],
            [{'text': 'Sample log'}]
        )
        
        # Check consistency
        checks = []
        checks.append(('attack_type matches', fallback['attack_type'] == test_case['classifier']['attack_type']))
        checks.append(('threat_detected matches', fallback['threat_detected'] == test_case['expected_threat']))
        checks.append(('severity matches risk_level', fallback['severity'] == test_case['expected_severity']))
        checks.append(('risk_score matches', fallback['risk_score'] == test_case['risk']['risk_score']))
        checks.append(('risk_level matches', fallback['risk_level'] == test_case['risk']['risk_level']))
        checks.append(('has recommendations', len(fallback['recommendations']) > 0))
        checks.append(('has evidence', len(fallback['evidence']) > 0))
        
        for check_name, passed in checks:
            status = "[PASS]" if passed else "[FAIL]"
            print(f"    {status} {check_name}")
            if not passed:
                all_passed = False
    
    print(f"\nResult: {'[PASS]' if all_passed else '[FAIL]'} - All fallback outputs consistent")
    return all_passed


def test_repair_various_formats():
    """Test 7: Repair handles various broken JSON formats"""
    print("\n" + "="*70)
    print("TEST 7: Repair Various Broken Formats")
    print("="*70)
    
    validator = OutputValidator()
    
    test_cases = [
        {
            'name': 'Single quotes',
            'input': "{'summary': 'test', 'severity': 'low', 'threat_detected': true, 'evidence': [], 'recommendations': []}"
        },
        {
            'name': 'Missing closing brace',
            'input': '{"summary": "test", "severity": "low", "threat_detected": false, "evidence": [], "recommendations": []'
        },
        {
            'name': 'Trailing commas',
            'input': '{"summary": "test", "severity": "low", "threat_detected": true, "evidence": ["a", "b",], "recommendations": ["c",],}'
        },
        {
            'name': 'Extra text around JSON',
            'input': 'Sure, here is the analysis: {"summary": "test", "severity": "medium", "threat_detected": false, "evidence": [], "recommendations": []} Hope this helps!'
        }
    ]
    
    all_passed = True
    
    for test_case in test_cases:
        print(f"\n  Testing: {test_case['name']}")
        print(f"  Input: {test_case['input'][:60]}...")
        
        repaired = validator.repair(test_case['input'])
        
        if repaired:
            is_valid, errors = validator.validate(repaired)
            print(f"  Repaired: Yes")
            print(f"  Valid: {is_valid}")
            if not is_valid:
                print(f"  Errors: {errors}")
                all_passed = False
        else:
            print(f"  Repaired: No")
            all_passed = False
    
    print(f"\nResult: {'[PASS]' if all_passed else '[FAIL]'} - All formats repaired")
    return all_passed


if __name__ == "__main__":
    print("\n" + "="*70)
    print("OUTPUT VALIDATION LAYER - COMPREHENSIVE TESTS")
    print("="*70)
    
    results = {}
    
    try:
        results['Valid Response'] = test_valid_response_passes()
        results['Missing Field'] = test_missing_required_field()
        results['Invalid Enum'] = test_invalid_enum_value()
        results['JSON Repair'] = test_broken_json_repair()
        results['Fallback Trigger'] = test_unrecoverable_response_fallback()
        results['Fallback Consistency'] = test_fallback_no_contradictions()
        results['Repair Formats'] = test_repair_various_formats()
        
        print("\n" + "="*70)
        print("RESULTS")
        print("="*70)
        
        for test_name, passed in results.items():
            status = "[PASS]" if passed else "[FAIL]"
            print(f"{status} {test_name}")
        
        if all(results.values()):
            print("\n" + "="*70)
            print("ALL TESTS PASSED - OUTPUT VALIDATION WORKING")
            print("="*70)
            print("\nOutput validation verified:")
            print("  - Valid responses pass validation")
            print("  - Missing fields detected")
            print("  - Invalid enum values caught")
            print("  - Broken JSON successfully repaired")
            print("  - Unrecoverable responses trigger fallback")
            print("  - Fallback outputs have no contradictions")
            print("  - Multiple JSON formats handled")
        else:
            print("\nSome tests failed")
            
    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()
