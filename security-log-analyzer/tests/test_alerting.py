"""
Alerting System Tests
Tests webhook alerts, email alerts, and alert storage
"""
import os
import sys
import time
import json
from unittest.mock import Mock, patch, MagicMock
from app.alerting import AlertManager


def get_test_db_path(test_name):
    """Get unique database path for test"""
    return f"data/test_alerting_{test_name}_{int(time.time()*1000)}.db"


def cleanup_test_db(db_path):
    """Clean up test database"""
    try:
        time.sleep(0.1)
        if os.path.exists(db_path):
            os.unlink(db_path)
    except:
        pass


def test_should_alert_critical():
    """Test 1: should_alert returns True for critical risk"""
    print("\n" + "="*70)
    print("TEST 1: should_alert Returns True for Critical Risk")
    print("="*70)
    
    db_path = get_test_db_path("critical")
    
    try:
        alert_manager = AlertManager(db_path=db_path)
        
        result = {
            'attack_type': 'brute_force',
            'risk_level': 'critical',
            'risk_score': 95
        }
        
        should_alert = alert_manager.should_alert(result)
        print(f"Risk level: {result['risk_level']}")
        print(f"Should alert: {should_alert}")
        
        assert should_alert == True, "Should alert for critical risk"
        
        print("\n[PASS] Critical risk triggers alert")
        return True
        
    finally:
        cleanup_test_db(db_path)


def test_should_alert_high():
    """Test 2: should_alert returns True for high risk"""
    print("\n" + "="*70)
    print("TEST 2: should_alert Returns True for High Risk")
    print("="*70)
    
    db_path = get_test_db_path("high")
    
    try:
        alert_manager = AlertManager(db_path=db_path)
        
        result = {
            'attack_type': 'ddos',
            'risk_level': 'high',
            'risk_score': 75
        }
        
        should_alert = alert_manager.should_alert(result)
        print(f"Risk level: {result['risk_level']}")
        print(f"Should alert: {should_alert}")
        
        assert should_alert == True, "Should alert for high risk"
        
        print("\n[PASS] High risk triggers alert")
        return True
        
    finally:
        cleanup_test_db(db_path)


def test_should_not_alert_medium():
    """Test 3: should_alert returns False for medium risk"""
    print("\n" + "="*70)
    print("TEST 3: should_alert Returns False for Medium Risk")
    print("="*70)
    
    db_path = get_test_db_path("medium")
    
    try:
        alert_manager = AlertManager(db_path=db_path)
        
        result = {
            'attack_type': 'suspicious_login',
            'risk_level': 'medium',
            'risk_score': 45
        }
        
        should_alert = alert_manager.should_alert(result)
        print(f"Risk level: {result['risk_level']}")
        print(f"Should alert: {should_alert}")
        
        assert should_alert == False, "Should NOT alert for medium risk"
        
        print("\n[PASS] Medium risk does not trigger alert")
        return True
        
    finally:
        cleanup_test_db(db_path)


def test_should_not_alert_low():
    """Test 4: should_alert returns False for low risk"""
    print("\n" + "="*70)
    print("TEST 4: should_alert Returns False for Low Risk")
    print("="*70)
    
    db_path = get_test_db_path("low")
    
    try:
        alert_manager = AlertManager(db_path=db_path)
        
        result = {
            'attack_type': 'normal',
            'risk_level': 'low',
            'risk_score': 10
        }
        
        should_alert = alert_manager.should_alert(result)
        print(f"Risk level: {result['risk_level']}")
        print(f"Should alert: {should_alert}")
        
        assert should_alert == False, "Should NOT alert for low risk"
        
        print("\n[PASS] Low risk does not trigger alert")
        return True
        
    finally:
        cleanup_test_db(db_path)


def test_webhook_called_on_alert():
    """Test 5: Webhook is called with correct payload when alert fires"""
    print("\n" + "="*70)
    print("TEST 5: Webhook Called with Correct Payload")
    print("="*70)
    
    db_path = get_test_db_path("webhook")
    
    try:
        alert_manager = AlertManager(db_path=db_path)
        
        result = {
            'attack_type': 'brute_force',
            'risk_level': 'critical',
            'risk_score': 90,
            'severity': 'critical',
            'summary': 'Detected brute force attack from IP 192.168.1.100',
            'risk_factors': ['Attack type: brute_force (+40)', 'High frequency (+15)'],
            'source_ip': '192.168.1.100'
        }
        
        query = "failed logins from 192.168.1.100"
        
        # Mock requests.post
        with patch('app.alerting.alerting.requests.post') as mock_post:
            # Mock successful response
            mock_response = Mock()
            mock_response.status_code = 200
            mock_post.return_value = mock_response
            
            # Mock ALERT_WEBHOOK_URL to be set
            with patch('app.alerting.alerting.ALERT_WEBHOOK_URL', 'http://example.com/webhook'):
                alert_payload = alert_manager.fire(result, query)
                
                print(f"Alert fired: {alert_payload is not None}")
                print(f"Alert ID: {alert_payload['alert_id'] if alert_payload else 'None'}")
                
                # Verify webhook was called
                assert mock_post.called, "Webhook should be called"
                print(f"Webhook called: {mock_post.called}")
                
                # Verify payload
                call_args = mock_post.call_args
                sent_payload = call_args[1]['json']
                
                print(f"\nPayload sent:")
                print(f"  - attack_type: {sent_payload['attack_type']}")
                print(f"  - risk_level: {sent_payload['risk_level']}")
                print(f"  - risk_score: {sent_payload['risk_score']}")
                print(f"  - source_ip: {sent_payload['source_ip']}")
                
                assert sent_payload['attack_type'] == 'brute_force'
                assert sent_payload['risk_level'] == 'critical'
                assert sent_payload['risk_score'] == 90
                assert sent_payload['source_ip'] == '192.168.1.100'
                assert 'alert_id' in sent_payload
                assert 'timestamp' in sent_payload
                assert 'recommended_action' in sent_payload
        
        print("\n[PASS] Webhook called with correct payload")
        return True
        
    finally:
        cleanup_test_db(db_path)


def test_no_webhook_for_medium_risk():
    """Test 6: No webhook call when risk is medium/low"""
    print("\n" + "="*70)
    print("TEST 6: No Webhook for Medium/Low Risk")
    print("="*70)
    
    db_path = get_test_db_path("no_webhook")
    
    try:
        alert_manager = AlertManager(db_path=db_path)
        
        result = {
            'attack_type': 'suspicious_login',
            'risk_level': 'medium',
            'risk_score': 35,
            'severity': 'medium',
            'summary': 'Suspicious login detected',
            'risk_factors': []
        }
        
        query = "suspicious logins"
        
        # Mock requests.post
        with patch('app.alerting.alerting.requests.post') as mock_post:
            with patch('app.alerting.alerting.ALERT_WEBHOOK_URL', 'http://example.com/webhook'):
                alert_payload = alert_manager.fire(result, query)
                
                print(f"Alert fired: {alert_payload is not None}")
                print(f"Webhook called: {mock_post.called}")
                
                # Verify no alert was fired
                assert alert_payload is None, "Should not fire alert for medium risk"
                
                # Verify webhook was NOT called
                assert not mock_post.called, "Webhook should NOT be called for medium risk"
        
        print("\n[PASS] No webhook for medium risk")
        return True
        
    finally:
        cleanup_test_db(db_path)


def test_alert_saved_to_database():
    """Test 7: Alert is saved to SQLite and retrievable"""
    print("\n" + "="*70)
    print("TEST 7: Alert Saved to Database")
    print("="*70)
    
    db_path = get_test_db_path("database")
    
    try:
        alert_manager = AlertManager(db_path=db_path)
        
        result = {
            'attack_type': 'ddos',
            'risk_level': 'high',
            'risk_score': 80,
            'severity': 'high',
            'summary': 'DDoS attack detected from multiple IPs',
            'risk_factors': ['Attack type: ddos (+45)', 'IP diversity (+15)'],
            'source_ip': '192.168.1.50'
        }
        
        query = "high volume requests"
        
        # Mock webhook to avoid actual HTTP call
        with patch('app.alerting.alerting.requests.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_post.return_value = mock_response
            
            with patch('app.alerting.alerting.ALERT_WEBHOOK_URL', 'http://example.com/webhook'):
                # Fire alert
                alert_payload = alert_manager.fire(result, query)
                
                print(f"Alert fired: {alert_payload is not None}")
                print(f"Alert ID: {alert_payload['alert_id']}")
                
                assert alert_payload is not None, "Alert should be fired"
                
                # Retrieve alerts from database
                alerts = alert_manager.get_recent_alerts(limit=10)
                
                print(f"\nAlerts in database: {len(alerts)}")
                
                assert len(alerts) == 1, "Should have 1 alert in database"
                
                # Verify alert data
                saved_alert = alerts[0]
                print(f"\nSaved alert:")
                print(f"  - alert_id: {saved_alert['alert_id']}")
                print(f"  - attack_type: {saved_alert['attack_type']}")
                print(f"  - risk_level: {saved_alert['risk_level']}")
                print(f"  - risk_score: {saved_alert['risk_score']}")
                print(f"  - source_ip: {saved_alert['source_ip']}")
                print(f"  - webhook_sent: {saved_alert['webhook_sent']}")
                
                assert saved_alert['alert_id'] == alert_payload['alert_id']
                assert saved_alert['attack_type'] == 'ddos'
                assert saved_alert['risk_level'] == 'high'
                assert saved_alert['risk_score'] == 80
                assert saved_alert['source_ip'] == '192.168.1.50'
                assert saved_alert['webhook_sent'] == True
                
                # Test filtering by risk level
                high_alerts = alert_manager.get_recent_alerts(limit=10, risk_level='high')
                critical_alerts = alert_manager.get_recent_alerts(limit=10, risk_level='critical')
                
                print(f"\nFiltered alerts:")
                print(f"  - high: {len(high_alerts)}")
                print(f"  - critical: {len(critical_alerts)}")
                
                assert len(high_alerts) == 1, "Should have 1 high risk alert"
                assert len(critical_alerts) == 0, "Should have 0 critical alerts"
        
        print("\n[PASS] Alert saved to database and retrievable")
        return True
        
    finally:
        cleanup_test_db(db_path)


if __name__ == "__main__":
    print("\n" + "="*70)
    print("ALERTING SYSTEM - COMPREHENSIVE TESTS")
    print("="*70)
    
    results = {}
    
    try:
        results['Critical Risk Alert'] = test_should_alert_critical()
        results['High Risk Alert'] = test_should_alert_high()
        results['Medium Risk No Alert'] = test_should_not_alert_medium()
        results['Low Risk No Alert'] = test_should_not_alert_low()
        results['Webhook Called'] = test_webhook_called_on_alert()
        results['No Webhook Medium'] = test_no_webhook_for_medium_risk()
        results['Database Storage'] = test_alert_saved_to_database()
        
        print("\n" + "="*70)
        print("RESULTS")
        print("="*70)
        
        for test_name, passed in results.items():
            status = "[PASS]" if passed else "[FAIL]"
            print(f"{status} {test_name}")
        
        if all(results.values()):
            print("\n" + "="*70)
            print("ALL TESTS PASSED - ALERTING SYSTEM WORKING")
            print("="*70)
            print("\nAlerting features verified:")
            print("  ✅ Critical risk triggers alerts")
            print("  ✅ High risk triggers alerts")
            print("  ✅ Medium risk does not trigger alerts")
            print("  ✅ Low risk does not trigger alerts")
            print("  ✅ Webhook called with correct payload")
            print("  ✅ No webhook for medium/low risk")
            print("  ✅ Alerts saved to database and retrievable")
        else:
            print("\n❌ Some tests failed")
            sys.exit(1)
            
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
