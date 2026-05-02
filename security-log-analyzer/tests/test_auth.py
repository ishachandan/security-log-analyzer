"""
Authentication System Tests
Tests JWT authentication, API keys, and role-based access control
"""
import os
import sys
import time
from app.auth import AuthManager


def get_test_db_path(test_name):
    """Get unique database path for test"""
    return f"data/test_auth_{test_name}_{int(time.time()*1000)}.db"


def cleanup_test_db(db_path):
    """Clean up test database"""
    try:
        time.sleep(0.1)  # Give time for connections to close
        if os.path.exists(db_path):
            os.unlink(db_path)
    except:
        pass  # Ignore cleanup errors


def test_user_registration():
    """Test 1: User registration with validation"""
    print("\n" + "="*70)
    print("TEST 1: User Registration")
    print("="*70)
    
    db_path = get_test_db_path("registration")
    
    try:
        auth_manager = AuthManager(db_path=db_path)
        
        # Test successful registration
        success, message = auth_manager.register_user("admin", "password123", "admin")
        print(f"Admin registration: {message}")
        assert success, "Admin registration should succeed"
        
        success, message = auth_manager.register_user("analyst", "password456", "analyst")
        print(f"Analyst registration: {message}")
        assert success, "Analyst registration should succeed"
        
        # Test duplicate username
        success, message = auth_manager.register_user("admin", "newpassword", "admin")
        print(f"Duplicate username: {message}")
        assert not success, "Duplicate username should fail"
        assert "already exists" in message.lower()
        
        # Test invalid role
        success, message = auth_manager.register_user("user3", "password", "superuser")
        print(f"Invalid role: {message}")
        assert not success, "Invalid role should fail"
        
        # Test short username
        success, message = auth_manager.register_user("ab", "password123", "analyst")
        print(f"Short username: {message}")
        assert not success, "Short username should fail"
        
        # Test short password
        success, message = auth_manager.register_user("user4", "pass", "analyst")
        print(f"Short password: {message}")
        assert not success, "Short password should fail"
        
        print("\n[PASS] User registration validation working")
        return True
        
    finally:
        cleanup_test_db(db_path)


def test_login_and_jwt():
    """Test 2: Login with JWT token generation"""
    print("\n" + "="*70)
    print("TEST 2: Login and JWT Token Generation")
    print("="*70)
    
    db_path = get_test_db_path("login")
    
    try:
        auth_manager = AuthManager(db_path=db_path, jwt_secret="test_secret_key")
        
        # Register user
        auth_manager.register_user("testuser", "testpass123", "admin")
        
        # Test successful login
        success, token, user_info = auth_manager.login("testuser", "testpass123")
        print(f"Login success: {success}")
        print(f"Token generated: {token[:50]}...")
        print(f"User info: {user_info}")
        
        assert success, "Login should succeed"
        assert token is not None, "Token should be generated"
        assert user_info['username'] == "testuser"
        assert user_info['role'] == "admin"
        
        # Test invalid password
        success, token, user_info = auth_manager.login("testuser", "wrongpassword")
        print(f"\nInvalid password - Success: {success}")
        assert not success, "Login with wrong password should fail"
        assert token is None
        
        # Test non-existent user
        success, token, user_info = auth_manager.login("nonexistent", "password")
        print(f"Non-existent user - Success: {success}")
        assert not success, "Login with non-existent user should fail"
        
        print("\n[PASS] Login and JWT generation working")
        return True
        
    finally:
        cleanup_test_db(db_path)


def test_jwt_verification():
    """Test 3: JWT token verification"""
    print("\n" + "="*70)
    print("TEST 3: JWT Token Verification")
    print("="*70)
    
    db_path = get_test_db_path("jwt")
    
    try:
        auth_manager = AuthManager(db_path=db_path, jwt_secret="test_secret_key")
        
        # Register and login
        auth_manager.register_user("testuser", "testpass123", "analyst")
        success, token, user_info = auth_manager.login("testuser", "testpass123")
        
        # Verify valid token
        valid, payload = auth_manager.verify_jwt(token)
        print(f"Token valid: {valid}")
        print(f"Payload: {payload}")
        
        assert valid, "Valid token should be verified"
        assert payload['username'] == "testuser"
        assert payload['role'] == "analyst"
        assert 'exp' in payload
        assert 'iat' in payload
        
        # Test invalid token
        invalid_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature"
        valid, payload = auth_manager.verify_jwt(invalid_token)
        print(f"\nInvalid token - Valid: {valid}")
        assert not valid, "Invalid token should fail verification"
        
        # Test token with wrong secret
        other_auth = AuthManager(db_path=db_path, jwt_secret="different_secret")
        valid, payload = other_auth.verify_jwt(token)
        print(f"Wrong secret - Valid: {valid}")
        assert not valid, "Token with wrong secret should fail"
        
        print("\n[PASS] JWT verification working")
        return True
        
    finally:
        cleanup_test_db(db_path)


def test_api_key_generation():
    """Test 4: API key generation and verification"""
    print("\n" + "="*70)
    print("TEST 4: API Key Generation and Verification")
    print("="*70)
    
    db_path = get_test_db_path("apikey")
    
    try:
        auth_manager = AuthManager(db_path=db_path)
        
        # Register user
        auth_manager.register_user("apiuser", "password123", "admin")
        success, token, user_info = auth_manager.login("apiuser", "password123")
        user_id = user_info['id']
        
        # Generate API key
        success, api_key, message = auth_manager.generate_api_key(user_id, "Production key")
        print(f"API key generated: {success}")
        print(f"Key: {api_key[:20]}...")
        print(f"Message: {message}")
        
        assert success, "API key generation should succeed"
        assert api_key.startswith("sla_"), "API key should have correct prefix"
        assert len(api_key) > 40, "API key should be long enough"
        
        # Verify API key
        valid, user_info = auth_manager.verify_api_key(api_key)
        print(f"\nAPI key valid: {valid}")
        print(f"User info: {user_info}")
        
        assert valid, "Valid API key should be verified"
        assert user_info['username'] == "apiuser"
        assert user_info['role'] == "admin"
        
        # Test invalid API key
        valid, user_info = auth_manager.verify_api_key("sla_invalid_key_12345")
        print(f"\nInvalid API key - Valid: {valid}")
        assert not valid, "Invalid API key should fail verification"
        
        # List API keys
        keys = auth_manager.list_api_keys(user_id)
        print(f"\nAPI keys for user: {len(keys)}")
        assert len(keys) == 1, "Should have 1 API key"
        assert keys[0]['name'] == "Production key"
        
        print("\n[PASS] API key generation and verification working")
        return True
        
    finally:
        cleanup_test_db(db_path)


def test_api_key_revocation():
    """Test 5: API key revocation"""
    print("\n" + "="*70)
    print("TEST 5: API Key Revocation")
    print("="*70)
    
    db_path = get_test_db_path("revoke")
    
    try:
        auth_manager = AuthManager(db_path=db_path)
        
        # Register user and generate API key
        auth_manager.register_user("testuser", "password123", "analyst")
        success, token, user_info = auth_manager.login("testuser", "password123")
        user_id = user_info['id']
        
        success, api_key, message = auth_manager.generate_api_key(user_id, "Test key")
        
        # Verify key works
        valid, _ = auth_manager.verify_api_key(api_key)
        assert valid, "API key should work before revocation"
        
        # Get key ID
        keys = auth_manager.list_api_keys(user_id)
        key_id = keys[0]['id']
        
        # Revoke key
        success, message = auth_manager.revoke_api_key(key_id, user_id)
        print(f"Revocation: {message}")
        assert success, "Revocation should succeed"
        
        # Verify key no longer works
        valid, _ = auth_manager.verify_api_key(api_key)
        print(f"Key valid after revocation: {valid}")
        assert not valid, "Revoked API key should not work"
        
        # Verify key not in list
        keys = auth_manager.list_api_keys(user_id)
        print(f"API keys after revocation: {len(keys)}")
        assert len(keys) == 0, "Should have no API keys after revocation"
        
        print("\n[PASS] API key revocation working")
        return True
        
    finally:
        cleanup_test_db(db_path)


def test_role_based_access():
    """Test 6: Role-based access control"""
    print("\n" + "="*70)
    print("TEST 6: Role-Based Access Control")
    print("="*70)
    
    db_path = get_test_db_path("roles")
    
    try:
        auth_manager = AuthManager(db_path=db_path)
        
        # Register admin and analyst
        auth_manager.register_user("admin_user", "password123", "admin")
        auth_manager.register_user("analyst_user", "password456", "analyst")
        
        # Login both users
        success, admin_token, admin_info = auth_manager.login("admin_user", "password123")
        success, analyst_token, analyst_info = auth_manager.login("analyst_user", "password456")
        
        # Verify roles
        valid, admin_payload = auth_manager.verify_jwt(admin_token)
        valid, analyst_payload = auth_manager.verify_jwt(analyst_token)
        
        print(f"Admin role: {admin_payload['role']}")
        print(f"Analyst role: {analyst_payload['role']}")
        
        assert admin_payload['role'] == "admin", "Admin should have admin role"
        assert analyst_payload['role'] == "analyst", "Analyst should have analyst role"
        
        # Simulate role check (admin-only endpoint)
        def check_admin_access(payload):
            return payload['role'] == 'admin'
        
        admin_can_access = check_admin_access(admin_payload)
        analyst_can_access = check_admin_access(analyst_payload)
        
        print(f"\nAdmin can access admin endpoint: {admin_can_access}")
        print(f"Analyst can access admin endpoint: {analyst_can_access}")
        
        assert admin_can_access, "Admin should access admin endpoints"
        assert not analyst_can_access, "Analyst should NOT access admin endpoints"
        
        # Simulate role check (any authenticated user)
        def check_any_access(payload):
            return payload['role'] in ['admin', 'analyst']
        
        admin_can_query = check_any_access(admin_payload)
        analyst_can_query = check_any_access(analyst_payload)
        
        print(f"\nAdmin can query: {admin_can_query}")
        print(f"Analyst can query: {analyst_can_query}")
        
        assert admin_can_query, "Admin should query"
        assert analyst_can_query, "Analyst should query"
        
        print("\n[PASS] Role-based access control working")
        return True
        
    finally:
        cleanup_test_db(db_path)


def test_integration_flow():
    """Test 7: Complete authentication flow"""
    print("\n" + "="*70)
    print("TEST 7: Complete Authentication Flow")
    print("="*70)
    
    db_path = get_test_db_path("integration")
    
    try:
        auth_manager = AuthManager(db_path=db_path)
        
        # Step 1: Register
        print("Step 1: Register user")
        success, message = auth_manager.register_user("fulltest", "password123", "admin")
        assert success
        
        # Step 2: Login and get JWT
        print("Step 2: Login and get JWT")
        success, jwt_token, user_info = auth_manager.login("fulltest", "password123")
        assert success
        user_id = user_info['id']
        
        # Step 3: Verify JWT
        print("Step 3: Verify JWT")
        valid, payload = auth_manager.verify_jwt(jwt_token)
        assert valid
        
        # Step 4: Generate API key
        print("Step 4: Generate API key")
        success, api_key, message = auth_manager.generate_api_key(user_id, "Integration test key")
        assert success
        
        # Step 5: Verify API key
        print("Step 5: Verify API key")
        valid, user_info = auth_manager.verify_api_key(api_key)
        assert valid
        
        # Step 6: List API keys
        print("Step 6: List API keys")
        keys = auth_manager.list_api_keys(user_id)
        assert len(keys) == 1
        
        # Step 7: Get user info
        print("Step 7: Get user info")
        user = auth_manager.get_user_by_id(user_id)
        assert user is not None
        assert user['username'] == "fulltest"
        
        print("\n[PASS] Complete authentication flow working")
        return True
        
    finally:
        cleanup_test_db(db_path)


if __name__ == "__main__":
    print("\n" + "="*70)
    print("AUTHENTICATION SYSTEM - COMPREHENSIVE TESTS")
    print("="*70)
    
    results = {}
    
    try:
        results['User Registration'] = test_user_registration()
        results['Login and JWT'] = test_login_and_jwt()
        results['JWT Verification'] = test_jwt_verification()
        results['API Key Generation'] = test_api_key_generation()
        results['API Key Revocation'] = test_api_key_revocation()
        results['Role-Based Access'] = test_role_based_access()
        results['Integration Flow'] = test_integration_flow()
        
        print("\n" + "="*70)
        print("RESULTS")
        print("="*70)
        
        for test_name, passed in results.items():
            status = "[PASS]" if passed else "[FAIL]"
            print(f"{status} {test_name}")
        
        if all(results.values()):
            print("\n" + "="*70)
            print("ALL TESTS PASSED - AUTHENTICATION SYSTEM WORKING")
            print("="*70)
            print("\nAuthentication features verified:")
            print("  ✅ User registration with validation")
            print("  ✅ Login with JWT token generation")
            print("  ✅ JWT token verification")
            print("  ✅ API key generation and verification")
            print("  ✅ API key revocation")
            print("  ✅ Role-based access control (admin vs analyst)")
            print("  ✅ Complete authentication flow")
        else:
            print("\n❌ Some tests failed")
            sys.exit(1)
            
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
