"""
Authentication API Routes
"""
from flask import Blueprint, request, jsonify, current_app
from .auth import require_auth

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')


@auth_bp.route('/register', methods=['POST'])
def register():
    """
    Register a new user
    
    Request body:
        {
            "username": "string",
            "password": "string",
            "role": "admin" | "analyst"  (optional, defaults to "analyst")
        }
    
    Response:
        {
            "status": "success" | "error",
            "message": "string"
        }
    """
    auth_manager = current_app.config['AUTH_MANAGER']
    
    data = request.get_json()
    
    if not data:
        return jsonify({'status': 'error', 'message': 'Request body required'}), 400
    
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'analyst')
    
    if not username or not password:
        return jsonify({'status': 'error', 'message': 'Username and password required'}), 400
    
    success, message = auth_manager.register_user(username, password, role)
    
    if success:
        return jsonify({'status': 'success', 'message': message}), 201
    else:
        return jsonify({'status': 'error', 'message': message}), 400


@auth_bp.route('/login', methods=['POST'])
def login():
    """
    Login and receive JWT token
    
    Request body:
        {
            "username": "string",
            "password": "string"
        }
    
    Response:
        {
            "status": "success",
            "token": "jwt_token_string",
            "user": {
                "id": 1,
                "username": "string",
                "role": "admin" | "analyst"
            },
            "expires_in": 86400
        }
    """
    auth_manager = current_app.config['AUTH_MANAGER']
    
    data = request.get_json()
    
    if not data:
        return jsonify({'status': 'error', 'message': 'Request body required'}), 400
    
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'status': 'error', 'message': 'Username and password required'}), 400
    
    success, token, user_info = auth_manager.login(username, password)
    
    if success:
        return jsonify({
            'status': 'success',
            'token': token,
            'user': user_info,
            'expires_in': auth_manager.jwt_expiry_hours * 3600
        }), 200
    else:
        return jsonify({'status': 'error', 'message': 'Invalid credentials'}), 401


@auth_bp.route('/api-key', methods=['POST'])
@require_auth()
def generate_api_key():
    """
    Generate a new API key for the authenticated user
    
    Request body (optional):
        {
            "name": "string"  (optional description)
        }
    
    Response:
        {
            "status": "success",
            "api_key": "sla_...",
            "message": "API key generated successfully"
        }
    
    Note: The API key is only shown once. Store it securely.
    """
    auth_manager = current_app.config['AUTH_MANAGER']
    
    user_id = request.user['user_id']
    
    data = request.get_json() or {}
    name = data.get('name')
    
    success, api_key, message = auth_manager.generate_api_key(user_id, name)
    
    if success:
        return jsonify({
            'status': 'success',
            'api_key': api_key,
            'message': message,
            'warning': 'Store this key securely. It will not be shown again.'
        }), 201
    else:
        return jsonify({'status': 'error', 'message': message}), 400


@auth_bp.route('/api-keys', methods=['GET'])
@require_auth()
def list_api_keys():
    """
    List all API keys for the authenticated user
    
    Response:
        {
            "status": "success",
            "api_keys": [
                {
                    "id": 1,
                    "key_prefix": "sla_abc123...",
                    "name": "Production key",
                    "created_at": "2026-05-02T12:00:00",
                    "last_used": "2026-05-02T14:30:00"
                }
            ]
        }
    """
    auth_manager = current_app.config['AUTH_MANAGER']
    
    user_id = request.user['user_id']
    
    api_keys = auth_manager.list_api_keys(user_id)
    
    return jsonify({
        'status': 'success',
        'api_keys': api_keys
    }), 200


@auth_bp.route('/api-keys/<int:key_id>', methods=['DELETE'])
@require_auth()
def revoke_api_key(key_id):
    """
    Revoke an API key
    
    Response:
        {
            "status": "success",
            "message": "API key revoked successfully"
        }
    """
    auth_manager = current_app.config['AUTH_MANAGER']
    
    user_id = request.user['user_id']
    
    success, message = auth_manager.revoke_api_key(key_id, user_id)
    
    if success:
        return jsonify({'status': 'success', 'message': message}), 200
    else:
        return jsonify({'status': 'error', 'message': message}), 404


@auth_bp.route('/me', methods=['GET'])
@require_auth()
def get_current_user():
    """
    Get current authenticated user info
    
    Response:
        {
            "status": "success",
            "user": {
                "id": 1,
                "username": "admin",
                "role": "admin",
                "created_at": "2026-05-02T12:00:00",
                "last_login": "2026-05-02T14:30:00"
            }
        }
    """
    auth_manager = current_app.config['AUTH_MANAGER']
    
    user_id = request.user['user_id']
    user_info = auth_manager.get_user_by_id(user_id)
    
    if user_info:
        return jsonify({'status': 'success', 'user': user_info}), 200
    else:
        return jsonify({'status': 'error', 'message': 'User not found'}), 404
