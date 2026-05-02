"""
Authentication Module
JWT-based authentication with API key support and role-based access control
"""
import sqlite3
import secrets
import hashlib
from datetime import datetime, timedelta
from functools import wraps
from typing import Optional, Dict, Any, Tuple
from flask import request, jsonify
import jwt
import bcrypt


class AuthManager:
    """Manages user authentication, JWT tokens, and API keys"""
    
    def __init__(self, db_path: str = "data/users.db", jwt_secret: str = None):
        """
        Initialize authentication manager
        
        Args:
            db_path: Path to SQLite database
            jwt_secret: Secret key for JWT signing
        """
        self.db_path = db_path
        self.jwt_secret = jwt_secret or secrets.token_urlsafe(32)
        self.jwt_algorithm = "HS256"
        self.jwt_expiry_hours = 24
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database with users and api_keys tables"""
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL")  # Better concurrency
        cursor = conn.cursor()
        
        # Users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'analyst',
                created_at TEXT NOT NULL,
                last_login TEXT
            )
        """)
        
        # API keys table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                key_hash TEXT UNIQUE NOT NULL,
                key_prefix TEXT NOT NULL,
                name TEXT,
                created_at TEXT NOT NULL,
                last_used TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)
        
        conn.commit()
        cursor.close()
        conn.close()
    
    def register_user(
        self,
        username: str,
        password: str,
        role: str = "analyst"
    ) -> Tuple[bool, str]:
        """
        Register a new user
        
        Args:
            username: Username (must be unique)
            password: Plain text password (will be hashed)
            role: User role (admin or analyst)
            
        Returns:
            Tuple of (success, message)
        """
        # Validate role
        if role not in ["admin", "analyst"]:
            return False, "Invalid role. Must be 'admin' or 'analyst'"
        
        # Validate username
        if not username or len(username) < 3:
            return False, "Username must be at least 3 characters"
        
        # Validate password
        if not password or len(password) < 6:
            return False, "Password must be at least 6 characters"
        
        # Hash password
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute(
                "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                (username, password_hash.decode('utf-8'), role, datetime.utcnow().isoformat())
            )
            
            conn.commit()
            conn.close()
            
            return True, f"User '{username}' registered successfully"
            
        except sqlite3.IntegrityError:
            return False, f"Username '{username}' already exists"
        except Exception as e:
            return False, f"Registration failed: {str(e)}"
    
    def login(self, username: str, password: str) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        """
        Authenticate user and generate JWT token
        
        Args:
            username: Username
            password: Plain text password
            
        Returns:
            Tuple of (success, token, user_info)
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute(
                "SELECT id, username, password_hash, role FROM users WHERE username = ?",
                (username,)
            )
            
            user = cursor.fetchone()
            
            if not user:
                conn.close()
                return False, None, None
            
            user_id, username, password_hash, role = user
            
            # Verify password
            if not bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8')):
                conn.close()
                return False, None, None
            
            # Update last login
            cursor.execute(
                "UPDATE users SET last_login = ? WHERE id = ?",
                (datetime.utcnow().isoformat(), user_id)
            )
            conn.commit()
            conn.close()
            
            # Generate JWT token
            token = self._generate_jwt(user_id, username, role)
            
            user_info = {
                'id': user_id,
                'username': username,
                'role': role
            }
            
            return True, token, user_info
            
        except Exception as e:
            return False, None, None
    
    def _generate_jwt(self, user_id: int, username: str, role: str) -> str:
        """Generate JWT token"""
        payload = {
            'user_id': user_id,
            'username': username,
            'role': role,
            'exp': datetime.utcnow() + timedelta(hours=self.jwt_expiry_hours),
            'iat': datetime.utcnow()
        }
        
        token = jwt.encode(payload, self.jwt_secret, algorithm=self.jwt_algorithm)
        return token
    
    def verify_jwt(self, token: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Verify JWT token
        
        Args:
            token: JWT token string
            
        Returns:
            Tuple of (valid, payload)
        """
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm])
            return True, payload
        except jwt.ExpiredSignatureError:
            return False, None
        except jwt.InvalidTokenError:
            return False, None
    
    def generate_api_key(
        self,
        user_id: int,
        name: Optional[str] = None
    ) -> Tuple[bool, Optional[str], str]:
        """
        Generate API key for user
        
        Args:
            user_id: User ID
            name: Optional name/description for the key
            
        Returns:
            Tuple of (success, api_key, message)
        """
        try:
            # Generate random API key
            api_key = f"sla_{secrets.token_urlsafe(32)}"
            
            # Hash the key for storage
            key_hash = hashlib.sha256(api_key.encode('utf-8')).hexdigest()
            
            # Store prefix for identification (first 8 chars)
            key_prefix = api_key[:12]
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute(
                "INSERT INTO api_keys (user_id, key_hash, key_prefix, name, created_at) VALUES (?, ?, ?, ?, ?)",
                (user_id, key_hash, key_prefix, name, datetime.utcnow().isoformat())
            )
            
            conn.commit()
            conn.close()
            
            return True, api_key, "API key generated successfully"
            
        except Exception as e:
            return False, None, f"Failed to generate API key: {str(e)}"
    
    def verify_api_key(self, api_key: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Verify API key and return user info
        
        Args:
            api_key: API key string
            
        Returns:
            Tuple of (valid, user_info)
        """
        try:
            # Hash the provided key
            key_hash = hashlib.sha256(api_key.encode('utf-8')).hexdigest()
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT u.id, u.username, u.role, a.id as api_key_id
                FROM api_keys a
                JOIN users u ON a.user_id = u.id
                WHERE a.key_hash = ?
            """, (key_hash,))
            
            result = cursor.fetchone()
            
            if not result:
                conn.close()
                return False, None
            
            user_id, username, role, api_key_id = result
            
            # Update last used timestamp
            cursor.execute(
                "UPDATE api_keys SET last_used = ? WHERE id = ?",
                (datetime.utcnow().isoformat(), api_key_id)
            )
            conn.commit()
            conn.close()
            
            user_info = {
                'user_id': user_id,
                'username': username,
                'role': role
            }
            
            return True, user_info
            
        except Exception as e:
            return False, None
    
    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Get user information by ID"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute(
                "SELECT id, username, role, created_at, last_login FROM users WHERE id = ?",
                (user_id,)
            )
            
            user = cursor.fetchone()
            conn.close()
            
            if not user:
                return None
            
            return {
                'id': user[0],
                'username': user[1],
                'role': user[2],
                'created_at': user[3],
                'last_login': user[4]
            }
            
        except Exception:
            return None
    
    def list_api_keys(self, user_id: int) -> list:
        """List all API keys for a user"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT id, key_prefix, name, created_at, last_used
                FROM api_keys
                WHERE user_id = ?
                ORDER BY created_at DESC
            """, (user_id,))
            
            keys = cursor.fetchall()
            conn.close()
            
            return [
                {
                    'id': k[0],
                    'key_prefix': k[1],
                    'name': k[2],
                    'created_at': k[3],
                    'last_used': k[4]
                }
                for k in keys
            ]
            
        except Exception:
            return []
    
    def revoke_api_key(self, key_id: int, user_id: int) -> Tuple[bool, str]:
        """Revoke an API key"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute(
                "DELETE FROM api_keys WHERE id = ? AND user_id = ?",
                (key_id, user_id)
            )
            
            if cursor.rowcount == 0:
                conn.close()
                return False, "API key not found"
            
            conn.commit()
            conn.close()
            
            return True, "API key revoked successfully"
            
        except Exception as e:
            return False, f"Failed to revoke API key: {str(e)}"


def require_auth(required_role: Optional[str] = None):
    """
    Decorator to require authentication for endpoints
    
    Args:
        required_role: Optional role requirement ('admin' or 'analyst')
                      If None, any authenticated user can access
    
    Usage:
        @require_auth()  # Any authenticated user
        @require_auth('admin')  # Admin only
        @require_auth('analyst')  # Analyst or admin
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get auth manager from Flask app config
            from flask import current_app
            auth_manager = current_app.config.get('AUTH_MANAGER')
            
            if not auth_manager:
                return jsonify({'error': 'Authentication not configured'}), 500
            
            # Try JWT token first (Bearer token)
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
                valid, payload = auth_manager.verify_jwt(token)
                
                if valid:
                    # Check role if required
                    if required_role and payload['role'] != 'admin':
                        if required_role == 'admin':
                            return jsonify({'error': 'Admin access required'}), 403
                    
                    # Attach user info to request
                    request.user = payload
                    return f(*args, **kwargs)
            
            # Try API key (X-API-Key header)
            api_key = request.headers.get('X-API-Key')
            if api_key:
                valid, user_info = auth_manager.verify_api_key(api_key)
                
                if valid:
                    # Check role if required
                    if required_role and user_info['role'] != 'admin':
                        if required_role == 'admin':
                            return jsonify({'error': 'Admin access required'}), 403
                    
                    # Attach user info to request
                    request.user = user_info
                    return f(*args, **kwargs)
            
            # No valid authentication
            return jsonify({'error': 'Authentication required'}), 401
        
        return decorated_function
    return decorator
