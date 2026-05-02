"""
Test suite for API endpoints
Step 1 verification tests
"""
import pytest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from main import create_app


@pytest.fixture
def client():
    """Create test client"""
    app = create_app()
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_health_endpoint(client):
    """Test health check endpoint"""
    response = client.get('/api/health')
    
    assert response.status_code == 200
    
    data = response.get_json()
    assert data['status'] == 'ok'
    assert 'timestamp' in data
    assert data['service'] == 'Security Log Analyzer'
    assert data['version'] == '1.0.0'
    
    print("✅ Health endpoint test passed")


def test_ingest_placeholder(client):
    """Test ingest endpoint placeholder"""
    response = client.post('/api/ingest')
    
    assert response.status_code == 501
    data = response.get_json()
    assert data['status'] == 'not_implemented'
    
    print("✅ Ingest placeholder test passed")


def test_query_placeholder(client):
    """Test query endpoint placeholder"""
    response = client.post('/api/query')
    
    assert response.status_code == 501
    data = response.get_json()
    assert data['status'] == 'not_implemented'
    
    print("✅ Query placeholder test passed")


def test_stats_placeholder(client):
    """Test stats endpoint placeholder"""
    response = client.get('/api/stats')
    
    assert response.status_code == 501
    data = response.get_json()
    assert data['status'] == 'not_implemented'
    
    print("✅ Stats placeholder test passed")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
