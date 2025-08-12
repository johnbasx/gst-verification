import pytest
import json
import uuid
from unittest.mock import patch, Mock
from datetime import datetime, timedelta

from app import app_instance, gst_sessions, validate_gstin, clean_expired_sessions
from config import get_config


@pytest.fixture
def client():
    """Create a test client for the Flask application."""
    app_instance.config['TESTING'] = True
    with app_instance.test_client() as client:
        yield client


@pytest.fixture
def mock_session():
    """Create a mock session for testing."""
    session = Mock()
    session.get.return_value.status_code = 200
    session.get.return_value.content = b'fake_captcha_image_data'
    session.post.return_value.status_code = 200
    session.post.return_value.json.return_value = {
        "gstin": "01ABCDE0123F0AA",
        "lgnm": "Test Company",
        "sts": "Active"
    }
    return session


class TestHealthCheck:
    """Test health check endpoint."""
    
    def test_health_check(self, client):
        """Test health check endpoint returns correct response."""
        response = client.get('/health')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['status'] == 'healthy'
        assert data['version'] == '1.0.0'
        assert 'timestamp' in data


class TestGSTINValidation:
    """Test GSTIN validation functionality."""
    
    def test_valid_gstin(self):
        """Test validation of valid GSTIN."""
        valid_gstins = [
            "01ABCDE0123F1Z5",
            "27ABCDE0123F1Z5",
            "09ABCDE0123F1Z5"
        ]
        
        for gstin in valid_gstins:
            assert validate_gstin(gstin) == True
    
    def test_invalid_gstin(self):
        """Test validation of invalid GSTIN."""
        invalid_gstins = [
            "01ABCDE0123F1Z",  # Too short
            "01ABCDE0123F1Z55",  # Too long
            "ABCDE0123F1Z55",  # Missing state code
            "01ABCDE0123F1@5",  # Invalid character
            "",  # Empty string
            None  # None value
        ]
        
        for gstin in invalid_gstins:
            assert validate_gstin(gstin) == False
            
        # Test lowercase - should be valid after uppercase conversion
        assert validate_gstin("01abcde0123f1z5") == True
    
    def test_validate_gstin_endpoint(self, client):
        """Test GSTIN validation endpoint."""
        # Test valid GSTIN
        response = client.post('/validate-gstin',
                             json={'gstin': '01ABCDE0123F1Z5'},
                             content_type='application/json')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['success'] == True
        assert data['data']['is_valid'] == True
        assert data['data']['gstin'] == '01ABCDE0123F1Z5'
        
        # Test invalid GSTIN
        response = client.post('/validate-gstin',
                             json={'gstin': 'invalid'},
                             content_type='application/json')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['success'] == True
        assert data['data']['is_valid'] == False
        
        # Test missing GSTIN
        response = client.post('/validate-gstin',
                             json={},
                             content_type='application/json')
        assert response.status_code == 400
        
        data = json.loads(response.data)
        assert data['success'] == False
        assert data['error'] == 'invalid_request_format'


class TestCaptchaEndpoint:
    """Test captcha fetching functionality."""
    
    @patch('app.requests.Session')
    def test_get_captcha_success(self, mock_session_class, client):
        """Test successful captcha fetching."""
        # Setup mock session
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        
        # Mock captcha response with sufficient content length (>100 bytes)
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b'fake_captcha_data' * 20  # Make it longer than 100 bytes
        mock_response.headers = {'content-type': 'image/png'}
        mock_response.raise_for_status.return_value = None
        mock_session.get.return_value = mock_response
        
        # Make request
        response = client.get('/captcha')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['success'] == True
        assert 'session_id' in data['data']
        assert 'captcha_image' in data['data']
        assert data['data']['captcha_image'].startswith('data:image/png;base64,')


class TestGSTDetailsEndpoint:
    """Test GST details fetching functionality."""
    
    def setup_method(self):
        """Setup test session."""
        self.session_id = str(uuid.uuid4())
        mock_session = Mock()
        gst_sessions[self.session_id] = {
            'requests_session': mock_session,
            'created_at': datetime.now(),
            'request_count': 0,
            'last_activity': datetime.now()
        }
    
    def teardown_method(self):
        """Clean up test sessions."""
        gst_sessions.clear()
    
    def test_get_gst_details_success(self, client):
        """Test successful GST details fetching."""
        # Setup mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "gstin": "01ABCDE0123F1Z5",
            "lgnm": "Test Company",
            "sts": "Active"
        }
        
        gst_sessions[self.session_id]['requests_session'].post.return_value = mock_response
        
        # Make request
        response = client.post('/gst-details',
                             json={
                                 'session_id': self.session_id,
                                 'gstin': '01ABCDE0123F1Z5',
                                 'captcha': 'ABC123'
                             },
                             content_type='application/json')
        
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['success'] == True
        assert data['data']['gstin'] == '01ABCDE0123F1Z5'
        assert data['data']['legal_name'] == 'Test Company'
    
    def test_get_gst_details_invalid_session(self, client):
        """Test GST details fetching with invalid session."""
        response = client.post('/gst-details',
                             json={
                                 'session_id': 'invalid-session-id',
                                 'gstin': '01ABCDE0123F1Z5',
                                 'captcha': 'ABC123'
                             },
                             content_type='application/json')
        
        assert response.status_code == 400
        
        data = json.loads(response.data)
        assert data['success'] == False
        assert data['error'] == 'invalid_session'
    
    def test_get_gst_details_missing_fields(self, client):
        """Test GST details fetching with missing fields."""
        # Test completely empty request
        response = client.post('/gst-details',
                             json={},
                             content_type='application/json')
        
        assert response.status_code == 400
        
        data = json.loads(response.data)
        assert data['success'] == False
        assert data['error'] == 'invalid_request_format'
        
        # Test partial request (missing captcha)
        response = client.post('/gst-details',
                             json={
                                 'session_id': self.session_id,
                                 'gstin': '01ABCDE0123F1Z5'
                             },
                             content_type='application/json')
        
        assert response.status_code == 400
        
        data = json.loads(response.data)
        assert data['success'] == False
        assert data['error'] == 'missing_required_fields'


class TestGSTServicesEndpoint:
    """Test GST services/goods details fetching functionality."""
    
    @patch('app.requests.Session')
    def test_get_gst_services_success(self, mock_session_class, client):
        """Test successful GST services fetching."""
        # Setup mock
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        
        # Mock services response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "bzsdtls": [
                {
                    "saccd": "996791",
                    "sdes": "Goods transport agency services for road transport"
                },
                {
                    "saccd": "00440193",
                    "sdes": "STORAGE AND WAREHOUSE SERVICE"
                },
                {
                    "saccd": "00440189",
                    "sdes": "CARGO HANDLING SERVICES"
                }
            ]
        }
        
        mock_session.get.return_value = mock_response
        
        # Make request
        response = client.post('/gst-services',
                             json={'gstin': '24AAACC1206D1ZM'},
                             content_type='application/json')
        
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['success'] == True
        assert data['data']['gstin'] == '24AAACC1206D1ZM'
        assert data['data']['total_activities'] == 3
        assert len(data['data']['business_activities']) == 3
        
        # Check first activity
        first_activity = data['data']['business_activities'][0]
        assert first_activity['sac_code'] == '996791'
        assert first_activity['service_description'] == 'Goods transport agency services for road transport'
        assert first_activity['category'] == 'Service'
    
    def test_get_gst_services_missing_gstin(self, client):
        """Test GST services fetching with missing GSTIN."""
        response = client.post('/gst-services',
                             json={},
                             content_type='application/json')
        
        assert response.status_code == 400
        
        data = json.loads(response.data)
        assert data['success'] == False
        assert data['error'] == 'invalid_request_format'
    
    def test_get_gst_services_invalid_gstin(self, client):
        """Test GST services fetching with invalid GSTIN format."""
        response = client.post('/gst-services',
                             json={'gstin': 'invalid-gstin'},
                             content_type='application/json')
        
        assert response.status_code == 400
        
        data = json.loads(response.data)
        assert data['success'] == False
        assert data['error'] == 'invalid_gstin_format'
    
    @patch('app.requests.Session')
    def test_get_gst_services_not_found(self, mock_session_class, client):
        """Test GST services fetching for non-existent GSTIN."""
        # Setup mock
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        
        # Mock not found response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "error": "GSTIN not found",
            "message": "GSTIN not found in records"
        }
        
        mock_session.get.return_value = mock_response
        
        # Make request
        response = client.post('/gst-services',
                             json={'gstin': '01ABCDE0123F1Z5'},
                             content_type='application/json')
        
        assert response.status_code == 404
        
        data = json.loads(response.data)
        assert data['success'] == False
        assert data['error'] == 'gstin_not_found'
    
    @patch('app.requests.Session')
    def test_get_gst_services_timeout(self, mock_session_class, client):
        """Test GST services fetching with timeout error."""
        # Setup mock
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        
        # Mock timeout exception
        from requests.exceptions import Timeout
        mock_session.get.side_effect = Timeout("Request timeout")
        
        # Make request
        response = client.post('/gst-services',
                             json={'gstin': '24AAACC1206D1ZM'},
                             content_type='application/json')
        
        assert response.status_code == 504
        
        data = json.loads(response.data)
        assert data['success'] == False
        assert data['error'] == 'timeout_error'


class TestSessionManagement:
    """Test session management functionality."""
    
    def test_clean_expired_sessions(self):
        """Test cleaning of expired sessions."""
        # Add test sessions
        current_time = datetime.now()
        expired_time = current_time - timedelta(minutes=10)
        
        # Add expired session
        expired_session_id = str(uuid.uuid4())
        gst_sessions[expired_session_id] = {
            'requests_session': Mock(),
            'created_at': expired_time,
            'request_count': 0,
            'last_activity': expired_time
        }
        
        # Add active session
        active_session_id = str(uuid.uuid4())
        gst_sessions[active_session_id] = {
            'requests_session': Mock(),
            'created_at': current_time,
            'request_count': 0,
            'last_activity': current_time
        }
        
        # Clean expired sessions
        cleaned_count = clean_expired_sessions()
        
        # Verify results
        assert cleaned_count == 1
        assert expired_session_id not in gst_sessions
        assert active_session_id in gst_sessions
        
        # Clean up
        gst_sessions.clear()


class TestRootEndpoint:
    """Test root API endpoint."""
    
    def test_root_endpoint(self, client):
        """Test root endpoint returns API information."""
        response = client.get('/')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['success'] == True
        assert data['message'] == 'GST Verification API'
        assert data['version'] == '1.0.0'
        assert 'endpoints' in data
        
        # Check that all endpoints are documented
        endpoints = data['endpoints']
        assert 'health' in endpoints
        assert 'captcha' in endpoints
        assert 'gst_details' in endpoints
        assert 'gst_services' in endpoints
        assert 'validate_gstin' in endpoints


if __name__ == '__main__':
    pytest.main(['-v', '--tb=short'])