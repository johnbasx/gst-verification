import pytest
import json
import uuid
from unittest.mock import patch, Mock
from datetime import datetime, timedelta

from app import app, gst_sessions, validate_gstin, clean_expired_sessions, Config


@pytest.fixture
def client():
    """Create a test client for the Flask application."""
    app.config['TESTING'] = True
    with app.test_client() as client:
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
        response = client.get('/api/v1/health')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['status'] == 'healthy'
        assert data['service'] == 'GST Verification API'
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
            "01abcde0123f1z5",  # Lowercase letters
            "01ABCDE0123F0Z5",  # Invalid check digit
            "",  # Empty string
            None  # None value
        ]
        
        for gstin in invalid_gstins:
            assert validate_gstin(gstin) == False
    
    def test_validate_gstin_endpoint(self, client):
        """Test GSTIN validation endpoint."""
        # Test valid GSTIN
        response = client.post('/api/v1/validateGSTIN',
                             json={'gstin': '01ABCDE0123F1Z5'},
                             content_type='application/json')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['success'] == True
        assert data['data']['is_valid'] == True
        assert data['data']['gstin'] == '01ABCDE0123F1Z5'
        
        # Test invalid GSTIN
        response = client.post('/api/v1/validateGSTIN',
                             json={'gstin': 'invalid'},
                             content_type='application/json')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['success'] == True
        assert data['data']['is_valid'] == False
        
        # Test missing GSTIN
        response = client.post('/api/v1/validateGSTIN',
                             json={},
                             content_type='application/json')
        assert response.status_code == 400
        
        data = json.loads(response.data)
        assert data['success'] == False
        assert data['error_code'] == 'MISSING_GSTIN'


class TestCaptchaEndpoint:
    """Test captcha fetching functionality."""
    
    @patch('app.requests.Session')
    def test_get_captcha_success(self, mock_session_class, client):
        """Test successful captcha fetching."""
        # Setup mock
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        
        # Mock session initialization
        mock_init_response = Mock()
        mock_init_response.status_code = 200
        
        # Mock captcha response
        mock_captcha_response = Mock()
        mock_captcha_response.status_code = 200
        mock_captcha_response.content = b'fake_captcha_data'
        
        mock_session.get.side_effect = [mock_init_response, mock_captcha_response]
        
        # Make request
        response = client.get('/api/v1/getCaptcha')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['success'] == True
        assert 'session_id' in data['data']
        assert 'captcha_image' in data['data']
        assert data['data']['captcha_image'].startswith('data:image/png;base64,')
        assert data['data']['expires_in'] == Config.SESSION_TIMEOUT
    
    @patch('app.requests.Session')
    def test_get_captcha_session_init_failure(self, mock_session_class, client):
        """Test captcha fetching when session initialization fails."""
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        
        # Mock failed session initialization
        mock_init_response = Mock()
        mock_init_response.status_code = 500
        mock_session.get.return_value = mock_init_response
        
        response = client.get('/api/v1/getCaptcha')
        assert response.status_code == 500
        
        data = json.loads(response.data)
        assert data['success'] == False
        assert data['error_code'] == 'SESSION_INIT_FAILED'
    
    @patch('app.requests.Session')
    def test_get_captcha_timeout(self, mock_session_class, client):
        """Test captcha fetching timeout."""
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        
        # Mock timeout exception
        from requests.exceptions import Timeout
        mock_session.get.side_effect = Timeout()
        
        response = client.get('/api/v1/getCaptcha')
        assert response.status_code == 504
        
        data = json.loads(response.data)
        assert data['success'] == False
        assert data['error_code'] == 'TIMEOUT_ERROR'


class TestGSTDetailsEndpoint:
    """Test GST details fetching functionality."""
    
    def setup_method(self):
        """Setup test session."""
        self.session_id = str(uuid.uuid4())
        mock_session = Mock()
        gst_sessions[self.session_id] = {
            'session': mock_session,
            'created_at': datetime.now(),
            'requests_count': 0
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
        
        gst_sessions[self.session_id]['session'].post.return_value = mock_response
        
        # Make request
        response = client.post('/api/v1/getGSTDetails',
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
        assert data['data']['lgnm'] == 'Test Company'
    
    def test_get_gst_details_invalid_session(self, client):
        """Test GST details fetching with invalid session."""
        response = client.post('/api/v1/getGSTDetails',
                             json={
                                 'session_id': 'invalid-session-id',
                                 'gstin': '01ABCDE0123F1Z5',
                                 'captcha': 'ABC123'
                             },
                             content_type='application/json')
        
        assert response.status_code == 400
        
        data = json.loads(response.data)
        assert data['success'] == False
        assert data['error_code'] == 'INVALID_SESSION'
    
    def test_get_gst_details_missing_fields(self, client):
        """Test GST details fetching with missing fields."""
        test_cases = [
            {},  # Empty request
            {'session_id': self.session_id},  # Missing gstin and captcha
            {'session_id': self.session_id, 'gstin': '01ABCDE0123F1Z5'},  # Missing captcha
            {'gstin': '01ABCDE0123F1Z5', 'captcha': 'ABC123'},  # Missing session_id
        ]
        
        for test_data in test_cases:
            response = client.post('/api/v1/getGSTDetails',
                                 json=test_data,
                                 content_type='application/json')
            
            assert response.status_code == 400
            
            data = json.loads(response.data)
            assert data['success'] == False
            assert data['error_code'] in ['MISSING_FIELDS', 'EMPTY_REQUEST']
    
    def test_get_gst_details_invalid_gstin(self, client):
        """Test GST details fetching with invalid GSTIN."""
        response = client.post('/api/v1/getGSTDetails',
                             json={
                                 'session_id': self.session_id,
                                 'gstin': 'invalid-gstin',
                                 'captcha': 'ABC123'
                             },
                             content_type='application/json')
        
        assert response.status_code == 400
        
        data = json.loads(response.data)
        assert data['success'] == False
        assert data['error_code'] == 'INVALID_GSTIN'
    
    def test_get_gst_details_invalid_captcha(self, client):
        """Test GST details fetching with invalid captcha."""
        invalid_captchas = ['', '  ', 'AB']  # Empty, whitespace, too short
        
        for captcha in invalid_captchas:
            response = client.post('/api/v1/getGSTDetails',
                                 json={
                                     'session_id': self.session_id,
                                     'gstin': '01ABCDE0123F1Z5',
                                     'captcha': captcha
                                 },
                                 content_type='application/json')
            
            assert response.status_code == 400
            
            data = json.loads(response.data)
            assert data['success'] == False
            assert data['error_code'] == 'INVALID_CAPTCHA'
    
    def test_get_gst_details_expired_session(self, client):
        """Test GST details fetching with expired session."""
        # Set session creation time to past
        gst_sessions[self.session_id]['created_at'] = datetime.now() - timedelta(seconds=Config.SESSION_TIMEOUT + 1)
        
        response = client.post('/api/v1/getGSTDetails',
                             json={
                                 'session_id': self.session_id,
                                 'gstin': '01ABCDE0123F1Z5',
                                 'captcha': 'ABC123'
                             },
                             content_type='application/json')
        
        assert response.status_code == 400
        
        data = json.loads(response.data)
        assert data['success'] == False
        assert data['error_code'] == 'SESSION_EXPIRED'
    
    def test_get_gst_details_invalid_content_type(self, client):
        """Test GST details fetching with invalid content type."""
        response = client.post('/api/v1/getGSTDetails',
                             data='not json',
                             content_type='text/plain')
        
        assert response.status_code == 400
        
        data = json.loads(response.data)
        assert data['success'] == False
        assert data['error_code'] == 'INVALID_CONTENT_TYPE'


class TestSessionManagement:
    """Test session management functionality."""
    
    def test_clean_expired_sessions(self):
        """Test cleaning of expired sessions."""
        # Add active session
        active_session_id = str(uuid.uuid4())
        gst_sessions[active_session_id] = {
            'session': Mock(),
            'created_at': datetime.now(),
            'requests_count': 0
        }
        
        # Add expired session
        expired_session_id = str(uuid.uuid4())
        gst_sessions[expired_session_id] = {
            'session': Mock(),
            'created_at': datetime.now() - timedelta(seconds=Config.SESSION_TIMEOUT + 1),
            'requests_count': 0
        }
        
        # Clean expired sessions
        clean_expired_sessions()
        
        # Check results
        assert active_session_id in gst_sessions
        assert expired_session_id not in gst_sessions
        
        # Clean up
        gst_sessions.clear()


class TestErrorHandlers:
    """Test error handling functionality."""
    
    def test_404_error(self, client):
        """Test 404 error handler."""
        response = client.get('/nonexistent-endpoint')
        assert response.status_code == 404
        
        data = json.loads(response.data)
        assert data['success'] == False
        assert data['error_code'] == 'NOT_FOUND'
    
    def test_405_error(self, client):
        """Test 405 error handler."""
        response = client.post('/api/v1/health')  # GET endpoint called with POST
        assert response.status_code == 405
        
        data = json.loads(response.data)
        assert data['success'] == False
        assert data['error_code'] == 'METHOD_NOT_ALLOWED'


class TestRateLimiting:
    """Test rate limiting functionality."""
    
    @patch('app.requests.Session')
    def test_rate_limiting(self, mock_session_class, client):
        """Test rate limiting on captcha endpoint."""
        # Setup mock
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        
        mock_init_response = Mock()
        mock_init_response.status_code = 200
        
        mock_captcha_response = Mock()
        mock_captcha_response.status_code = 200
        mock_captcha_response.content = b'fake_captcha_data'
        
        mock_session.get.side_effect = [mock_init_response, mock_captcha_response] * 25
        
        # Make requests up to the limit
        for i in range(20):  # Rate limit is 20 requests per 60 seconds
            response = client.get('/api/v1/getCaptcha')
            assert response.status_code == 200
        
        # Next request should be rate limited
        response = client.get('/api/v1/getCaptcha')
        assert response.status_code == 429
        
        data = json.loads(response.data)
        assert data['success'] == False
        assert data['error'] == 'Rate limit exceeded'


if __name__ == '__main__':
    pytest.main(['-v', '--cov=app', '--cov-report=html'])