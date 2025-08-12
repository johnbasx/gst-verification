#!/usr/bin/env python3
"""
GST Verification API

A professional Flask API for fetching GST details from the official GST website.
This service handles captcha solving and provides structured GST information.

Features:
- Captcha fetching and handling
- GST details retrieval
- GSTIN validation
- Session management
- Rate limiting
- Comprehensive error handling
- Health checks
- Performance monitoring
- Structured logging
- Caching optimization
- Async processing
"""

import os
import re
import time
import uuid
import base64
import logging
import requests
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple
from functools import wraps

from flask import Flask, request, jsonify, g
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config import get_config, validate_config
from swagger import create_swagger_api

# Global variables for components
app = None
limiter = None
logger = None

# In-memory session storage (use Redis in production)
sessions = {}
gst_sessions: Dict[str, Dict[str, Any]] = {}


def setup_basic_logging():
    """Setup basic logging configuration."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('logs/gst_api.log')
        ]
    )
    return logging.getLogger('gst_api')


def create_app(config_name: Optional[str] = None) -> Flask:
    """Application factory pattern for creating Flask app."""
    global app, limiter, logger
    
    # Create Flask app
    app = Flask(__name__)
    
    # Load configuration
    config = get_config(config_name)
    app.config.from_object(config)
    app.config['START_TIME'] = datetime.now()
    app.config['VERSION'] = '1.0.0'
    
    # Validate configuration
    try:
        validate_config(app.config)
    except ValueError as e:
        print(f"Configuration validation failed: {e}")
        # Continue with warnings for development
    
    # Initialize basic logging
    logger = setup_basic_logging()
    
    # Setup CORS
    CORS(app, 
         origins=app.config.get('CORS_ORIGINS', ['*']),
         methods=['GET', 'POST'],
         allow_headers=['Content-Type', 'Authorization'])
    
    # Setup rate limiting with memory storage for development
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["100 per hour"],
        storage_uri="memory://",
        strategy="fixed-window"
    )
    
    # Register error handlers
    register_error_handlers(app)
    
    # Register routes
    register_routes(app)
    
    # Add Swagger API documentation
    create_swagger_api(app)
    
    # Setup middleware
    setup_middleware(app)
    
    logger.info(f"GST Verification API initialized in {app.config.get('FLASK_ENV', 'unknown')} mode")
    
    return app


def setup_middleware(app: Flask):
    """Setup middleware for request processing."""
    
    @app.before_request
    def before_request():
        """Process request before handling."""
        g.request_id = str(uuid.uuid4())
        g.start_time = time.time()
        
        # Log request start
        logger.info(
            f"Request started: {request.method} {request.path}",
            extra={
                'request_id': g.request_id,
                'method': request.method,
                'path': request.path,
                'remote_addr': request.remote_addr,
                'user_agent': request.headers.get('User-Agent', '')
            }
        )
    
    @app.after_request
    def after_request(response):
        """Process response after handling."""
        if hasattr(g, 'start_time'):
            duration = time.time() - g.start_time
            
            # Log request completion
            logger.info(
                f"Request completed: {request.method} {request.path} - {response.status_code} - {duration:.3f}s",
                extra={
                    'request_id': getattr(g, 'request_id', 'unknown'),
                    'method': request.method,
                    'path': request.path,
                    'status_code': response.status_code,
                    'duration': duration,
                    'response_size': len(response.get_data())
                }
            )
        
        # Add security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Content-Security-Policy'] = "default-src 'self'"
        
        return response


def register_error_handlers(app: Flask):
    """Register error handlers for the application."""
    
    @app.errorhandler(400)
    def bad_request(error):
        """Handle bad request errors."""
        logger.warning(f"Bad request: {error}", extra={'request_id': getattr(g, 'request_id', 'unknown')})
        return jsonify({
            'success': False,
            'error': 'Bad Request',
            'message': 'The request was malformed or invalid',
            'error_code': 'BAD_REQUEST',
            'request_id': getattr(g, 'request_id', 'unknown')
        }), 400
    
    @app.errorhandler(404)
    def not_found(error):
        """Handle not found errors."""
        logger.warning(f"Not found: {request.path}", extra={'request_id': getattr(g, 'request_id', 'unknown')})
        return jsonify({
            'success': False,
            'error': 'Not Found',
            'message': 'The requested resource was not found',
            'error_code': 'NOT_FOUND',
            'request_id': getattr(g, 'request_id', 'unknown')
        }), 404
    
    @app.errorhandler(429)
    def rate_limit_exceeded(error):
        """Handle rate limit exceeded errors."""
        logger.warning(f"Rate limit exceeded: {request.path}", 
                      extra={'request_id': getattr(g, 'request_id', 'unknown')})
        
        return jsonify({
            'success': False,
            'error': 'Rate Limit Exceeded',
            'message': 'Too many requests. Please try again later.',
            'error_code': 'RATE_LIMIT_EXCEEDED',
            'retry_after': getattr(error, 'retry_after', 60),
            'request_id': getattr(g, 'request_id', 'unknown')
        }), 429
    
    @app.errorhandler(500)
    def internal_error(error):
        """Handle internal server errors."""
        logger.error(f"Internal server error: {error}", 
                    exc_info=True,
                    extra={'request_id': getattr(g, 'request_id', 'unknown')})
        
        return jsonify({
            'success': False,
            'error': 'Internal Server Error',
            'message': 'An unexpected error occurred. Please try again later.',
            'error_code': 'INTERNAL_ERROR',
            'request_id': getattr(g, 'request_id', 'unknown')
        }), 500


# Utility functions
def validate_gstin(gstin: str) -> bool:
    """
    Validate GSTIN format.
    
    GSTIN format: 15 characters
    - First 2 characters: State code (digits)
    - Next 10 characters: PAN (alphanumeric)
    - 13th character: Entity number (digit)
    - 14th character: Z (default)
    - 15th character: Check digit (alphanumeric)
    """
    if not gstin or len(gstin) != 15:
        return False
    
    # GSTIN pattern: 2 digits + 10 alphanumeric + 1 digit + Z + 1 alphanumeric
    pattern = r'^[0-9]{2}[A-Z0-9]{10}[0-9]{1}Z[A-Z0-9]{1}$'
    is_valid = bool(re.match(pattern, gstin.upper()))
    
    return is_valid


def clean_expired_sessions() -> int:
    """Remove expired sessions from memory."""
    current_time = datetime.now()
    session_timeout = app.config.get('SESSION_TIMEOUT', 300) if app else 300
    
    expired_sessions = [
        session_id for session_id, session_data in gst_sessions.items()
        if current_time - session_data.get('created_at', current_time) > timedelta(seconds=session_timeout)
    ]
    
    for session_id in expired_sessions:
        # Close requests session if it exists
        if 'requests_session' in gst_sessions[session_id]:
            try:
                gst_sessions[session_id]['requests_session'].close()
            except Exception as e:
                logger.warning(f"Error closing requests session: {e}")
        
        del gst_sessions[session_id]
        logger.info(f"Expired session removed: {session_id}")
    
    return len(expired_sessions)


def create_session() -> str:
    """Create a new session and return session ID."""
    session_id = str(uuid.uuid4())
    
    # Create optimized requests session
    requests_session = requests.Session()
    
    # Configure session with optimizations
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    
    retry_strategy = Retry(
        total=3,
        backoff_factor=0.3,
        status_forcelist=[429, 500, 502, 503, 504]
    )
    
    adapter = HTTPAdapter(
        pool_connections=10,
        pool_maxsize=20,
        max_retries=retry_strategy
    )
    
    requests_session.mount("http://", adapter)
    requests_session.mount("https://", adapter)
    
    gst_sessions[session_id] = {
        'created_at': datetime.now(),
        'requests_session': requests_session,
        'request_count': 0,
        'last_activity': datetime.now()
    }
    
    # Clean expired sessions periodically
    if len(gst_sessions) % 10 == 0:
        clean_expired_sessions()
    
    logger.info(f"New session created: {session_id}")
    
    return session_id


def get_session(session_id: str) -> Optional[Dict[str, Any]]:
    """Get session data by session ID."""
    if not session_id or session_id not in gst_sessions:
        return None
    
    session_data = gst_sessions[session_id]
    session_timeout = app.config.get('SESSION_TIMEOUT', 300) if app else 300
    
    # Check if session is expired
    if datetime.now() - session_data['created_at'] > timedelta(seconds=session_timeout):
        # Close requests session
        if 'requests_session' in session_data:
            try:
                session_data['requests_session'].close()
            except Exception as e:
                logger.warning(f"Error closing requests session: {e}")
        
        del gst_sessions[session_id]
        logger.info(f"Expired session removed: {session_id}")
        
        return None
    
    # Update last activity
    session_data['last_activity'] = datetime.now()
    session_data['request_count'] = session_data.get('request_count', 0) + 1
    
    return session_data


def register_routes(app: Flask):
    """Register all API routes."""
    
    @app.route('/', methods=['GET'])
    def root():
        """Root endpoint providing API information and documentation links."""
        return jsonify({
            'success': True,
            'message': 'GST Verification API',
            'version': app.config.get('VERSION', '1.0.0'),
            'description': 'Professional API for GST verification and validation services using official GST portal endpoints',
            'documentation': {
                'swagger_ui': '/api/v1/docs/',
                'openapi_spec': '/api/v1/swagger.json',
                'description': 'Interactive API documentation with request/response examples and testing capabilities'
            },
            'endpoints': {
                'health': '/health - Health check endpoint',
                'captcha': '/captcha - Get captcha image (requires session)',
                'gst_details': '/gst-details - Get GST details using GSTIN and captcha',
                'gst_services': '/gst-services - Get GST services/goods details for a GSTIN',
                'validate_gstin': '/validate-gstin - Validate GSTIN format'
            },
            'features': [
                'Official GST Portal Integration',
                'Captcha Handling',
                'Session Management',
                'Rate Limiting',
                'Comprehensive Error Handling',
                'OpenAPI/Swagger Documentation'
            ],
            'getting_started': {
                'step_1': 'Visit /api/v1/docs/ for interactive API documentation',
                'step_2': 'Get captcha from /captcha endpoint',
                'step_3': 'Use session_id and captcha to fetch GST details',
                'step_4': 'Validate GSTIN format using /validate-gstin endpoint'
            },
            'timestamp': datetime.now().isoformat(),
            'request_id': getattr(g, 'request_id', 'unknown')
        }), 200
    
    @app.route('/health', methods=['GET'])
    def health_check():
        """Enhanced health check endpoint."""
        try:
            start_time = datetime.now()
            
            # Calculate response time
            response_time = (datetime.now() - start_time).total_seconds() * 1000
            
            response_data = {
                'status': 'healthy',
                'timestamp': datetime.now().isoformat(),
                'version': app.config.get('VERSION', '1.0.0'),
                'uptime': str(datetime.now() - app.config.get('START_TIME', datetime.now())),
                'response_time_ms': round(response_time, 2),
                'active_sessions': len(gst_sessions)
            }
            
            return jsonify(response_data), 200
            
        except Exception as e:
            logger.error(f"Health check failed: {str(e)}")
            return jsonify({
                'status': 'unhealthy',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }), 503
    
    @app.route('/captcha', methods=['GET'])
    @limiter.limit("30 per minute")
    def get_captcha():
        """Get captcha image from GST portal."""
        session_id = None
        try:
            # Create session
            session_id = create_session()
            session_data = get_session(session_id)
            
            if not session_data:
                logger.error("Failed to create session for captcha retrieval")
                return jsonify({
                    'success': False,
                    'error': 'session_creation_failed',
                    'message': 'Unable to initialize session for captcha retrieval'
                }), 500
            
            requests_session = session_data['requests_session']
            
            # Get captcha from GST portal
            captcha_url = "https://services.gst.gov.in/services/captcha"
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'image/png,image/*;q=0.8,*/*;q=0.5',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive',
                'Cache-Control': 'no-cache',
                'Pragma': 'no-cache'
            }
            
            # Make request with timeout
            timeout = app.config.get('REQUEST_TIMEOUT', 10)
            response = requests_session.get(
                captcha_url, 
                headers=headers, 
                timeout=timeout,
                verify=True
            )
            response.raise_for_status()
            
            # Validate response content
            if not response.content or len(response.content) < 100:
                raise ValueError("Invalid captcha response received")
            
            # Convert image to base64
            captcha_base64 = base64.b64encode(response.content).decode('utf-8')
            
            # Store captcha metadata in session
            session_data['captcha_retrieved_at'] = datetime.now()
            session_data['captcha_size'] = len(response.content)
            
            # Log successful captcha retrieval
            logger.info(f"Captcha retrieved successfully for session: {session_id}")
            
            return jsonify({
                'success': True,
                'data': {
                    'session_id': session_id,
                    'captcha_image': f"data:image/png;base64,{captcha_base64}",
                    'expires_in': app.config.get('SESSION_TIMEOUT', 300)
                },
                'message': 'Captcha retrieved successfully'
            }), 200
            
        except requests.exceptions.Timeout:
            logger.error(f"Timeout while fetching captcha for session: {session_id}")
            return jsonify({
                'success': False,
                'error': 'timeout_error',
                'message': 'Request timeout while fetching captcha from GST portal'
            }), 504
        except requests.exceptions.ConnectionError:
            logger.error(f"Connection error while fetching captcha for session: {session_id}")
            return jsonify({
                'success': False,
                'error': 'connection_error',
                'message': 'Unable to connect to GST portal'
            }), 502
        except Exception as e:
            logger.error(f"Unexpected error in get_captcha: {str(e)}")
            return jsonify({
                'success': False,
                'error': 'internal_server_error',
                'message': 'An unexpected error occurred while fetching captcha'
            }), 500
    
    @app.route('/gst-details', methods=['POST'])
    @limiter.limit("10 per minute")
    def get_gst_details():
        """Get GST details using GSTIN and captcha."""
        session_id = None
        gstin = None
        
        try:
            data = request.get_json()
            
            if not data:
                return jsonify({
                    'success': False,
                    'error': 'invalid_request_format',
                    'message': 'Request body must be valid JSON'
                }), 400
            
            session_id = data.get('session_id')
            gstin = data.get('gstin', '').strip().upper()
            captcha = data.get('captcha', '').strip()
            
            # Validate required fields
            if not all([session_id, gstin, captcha]):
                return jsonify({
                    'success': False,
                    'error': 'missing_required_fields',
                    'message': 'session_id, gstin, and captcha are required',
                    'required_fields': ['session_id', 'gstin', 'captcha']
                }), 400
            
            # Validate GSTIN format
            if not validate_gstin(gstin):
                return jsonify({
                    'success': False,
                    'error': 'invalid_gstin_format',
                    'message': 'GSTIN format is invalid. Expected format: 15 characters (2 digits + 10 alphanumeric + 1 digit + Z + 1 alphanumeric)'
                }), 400
            
            # Get session
            session_data = get_session(session_id)
            if not session_data:
                return jsonify({
                    'success': False,
                    'error': 'invalid_session',
                    'message': 'Session not found or expired. Please get a new captcha.'
                }), 400
            
            requests_session = session_data['requests_session']
            
            # Prepare GST search request to the correct API endpoint
            search_url = "https://services.gst.gov.in/services/api/search/taxpayerDetails"
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'application/json, text/plain, */*',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'Content-Type': 'application/json',
                'Connection': 'keep-alive',
                'Referer': 'https://services.gst.gov.in/services/searchtp',
                'X-Requested-With': 'XMLHttpRequest'
            }
            
            payload = {
                'gstin': gstin,
                'captcha': captcha
            }
            
            # Make request with enhanced error handling
            timeout = app.config.get('REQUEST_TIMEOUT', 15)
            response = requests_session.post(
                search_url,
                json=payload,
                headers=headers,
                timeout=timeout,
                verify=True
            )
            
            response.raise_for_status()
            
            # Parse response
            try:
                result = response.json()
            except ValueError as e:
                logger.error(f"Invalid JSON response from GST portal: {str(e)}")
                return jsonify({
                    'success': False,
                    'error': 'invalid_response_format',
                    'message': 'Invalid response format from GST portal'
                }), 502
            
            # Check for GST portal errors
            if 'error' in result or result.get('status') == 'error':
                error_message = result.get('message', 'Unknown error from GST portal')
                error_code = result.get('errorCode', 'unknown')
                
                logger.warning(f"GST portal error for GSTIN {gstin}: {error_message} (Code: {error_code})")
                
                # Handle specific error cases
                if 'captcha' in error_message.lower():
                    return jsonify({
                        'success': False,
                        'error': 'invalid_captcha',
                        'message': 'Invalid captcha. Please get a new captcha and try again.'
                    }), 400
                elif 'gstin' in error_message.lower() and 'not found' in error_message.lower():
                    return jsonify({
                        'success': False,
                        'error': 'gstin_not_found',
                        'message': 'GSTIN not found in GST portal records'
                    }), 404
                else:
                    return jsonify({
                        'success': False,
                        'error': 'gst_portal_error',
                        'message': error_message,
                        'error_code': error_code
                    }), 400
            
            # Extract and structure GST details from the official GST portal response
            gst_details = {
                'gstin': result.get('gstin', gstin),
                'legal_name': result.get('lgnm', '').strip(),
                'trade_name': result.get('tradeNam', '').strip(),
                'registration_date': result.get('rgdt', ''),
                'constitution_of_business': result.get('ctb', ''),
                'taxpayer_type': result.get('dty', ''),
                'gstin_status': result.get('sts', ''),
                'nature_of_business_activities': result.get('nba', []),
                'aadhaar_validation': result.get('adhrVFlag', 'No'),
                'ekyc_validation': result.get('ekycVFlag', 'No'),
                'composition_taxable_person': result.get('cmpRt', 'NA'),
                'field_visit_conducted': result.get('isFieldVisitConducted', 'No'),
                'einvoice_status': result.get('einvoiceStatus', 'No'),
                'nature_of_core_business_activity_code': result.get('ntcrbs', ''),
                'cancellation_date': result.get('cxdt', ''),
                'jurisdiction': {
                    'center': result.get('ctj', ''),
                    'state': result.get('stj', '')
                },
                'principal_place_of_business': {},
                'retrieved_at': datetime.now().isoformat()
            }
            
            # Extract principal place of business address
            pradr = result.get('pradr', {})
            if pradr and isinstance(pradr, dict):
                gst_details['principal_place_of_business'] = {
                    'address': pradr.get('adr', '').strip(),
                    'nature_of_premises': pradr.get('ntr', '').strip()
                }
            
            # Log successful retrieval
            logger.info(f"GST details retrieved successfully for GSTIN: {gstin}")
            
            return jsonify({
                'success': True,
                'data': gst_details,
                'message': 'GST details retrieved successfully'
            }), 200
            
        except requests.exceptions.Timeout:
            logger.error(f"Timeout while fetching GST details for GSTIN: {gstin}")
            return jsonify({
                'success': False,
                'error': 'timeout_error',
                'message': 'Request timeout while fetching GST details from portal'
            }), 504
        except requests.exceptions.ConnectionError:
            logger.error(f"Connection error while fetching GST details for GSTIN: {gstin}")
            return jsonify({
                'success': False,
                'error': 'connection_error',
                'message': 'Unable to connect to GST portal'
            }), 502
        except Exception as e:
            logger.error(f"Unexpected error in get_gst_details: {str(e)}")
            return jsonify({
                'success': False,
                'error': 'internal_server_error',
                'message': 'An unexpected error occurred while fetching GST details'
            }), 500
    
    @app.route('/gst-services', methods=['POST'])
    @limiter.limit("10 per minute")
    def get_gst_services():
        """Get GST services/goods details for a GSTIN."""
        gstin = None
        
        try:
            data = request.get_json()
            
            if not data:
                return jsonify({
                    'success': False,
                    'error': 'invalid_request_format',
                    'message': 'Request body must be valid JSON'
                }), 400
            
            gstin = data.get('gstin', '').strip().upper()
            
            # Validate required fields
            if not gstin:
                return jsonify({
                    'success': False,
                    'error': 'missing_required_fields',
                    'message': 'gstin is required',
                    'required_fields': ['gstin']
                }), 400
            
            # Validate GSTIN format
            if not validate_gstin(gstin):
                return jsonify({
                    'success': False,
                    'error': 'invalid_gstin_format',
                    'message': 'GSTIN format is invalid. Expected format: 15 characters (2 digits + 10 alphanumeric + 1 digit + Z + 1 alphanumeric)'
                }), 400
            
            # Prepare GST services request
            services_url = f"https://services.gst.gov.in/services/api/search/goodservice?gstin={gstin}"
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'application/json, text/plain, */*',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive',
                'Referer': 'https://services.gst.gov.in/services/searchtp'
            }
            
            # Create a new session for this request
            session = requests.Session()
            
            # Make request with enhanced error handling
            timeout = app.config.get('REQUEST_TIMEOUT', 15)
            response = session.get(
                services_url,
                headers=headers,
                timeout=timeout,
                verify=True
            )
            
            response.raise_for_status()
            
            # Parse response
            try:
                result = response.json()
            except ValueError as e:
                logger.error(f"Invalid JSON response from GST portal services API: {str(e)}")
                return jsonify({
                    'success': False,
                    'error': 'invalid_response_format',
                    'message': 'Invalid response format from GST portal'
                }), 502
            
            # Check for GST portal errors
            if 'error' in result or result.get('status') == 'error':
                error_message = result.get('message', 'Unknown error from GST portal')
                error_code = result.get('errorCode', 'unknown')
                
                logger.warning(f"GST portal services error for GSTIN {gstin}: {error_message} (Code: {error_code})")
                
                if 'gstin' in error_message.lower() and 'not found' in error_message.lower():
                    return jsonify({
                        'success': False,
                        'error': 'gstin_not_found',
                        'message': 'GSTIN not found in GST portal records'
                    }), 404
                else:
                    return jsonify({
                        'success': False,
                        'error': 'gst_portal_error',
                        'message': error_message,
                        'error_code': error_code
                    }), 400
            
            # Extract and structure business services/goods details
            business_activities = []
            bzsdtls = result.get('bzsdtls', [])
            
            if isinstance(bzsdtls, list):
                for activity in bzsdtls:
                    if isinstance(activity, dict):
                        activity_info = {
                            'sac_code': activity.get('saccd', '').strip(),
                            'service_description': activity.get('sdes', '').strip(),
                            'category': 'Service' if activity.get('saccd', '').startswith('99') else 'Goods'
                        }
                        business_activities.append(activity_info)
            
            # Structure the response
            services_details = {
                'gstin': gstin,
                'business_activities': business_activities,
                'total_activities': len(business_activities),
                'retrieved_at': datetime.now().isoformat()
            }
            
            # Log successful retrieval
            logger.info(f"GST services details retrieved successfully for GSTIN: {gstin}")
            
            return jsonify({
                'success': True,
                'data': services_details,
                'message': 'GST services details retrieved successfully'
            }), 200
            
        except requests.exceptions.Timeout:
            logger.error(f"Timeout while fetching GST services for GSTIN: {gstin}")
            return jsonify({
                'success': False,
                'error': 'timeout_error',
                'message': 'Request timeout while fetching GST services from portal'
            }), 504
        except requests.exceptions.ConnectionError:
            logger.error(f"Connection error while fetching GST services for GSTIN: {gstin}")
            return jsonify({
                'success': False,
                'error': 'connection_error',
                'message': 'Unable to connect to GST portal'
            }), 502
        except Exception as e:
            logger.error(f"Unexpected error in get_gst_services: {str(e)}")
            return jsonify({
                'success': False,
                'error': 'internal_server_error',
                'message': 'An unexpected error occurred while fetching GST services'
            }), 500
    
    @app.route('/validate-gstin', methods=['POST'])
    @limiter.limit("20 per minute")
    def validate_gstin_endpoint():
        """Validate GSTIN format."""
        try:
            data = request.get_json()
            
            if not data:
                return jsonify({
                    'success': False,
                    'error': 'invalid_request_format',
                    'message': 'Request body must be valid JSON'
                }), 400
            
            gstin = data.get('gstin', '').strip().upper()
            
            if not gstin:
                return jsonify({
                    'success': False,
                    'error': 'missing_gstin',
                    'message': 'GSTIN is required'
                }), 400
            
            # Validate GSTIN format
            is_valid = validate_gstin(gstin)
            
            # Extract GSTIN components for additional info
            gstin_info = {
                'gstin': gstin,
                'is_valid': is_valid,
                'length': len(gstin)
            }
            
            if len(gstin) == 15 and is_valid:
                gstin_info.update({
                    'state_code': gstin[:2],
                    'pan': gstin[2:12],
                    'entity_number': gstin[12],
                    'default_z': gstin[13],
                    'check_digit': gstin[14]
                })
            
            # Log validation request
            logger.info(f"GSTIN validation request: {gstin} - Valid: {is_valid}")
            
            return jsonify({
                'success': True,
                'data': gstin_info,
                'message': 'GSTIN validation completed successfully'
            }), 200
            
        except Exception as e:
            logger.error(f"Unexpected error in validate_gstin_endpoint: {str(e)}")
            return jsonify({
                'success': False,
                'error': 'internal_server_error',
                'message': 'An unexpected error occurred during GSTIN validation'
            }), 500


# Create application instance
def create_app_instance():
    """Create and configure the Flask application instance."""
    global app, limiter, logger
    
    try:
        # Create Flask app
        app = create_app()
        
        logger.info("GST Verification API initialized successfully")
        return app
        
    except Exception as e:
        print(f"Failed to initialize application: {e}")
        raise


# Create application instance
app_instance = create_app_instance()


if __name__ == "__main__":
    # Development server
    try:
        port = int(os.getenv("PORT", 5001))
        debug = os.getenv("FLASK_ENV") == "development"
        
        logger.info(f"Starting GST Verification API on port {port} (debug={debug})")
        
        app_instance.run(
            host="0.0.0.0",
            port=port,
            debug=debug,
            threaded=True
        )
        
    except KeyboardInterrupt:
        logger.info("Application stopped by user")
    except Exception as e:
        logger.error(f"Application startup failed: {e}")
        raise