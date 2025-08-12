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
from logging_config import setup_logging
from monitoring import initialize_monitoring, monitor_request
from performance import initialize_performance_optimizations, cached, timed

# Initialize performance optimizations
performance_components = None
monitoring_components = None
logger_config = None

# Global variables for components
app = None
limiter = None
logger = None

# In-memory session storage (use Redis in production)
sessions = {}


def create_app(config_name: Optional[str] = None) -> Flask:
    """Application factory pattern for creating Flask app."""
    global app, limiter, logger, performance_components, monitoring_components, logger_config
    
    # Create Flask app
    app = Flask(__name__)
    
    # Load configuration
    config = get_config(config_name)
    app.config.from_object(config)
    
    # Validate configuration
    validate_config(app.config)
    
    # Initialize logging
    logger_config = setup_logging({
        'LOG_DIR': app.config.get('LOG_DIR', 'logs'),
        'LOG_LEVEL': app.config.get('LOG_LEVEL', 'INFO'),
        'FLASK_ENV': app.config.get('FLASK_ENV', 'development'),
        'JSON_LOGGING': app.config.get('JSON_LOGGING', True),
        'FILE_LOGGING': app.config.get('FILE_LOGGING', True),
        'CONSOLE_LOGGING': app.config.get('CONSOLE_LOGGING', True)
    })
    
    # Configure Flask logging
    logger_config.configure_flask_logging(app)
    logger_config.setup_request_logging(app)
    logger = logger_config.get_logger('gst_api')
    
    # Initialize performance optimizations
    performance_components = initialize_performance_optimizations({
        'REDIS_URL': app.config.get('REDIS_URL'),
        'MEMORY_CACHE_SIZE': app.config.get('CACHE_SIZE', 1000),
        'DEFAULT_TTL': app.config.get('CACHE_TTL', 300),
        'HTTP_POOL_CONNECTIONS': app.config.get('HTTP_POOL_CONNECTIONS', 10),
        'HTTP_POOL_MAXSIZE': app.config.get('HTTP_POOL_MAXSIZE', 20),
        'HTTP_RETRIES': app.config.get('HTTP_RETRIES', 3),
        'ASYNC_MAX_WORKERS': app.config.get('ASYNC_MAX_WORKERS', 5)
    })
    
    # Initialize monitoring
    monitoring_components = initialize_monitoring()
    
    # Setup CORS
    CORS(app, 
         origins=app.config.get('CORS_ORIGINS', ['*']),
         methods=app.config.get('CORS_METHODS', ['GET', 'POST']),
         allow_headers=app.config.get('CORS_HEADERS', ['Content-Type', 'Authorization']))
    
    # Setup rate limiting
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=app.config.get('RATE_LIMITS', ["100 per hour"]),
        storage_uri=app.config.get('REDIS_URL', 'memory://'),
        strategy="fixed-window"
    )
    
    # Register error handlers
    register_error_handlers(app)
    
    # Register routes
    register_routes(app)
    
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
        
        # Update active sessions count
        if monitoring_components:
            monitoring_components[0].update_active_sessions(len(sessions))
    
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
            
            # Record performance metrics
            if logger_config:
                logger_config.log_performance(
                    f"{request.method} {request.path}",
                    duration,
                    {
                        'status_code': response.status_code,
                        'request_id': getattr(g, 'request_id', 'unknown')
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
    
    @app.errorhandler(405)
    def method_not_allowed(error):
        """Handle method not allowed errors."""
        logger.warning(f"Method not allowed: {request.method} {request.path}", 
                      extra={'request_id': getattr(g, 'request_id', 'unknown')})
        return jsonify({
            'success': False,
            'error': 'Method Not Allowed',
            'message': f'The {request.method} method is not allowed for this endpoint',
            'error_code': 'METHOD_NOT_ALLOWED',
            'request_id': getattr(g, 'request_id', 'unknown')
        }), 405
    
    @app.errorhandler(429)
    def rate_limit_exceeded(error):
        """Handle rate limit exceeded errors."""
        logger.warning(f"Rate limit exceeded: {request.path}", 
                      extra={'request_id': getattr(g, 'request_id', 'unknown')})
        
        # Record rate limit hit
        if monitoring_components:
            monitoring_components[0].record_rate_limit_hit(request.endpoint or 'unknown')
        
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
        
        # Record error in monitoring
        if monitoring_components:
            monitoring_components[0].record_error('internal_error', request.endpoint or 'unknown')
        
        return jsonify({
            'success': False,
            'error': 'Internal Server Error',
            'message': 'An unexpected error occurred. Please try again later.',
            'error_code': 'INTERNAL_ERROR',
            'request_id': getattr(g, 'request_id', 'unknown')
        }), 500
    
    @app.errorhandler(Exception)
    def handle_exception(error):
        """Handle unexpected exceptions."""
        logger.error(f"Unhandled exception: {error}", 
                    exc_info=True,
                    extra={'request_id': getattr(g, 'request_id', 'unknown')})
        
        # Record error in monitoring
        if monitoring_components:
            monitoring_components[0].record_error(type(error).__name__, request.endpoint or 'unknown')
        
        return jsonify({
            'success': False,
            'error': 'Internal Server Error',
            'message': 'An unexpected error occurred. Please try again later.',
            'error_code': 'UNEXPECTED_ERROR',
            'request_id': getattr(g, 'request_id', 'unknown')
        }), 500

# Configuration
# Remove duplicate Config class - using the one from config.py

# Global session storage (In production, use Redis or database)
gst_sessions: Dict[str, Dict[str, Any]] = {}

# Utility functions
@cached(ttl=300, key_prefix="gstin_validation")
@timed()
def validate_gstin(gstin: str) -> bool:
    """
    Validate GSTIN format with caching.
    
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
    
    # Record validation metrics
    if monitoring_components:
        monitoring_components[0].record_gstin_validation(is_valid)
    
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
    
    # Update active sessions count
    if monitoring_components:
        monitoring_components[0].update_active_sessions(len(gst_sessions))
    
    return len(expired_sessions)


def create_session() -> str:
    """Create a new session and return session ID."""
    session_id = str(uuid.uuid4())
    
    # Create optimized requests session
    requests_session = requests.Session()
    
    # Use HTTP connection pool if available
    if performance_components and performance_components['http_pool']:
        requests_session = performance_components['http_pool'].session
    else:
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
    
    # Update active sessions count
    if monitoring_components:
        monitoring_components[0].update_active_sessions(len(gst_sessions))
    
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
        
        # Update active sessions count
        if monitoring_components:
            monitoring_components[0].update_active_sessions(len(gst_sessions))
        
        return None
    
    # Update last activity
    session_data['last_activity'] = datetime.now()
    session_data['request_count'] = session_data.get('request_count', 0) + 1
    
    return session_data

def rate_limit(max_requests: int = 10, window: int = 60):
    """Simple rate limiting decorator."""
    def request_decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Simple in-memory rate limiting (use Redis in production)
            client_ip = request.remote_addr
            current_time = time.time()
            
            if not hasattr(decorated_function, 'requests'):
                decorated_function.requests = {}
            
            if client_ip not in decorated_function.requests:
                decorated_function.requests[client_ip] = []
            
            # Clean old requests
            decorated_function.requests[client_ip] = [
                req_time for req_time in decorated_function.requests[client_ip]
                if current_time - req_time < window
            ]
            
            if len(decorated_function.requests[client_ip]) >= max_requests:
                return jsonify({
                    "success": False,
                    "error": "Rate limit exceeded",
                    "message": f"Maximum {max_requests} requests per {window} seconds allowed"
                }), 429
            
            decorated_function.requests[client_ip].append(current_time)
            return f(*args, **kwargs)
        return decorated_function
    return request_decorator

def create_error_response(error_code: str, message: str, status_code: int = 400) -> Tuple[Dict[str, Any], int]:
    """Create standardized error response."""
    return {
        "success": False,
        "error_code": error_code,
        "message": message,
        "timestamp": datetime.now().isoformat()
    }, status_code

def create_success_response(data: Dict[str, Any], message: str = "Success") -> Dict[str, Any]:
    """Create standardized success response."""
    return {
        "success": True,
        "message": message,
        "data": data,
        "timestamp": datetime.now().isoformat()
    }

def register_routes(app: Flask):
    """Register all API routes."""
    
    @app.route('/', methods=['GET'])
    def root():
        """Root endpoint providing API information."""
        return jsonify({
            'success': True,
            'message': 'GST Verification API',
            'version': app.config.get('VERSION', '1.0.0'),
            'description': 'API for GST verification and validation services',
            'endpoints': {
                'health': '/health - Health check endpoint',
                'captcha': '/captcha - Get captcha image',
                'gst_details': '/gst-details - Get GST details using GSTIN and captcha',
                'validate_gstin': '/validate-gstin - Validate GSTIN format',
                'api_docs': '/api/v1/docs - API documentation'
            },
            'timestamp': datetime.now().isoformat(),
            'request_id': getattr(g, 'request_id', 'unknown')
        }), 200
    
    @app.route('/health', methods=['GET'])
    @monitor_request(monitoring_components[0])
    def health_check():
        """Enhanced health check endpoint with comprehensive system monitoring."""
        try:
            start_time = datetime.now()
            
            # Get health check results
            health_status = {}
            overall_status = 'healthy'
            
            if monitoring_components and len(monitoring_components) > 1:
                health_checker = monitoring_components[1]
                health_status = health_checker.check_health()
                
                # Determine overall status
                if any(not check['healthy'] for check in health_status.values()):
                    overall_status = 'degraded'
            
            # Get performance stats
            performance_stats = {}
            if performance_components:
                try:
                    from performance import get_performance_stats
                    performance_stats = get_performance_stats()
                except Exception as e:
                    logger.warning(f"Failed to get performance stats: {e}")
            
            # Calculate response time
            response_time = (datetime.now() - start_time).total_seconds() * 1000
            
            response_data = {
                'status': overall_status,
                'timestamp': datetime.now().isoformat(),
                'version': app.config.get('VERSION', '1.0.0'),
                'uptime': str(datetime.now() - app.config.get('START_TIME', datetime.now())),
                'response_time_ms': round(response_time, 2),
                'active_sessions': len(gst_sessions),
                'health_checks': health_status,
                'performance': performance_stats
            }
            
            status_code = 200 if overall_status == 'healthy' else 503
            
            # Log health check
            if logger_config:
                logger_config.log_audit(
                    'health_check',
                    {'status': overall_status, 'response_time_ms': response_time}
                )
            
            return jsonify(response_data), status_code
            
        except Exception as e:
            logger.error(f"Health check failed: {str(e)}")
            return jsonify({
                'status': 'unhealthy',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }), 503
    
    @app.route('/captcha', methods=['GET'])
    @limiter.limit("30 per minute")
    @monitor_request(monitoring_components[0])
    @timed()
    def get_captcha():
        """Get captcha image from GST portal with enhanced error handling and monitoring."""
        session_id = None
        try:
            # Create session
            session_id = create_session()
            session_data = get_session(session_id)
            
            if not session_data:
                logger.error("Failed to create session for captcha retrieval")
                return jsonify({
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
                'Sec-Fetch-Dest': 'image',
                'Sec-Fetch-Mode': 'no-cors',
                'Sec-Fetch-Site': 'cross-site',
                'Cache-Control': 'no-cache',
                'Pragma': 'no-cache'
            }
            
            # Make request with timeout and retries
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
            
            # Verify content type
            content_type = response.headers.get('content-type', '')
            if 'image' not in content_type.lower():
                logger.warning(f"Unexpected content type for captcha: {content_type}")
            
            # Convert image to base64
            captcha_base64 = base64.b64encode(response.content).decode('utf-8')
            
            # Store captcha metadata in session
            session_data['captcha_retrieved_at'] = datetime.now()
            session_data['captcha_size'] = len(response.content)
            
            # Log successful captcha retrieval
            logger.info(f"Captcha retrieved successfully for session: {session_id}")
            
            if logger_config:
                logger_config.log_audit(
                    'captcha_retrieved',
                    {
                        'session_id': session_id,
                        'captcha_size': len(response.content),
                        'content_type': content_type
                    }
                )
            
            return jsonify({
                'session_id': session_id,
                'captcha_image': f"data:image/png;base64,{captcha_base64}",
                'message': 'Captcha retrieved successfully',
                'expires_in': app.config.get('SESSION_TIMEOUT', 300)
            }), 200
            
        except requests.exceptions.Timeout:
            logger.error(f"Timeout while fetching captcha for session: {session_id}")
            return jsonify({
                'error': 'timeout_error',
                'message': 'Request timeout while fetching captcha from GST portal'
            }), 504
        except requests.exceptions.ConnectionError:
            logger.error(f"Connection error while fetching captcha for session: {session_id}")
            return jsonify({
                'error': 'connection_error',
                'message': 'Unable to connect to GST portal'
            }), 502
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP error while fetching captcha: {e.response.status_code} - {str(e)}")
            return jsonify({
                'error': 'http_error',
                'message': f'GST portal returned error: {e.response.status_code}'
            }), 502
        except ValueError as e:
            logger.error(f"Invalid captcha data received: {str(e)}")
            return jsonify({
                'error': 'invalid_response',
                'message': 'Invalid captcha data received from GST portal'
            }), 502
        except Exception as e:
            logger.error(f"Unexpected error in get_captcha: {str(e)}")
            return jsonify({
                'error': 'internal_server_error',
                'message': 'An unexpected error occurred while fetching captcha'
            }), 500
    
    @app.route('/gst-details', methods=['POST'])
    @limiter.limit("10 per minute")
    @monitor_request(monitoring_components[0])
    @timed()
    def get_gst_details():
        """Get GST details using GSTIN and captcha with enhanced monitoring and caching."""
        session_id = None
        gstin = None
        
        try:
            data = request.get_json()
            
            if not data:
                return jsonify({
                    'error': 'invalid_request_format',
                    'message': 'Request body must be valid JSON'
                }), 400
            
            session_id = data.get('session_id')
            gstin = data.get('gstin', '').strip().upper()
            captcha = data.get('captcha', '').strip()

            print("Received request with session_id:",session_id, "gstin:",gstin, "captcha:",session_id, gstin, captcha)
            
            # Validate required fields
            if not all([session_id, gstin, captcha]):
                return jsonify({
                    'error': 'missing_required_fields',
                    'message': 'session_id, gstin, and captcha are required',
                    'required_fields': ['session_id', 'gstin', 'captcha']
                }), 400
            
            # Validate GSTIN format
            if not validate_gstin(gstin):
                return jsonify({
                    'error': 'invalid_gstin_format',
                    'message': 'GSTIN format is invalid. Expected format: 15 characters (2 digits + 10 alphanumeric + 1 digit + Z + 1 alphanumeric)'
                }), 400
            
            # Get session
            session_data = get_session(session_id)
            if not session_data:
                return jsonify({
                    'error': 'invalid_session',
                    'message': 'Session not found or expired. Please get a new captcha.'
                }), 400
            
            # Check cache first
            cache_key = f"gst_details:{gstin}"
            if performance_components and performance_components.get('cache_manager'):
                cached_result = performance_components['cache_manager'].get(cache_key)
                if cached_result:
                    logger.info(f"GST details served from cache for GSTIN: {gstin}")
                    return jsonify({
                        'success': True,
                        'data': cached_result,
                        'message': 'GST details retrieved successfully (cached)',
                        'cached': True
                    }), 200
            
            requests_session = session_data['requests_session']
            
            # Prepare GST search request
            search_url = "https://services.gst.gov.in/services/searchtp"
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'application/json, text/plain, */*',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'Content-Type': 'application/json',
                'Connection': 'keep-alive',
                'Referer': 'https://services.gst.gov.in/services/searchtp',
                'Sec-Fetch-Dest': 'empty',
                'Sec-Fetch-Mode': 'cors',
                'Sec-Fetch-Site': 'same-origin',
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
                        'error': 'invalid_captcha',
                        'message': 'Invalid captcha. Please get a new captcha and try again.'
                    }), 400
                elif 'gstin' in error_message.lower() and 'not found' in error_message.lower():
                    return jsonify({
                        'error': 'gstin_not_found',
                        'message': 'GSTIN not found in GST portal records'
                    }), 404
                else:
                    return jsonify({
                        'error': 'gst_portal_error',
                        'message': error_message,
                        'error_code': error_code
                    }), 400
            
            # Extract and structure GST details
            gst_details = {
                'gstin': gstin,
                'legal_name': result.get('lgnm', '').strip(),
                'trade_name': result.get('tradeNam', '').strip(),
                'registration_date': result.get('rgdt', ''),
                'constitution': result.get('ctb', ''),
                'taxpayer_type': result.get('dty', ''),
                'status': result.get('sts', ''),
                'last_updated': result.get('lstupdt', ''),
                'center_jurisdiction': result.get('ctjCd', ''),
                'state_jurisdiction': result.get('stj', ''),
                'addresses': [],
                'filing_status': [],
                'retrieved_at': datetime.now().isoformat()
            }
            
            # Extract addresses
            addresses = result.get('pradr', {}).get('addr', [])
            if not isinstance(addresses, list):
                addresses = [addresses] if addresses else []
            
            for addr in addresses:
                if isinstance(addr, dict):
                    address_info = {
                        'address_line': addr.get('addr', '').strip(),
                        'city': addr.get('city', '').strip(),
                        'state': addr.get('stcd', '').strip(),
                        'pincode': addr.get('pncd', '').strip(),
                        'nature': addr.get('ntr', '').strip(),
                        'floor': addr.get('flno', '').strip(),
                        'building': addr.get('bno', '').strip(),
                        'street': addr.get('st', '').strip(),
                        'location': addr.get('loc', '').strip()
                    }
                    gst_details['addresses'].append(address_info)
            
            # Extract filing status if available
            filing_status = result.get('filingStatus', [])
            if isinstance(filing_status, list):
                gst_details['filing_status'] = filing_status
            
            # Cache the result
            if performance_components and performance_components.get('cache_manager'):
                cache_ttl = app.config.get('GST_DETAILS_CACHE_TTL', 3600)  # 1 hour default
                performance_components['cache_manager'].set(cache_key, gst_details, ttl=cache_ttl)
            
            # Log successful retrieval
            logger.info(f"GST details retrieved successfully for GSTIN: {gstin}")
            
            if logger_config:
                logger_config.log_audit(
                    'gst_details_retrieved',
                    {
                        'gstin': gstin,
                        'session_id': session_id,
                        'legal_name': gst_details['legal_name'],
                        'status': gst_details['status']
                    }
                )
            
            return jsonify({
                'success': True,
                'data': gst_details,
                'message': 'GST details retrieved successfully',
                'cached': False
            }), 200
            
        except requests.exceptions.Timeout:
            logger.error(f"Timeout while fetching GST details for GSTIN: {gstin}")
            return jsonify({
                'error': 'timeout_error',
                'message': 'Request timeout while fetching GST details from portal'
            }), 504
        except requests.exceptions.ConnectionError:
            logger.error(f"Connection error while fetching GST details for GSTIN: {gstin}")
            return jsonify({
                'error': 'connection_error',
                'message': 'Unable to connect to GST portal'
            }), 502
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP error while fetching GST details: {e.response.status_code} - {str(e)}")
            return jsonify({
                'error': 'http_error',
                'message': f'GST portal returned error: {e.response.status_code}'
            }), 502
        except Exception as e:
            logger.error(f"Unexpected error in get_gst_details: {str(e)}")
            return jsonify({
                'error': 'internal_server_error',
                'message': 'An unexpected error occurred while fetching GST details'
            }), 500
    
    @app.route('/validate-gstin', methods=['POST'])
    @limiter.limit("20 per minute")
    @monitor_request(monitoring_components[0])
    @timed()
    def validate_gstin_endpoint():
        """Validate GSTIN format with enhanced monitoring and caching."""
        try:
            data = request.get_json()
            
            if not data:
                return jsonify({
                    'error': 'invalid_request_format',
                    'message': 'Request body must be valid JSON'
                }), 400
            
            gstin = data.get('gstin', '').strip().upper()
            
            if not gstin:
                return jsonify({
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
            
            if logger_config:
                logger_config.log_audit(
                    'gstin_validated',
                    {
                        'gstin': gstin,
                        'is_valid': is_valid,
                        'validation_details': gstin_info
                    }
                )
            
            return jsonify({
                'success': True,
                'data': gstin_info,
                'message': 'GSTIN validation completed successfully'
            }), 200
            
        except Exception as e:
            logger.error(f"Unexpected error in validate_gstin_endpoint: {str(e)}")
            return jsonify({
                'error': 'internal_server_error',
                'message': 'An unexpected error occurred during GSTIN validation'
            }), 500

def cleanup_expired_sessions():
    """Background task to clean expired sessions."""
    import threading
    import time
    
    def cleanup_worker():
        while True:
            try:
                time.sleep(300)  # Clean every 5 minutes
                expired_count = clean_expired_sessions()
                if expired_count > 0:
                    logger.info(f"Cleaned {expired_count} expired sessions")
            except Exception as e:
                logger.error(f"Error in session cleanup: {e}")
    
    cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
    cleanup_thread.start()
    logger.info("Session cleanup thread started")


def setup_signal_handlers(app: Flask):
    """Setup signal handlers for graceful shutdown."""
    import signal
    import sys
    
    def signal_handler(sig, frame):
        logger.info(f"Received signal {sig}, shutting down gracefully...")
        
        # Close all active sessions
        for session_id, session_data in list(gst_sessions.items()):
            if 'requests_session' in session_data:
                try:
                    session_data['requests_session'].close()
                except Exception as e:
                    logger.warning(f"Error closing session {session_id}: {e}")
        
        # Cleanup performance components
        if performance_components:
            try:
                if 'async_processor' in performance_components:
                    performance_components['async_processor'].shutdown()
                if 'http_pool' in performance_components:
                    performance_components['http_pool'].close()
            except Exception as e:
                logger.warning(f"Error during performance cleanup: {e}")
        
        logger.info("Graceful shutdown completed")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)


# Application factory function
def create_app_instance():
    """Create and configure the Flask application instance."""
    global app, limiter, logger, performance_components, monitoring_components, logger_config
    
    try:
        # Create Flask app
        app = create_app()
        
        # Setup cleanup and signal handlers
        cleanup_expired_sessions()
        setup_signal_handlers(app)
        
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
