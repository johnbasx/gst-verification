from flask_restx import Api, Resource, fields, Namespace
from flask import Blueprint

def create_swagger_api(app):
    """Create Swagger API documentation for existing endpoints."""
    
    # Create a blueprint for API documentation
    api_bp = Blueprint('api_docs', __name__, url_prefix='/api/v1')
    
    # Initialize Flask-RESTX API
    api = Api(
        api_bp,
        version='1.0.0',
        title='GST Verification API',
        description='Professional API for GST verification and validation services using official GST portal endpoints',
        doc='/docs/',
        contact='GST Verification API Team',
        contact_email='support@gstapi.com',
        license='MIT',
        license_url='https://opensource.org/licenses/MIT'
    )
    
    # Define API models for request/response documentation
    captcha_response_model = api.model('CaptchaResponse', {
        'success': fields.Boolean(required=True, description='Request success status'),
        'data': fields.Nested(api.model('CaptchaData', {
            'session_id': fields.String(required=True, description='Unique session identifier'),
            'captcha_image': fields.String(required=True, description='Base64 encoded captcha image'),
            'expires_in': fields.Integer(required=True, description='Session expiry time in seconds')
        })),
        'message': fields.String(required=True, description='Response message')
    })
    
    gst_details_request_model = api.model('GSTDetailsRequest', {
        'session_id': fields.String(required=True, description='Session ID from captcha endpoint', example='550e8400-e29b-41d4-a716-446655440000'),
        'gstin': fields.String(required=True, description='15-character GSTIN number', example='24AAACC1206D1ZM'),
        'captcha': fields.String(required=True, description='Captcha text from image', example='ABC123')
    })
    
    gst_services_request_model = api.model('GSTServicesRequest', {
        'gstin': fields.String(required=True, description='15-character GSTIN number', example='24AAACC1206D1ZM')
    })
    
    gstin_validation_request_model = api.model('GSTINValidationRequest', {
        'gstin': fields.String(required=True, description='GSTIN number to validate', example='24AAACC1206D1ZM')
    })
    
    success_response_model = api.model('SuccessResponse', {
        'success': fields.Boolean(required=True, description='Request success status'),
        'data': fields.Raw(required=True, description='Response data'),
        'message': fields.String(required=True, description='Success message')
    })
    
    error_response_model = api.model('ErrorResponse', {
        'success': fields.Boolean(required=True, description='Request success status (false)'),
        'error': fields.String(required=True, description='Error code'),
        'message': fields.String(required=True, description='Error message')
    })
    
    health_response_model = api.model('HealthResponse', {
        'status': fields.String(required=True, description='Health status', example='healthy'),
        'timestamp': fields.String(required=True, description='Current timestamp'),
        'version': fields.String(required=True, description='API version', example='1.0.0'),
        'uptime': fields.String(required=True, description='Service uptime'),
        'response_time_ms': fields.Float(required=True, description='Response time in milliseconds'),
        'active_sessions': fields.Integer(required=True, description='Number of active sessions')
    })
    
    gstin_validation_response_model = api.model('GSTINValidationResponse', {
        'success': fields.Boolean(required=True, description='Request success status'),
        'data': fields.Nested(api.model('GSTINValidationData', {
            'gstin': fields.String(required=True, description='Input GSTIN'),
            'is_valid': fields.Boolean(required=True, description='Validation result'),
            'length': fields.Integer(required=True, description='GSTIN length'),
            'state_code': fields.String(description='State code (first 2 digits)'),
            'pan': fields.String(description='PAN number (characters 3-12)'),
            'entity_number': fields.String(description='Entity number (13th character)'),
            'default_z': fields.String(description='Default Z character (14th character)'),
            'check_digit': fields.String(description='Check digit (15th character)')
        })),
        'message': fields.String(required=True, description='Validation message')
    })
    
    # Create namespaces
    ns_main = Namespace('main', description='Main API endpoints')
    ns_gst = Namespace('gst', description='GST verification endpoints')
    ns_validation = Namespace('validation', description='GSTIN validation endpoints')
    
    api.add_namespace(ns_main)
    api.add_namespace(ns_gst)
    api.add_namespace(ns_validation)
    
    # Document endpoints with examples
    @ns_main.route('/health')
    class HealthCheckDoc(Resource):
        @ns_main.doc('health_check')
        @ns_main.marshal_with(health_response_model)
        def get(self):
            """Check API health status and system metrics
            
            Returns comprehensive health information including:
            - Service status
            - Current timestamp
            - API version
            - Service uptime
            - Response time metrics
            - Active session count
            """
            pass
    
    @ns_gst.route('/captcha')
    class CaptchaDoc(Resource):
        @ns_gst.doc('get_captcha')
        @ns_gst.marshal_with(captcha_response_model)
        @ns_gst.response(500, 'Session creation failed', error_response_model)
        @ns_gst.response(502, 'Connection error to GST portal', error_response_model)
        @ns_gst.response(504, 'Request timeout', error_response_model)
        def get(self):
            """Retrieve captcha image from GST portal
            
            This endpoint:
            1. Creates a new session with the GST portal
            2. Fetches a captcha image
            3. Returns the captcha as base64 encoded image
            4. Provides session ID for subsequent requests
            
            Rate limit: 30 requests per minute
            Session expires in: 5 minutes
            """
            pass
    
    @ns_gst.route('/gst-details')
    class GSTDetailsDoc(Resource):
        @ns_gst.doc('get_gst_details')
        @ns_gst.expect(gst_details_request_model)
        @ns_gst.marshal_with(success_response_model)
        @ns_gst.response(400, 'Invalid request or GSTIN format', error_response_model)
        @ns_gst.response(404, 'GSTIN not found', error_response_model)
        @ns_gst.response(502, 'GST portal error', error_response_model)
        def post(self):
            """Get detailed GST information using GSTIN and captcha
            
            This endpoint:
            1. Validates the provided session ID
            2. Validates GSTIN format (15 characters)
            3. Submits GSTIN and captcha to GST portal
            4. Returns detailed taxpayer information
            
            Rate limit: 10 requests per minute
            
            Required fields:
            - session_id: From /captcha endpoint
            - gstin: 15-character GSTIN number
            - captcha: Text from captcha image
            """
            pass
    
    @ns_gst.route('/gst-services')
    class GSTServicesDoc(Resource):
        @ns_gst.doc('get_gst_services')
        @ns_gst.expect(gst_services_request_model)
        @ns_gst.marshal_with(success_response_model)
        @ns_gst.response(400, 'Invalid GSTIN format', error_response_model)
        @ns_gst.response(404, 'GSTIN not found', error_response_model)
        @ns_gst.response(502, 'GST portal error', error_response_model)
        def post(self):
            """Get GST services/goods details for a GSTIN
            
            This endpoint:
            1. Validates GSTIN format (15 characters)
            2. Queries GST portal for goods/services information
            3. Returns detailed services/goods data
            
            Rate limit: 10 requests per minute
            
            Note: This endpoint doesn't require captcha or session
            """
            pass
    
    @ns_validation.route('/validate-gstin')
    class GSTINValidationDoc(Resource):
        @ns_validation.doc('validate_gstin')
        @ns_validation.expect(gstin_validation_request_model)
        @ns_validation.marshal_with(gstin_validation_response_model)
        @ns_validation.response(400, 'Invalid request format', error_response_model)
        def post(self):
            """Validate GSTIN format and extract components
            
            This endpoint:
            1. Validates GSTIN format using regex pattern
            2. Extracts GSTIN components (state code, PAN, etc.)
            3. Returns validation result with detailed breakdown
            
            Rate limit: 20 requests per minute
            
            GSTIN Format:
            - Total length: 15 characters
            - First 2 digits: State code
            - Next 10 characters: PAN of taxpayer
            - 13th character: Entity number
            - 14th character: 'Z' (default)
            - 15th character: Check digit
            """
            pass
    
    # Register the blueprint
    app.register_blueprint(api_bp)
    
    return api