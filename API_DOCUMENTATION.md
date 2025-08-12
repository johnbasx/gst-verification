# GST Verification API Documentation

A professional Flask API for fetching GST details from the official GST website. This service handles captcha solving and provides structured GST information using the official GST portal endpoints.

## Base URL
```
http://localhost:5001
```

## Features

- **Official GST Portal Integration**: Uses official GST website endpoints
- **Captcha Handling**: Automatic captcha fetching and processing
- **Structured Responses**: Clean, professional JSON responses
- **Rate Limiting**: Built-in rate limiting for API protection
- **Session Management**: Secure session handling
- **Comprehensive Error Handling**: Detailed error responses
- **CORS Support**: Cross-origin resource sharing enabled
- **Health Monitoring**: Built-in health check endpoint
- **Input Validation**: GSTIN format validation
- **Logging**: Comprehensive request/response logging

## API Endpoints

### 1. Health Check

**GET** `/health`

Check the API health status.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "version": "1.0.0",
  "uptime": "0:05:23.123456",
  "response_time_ms": 12.34,
  "active_sessions": 5
}
```

### 2. Get Captcha

**GET** `/captcha`

Fetch captcha image from the official GST portal.

**Rate Limit:** 30 requests per minute

**Response:**
```json
{
  "success": true,
  "data": {
    "session_id": "550e8400-e29b-41d4-a716-446655440000",
    "captcha_image": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA...",
    "expires_in": 300
  },
  "message": "Captcha retrieved successfully"
}
```

**Error Responses:**
- `502` - Connection error to GST portal
- `504` - Request timeout
- `500` - Internal server error

### 3. Get GST Details

**POST** `/gst-details`

Retrieve detailed GST information using GSTIN and captcha.

**Rate Limit:** 10 requests per minute

**Request Body:**
```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "gstin": "24AAACC1206D1ZM",
  "captcha": "ABC123"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "gstin": "24AAACC1206D1ZM",
    "legal_name": "CENTRAL WAREHOUSING CORPORATION",
    "trade_name": "CENTRAL WARE HOUSING CORP.LTD.",
    "registration_date": "01/07/2017",
    "constitution_of_business": "CORPORATION",
    "taxpayer_type": "Regular",
    "gstin_status": "Active",
    "nature_of_business_activities": [
      "Bonded Warehouse",
      "Service Provision",
      "Recipient of Goods or Services",
      "Warehouse / Depot",
      "Input Service Distributor (ISD)",
      "Supplier of Services"
    ],
    "aadhaar_validation": "No",
    "ekyc_validation": "No",
    "composition_taxable_person": "NA",
    "field_visit_conducted": "Yes",
    "einvoice_status": "Yes",
    "nature_of_core_business_activity_code": "SPO",
    "cancellation_date": "",
    "jurisdiction": {
      "center": "State - CBIC,Zone - AHMEDABAD,Commissionerate - AHMEDABAD SOUTH,Division - DIVISION-VII - SATELLITE,Range - RANGE V",
      "state": "State - Gujarat,Division - Division - 1,Range - Range - 3,Unit - Ghatak 10 (Ahmedabad) (Jurisdictional Office)"
    },
    "principal_place_of_business": {
      "address": "CENTRAL WAREHOUSING CORPORATION, MAHALAXMI CHAR RASTA, PALDI, Ahmedabad, Gujarat, 380007",
      "nature_of_premises": ""
    },
    "retrieved_at": "2024-01-15T10:30:00.000Z"
  },
  "message": "GST details retrieved successfully"
}
```

**Error Responses:**
- `400` - Missing required fields, invalid GSTIN format, invalid captcha, or invalid session
- `404` - GSTIN not found in GST portal records
- `502` - Connection error to GST portal
- `504` - Request timeout
- `500` - Internal server error

### 4. Get GST Services/Goods

**POST** `/gst-services`

Retrieve business activities (goods/services) for a GSTIN.

**Rate Limit:** 10 requests per minute

**Request Body:**
```json
{
  "gstin": "24AAACC1206D1ZM"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "gstin": "24AAACC1206D1ZM",
    "business_activities": [
      {
        "sac_code": "996791",
        "service_description": "Goods transport agency services for road transport",
        "category": "Service"
      },
      {
        "sac_code": "00440193",
        "service_description": "STORAGE AND WAREHOUSE SERVICE",
        "category": "Goods"
      },
      {
        "sac_code": "00440189",
        "service_description": "CARGO HANDLING SERVICES",
        "category": "Goods"
      },
      {
        "sac_code": "00440406",
        "service_description": "RENTING OF IMMOVABLE PROPERTY SERVICES",
        "category": "Goods"
      },
      {
        "sac_code": "00440318",
        "service_description": "CLEANING SERVICES",
        "category": "Goods"
      }
    ],
    "total_activities": 5,
    "retrieved_at": "2024-01-15T10:30:00.000Z"
  },
  "message": "GST services details retrieved successfully"
}
```

**Error Responses:**
- `400` - Missing GSTIN or invalid GSTIN format
- `404` - GSTIN not found in GST portal records
- `502` - Connection error to GST portal
- `504` - Request timeout
- `500` - Internal server error

### 5. Validate GSTIN

**POST** `/validate-gstin`

Validate GSTIN format and extract components.

**Rate Limit:** 20 requests per minute

**Request Body:**
```json
{
  "gstin": "24AAACC1206D1ZM"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "gstin": "24AAACC1206D1ZM",
    "is_valid": true,
    "length": 15,
    "state_code": "24",
    "pan": "AAACC1206D",
    "entity_number": "1",
    "default_z": "Z",
    "check_digit": "M"
  },
  "message": "GSTIN validation completed successfully"
}
```

**Error Responses:**
- `400` - Missing GSTIN
- `500` - Internal server error

## Usage Flow

### Complete GST Verification Process

1. **Get Captcha**
   ```bash
   curl -X GET http://localhost:5001/captcha
   ```

2. **Solve Captcha** (manually view the base64 image and solve)

3. **Get GST Details**
   ```bash
   curl -X POST http://localhost:5001/gst-details \
     -H "Content-Type: application/json" \
     -d '{
       "session_id": "your-session-id",
       "gstin": "24AAACC1206D1ZM",
       "captcha": "solved-captcha"
     }'
   ```

4. **Get Business Activities** (optional)
   ```bash
   curl -X POST http://localhost:5001/gst-services \
     -H "Content-Type: application/json" \
     -d '{"gstin": "24AAACC1206D1ZM"}'
   ```

### Quick GSTIN Validation

```bash
curl -X POST http://localhost:5001/validate-gstin \
  -H "Content-Type: application/json" \
  -d '{"gstin": "24AAACC1206D1ZM"}'
```

## Rate Limits

- **Captcha**: 30 requests per minute
- **GST Details**: 10 requests per minute
- **GST Services**: 10 requests per minute
- **GSTIN Validation**: 20 requests per minute
- **Health Check**: No limit

## Error Handling

All endpoints return standardized error responses:

```json
{
  "success": false,
  "error": "error_code",
  "message": "Human readable error message",
  "error_code": "specific_error_code" // (optional)
}
```

### Common Error Codes

- `invalid_request_format` - Request body is not valid JSON
- `missing_required_fields` - Required fields are missing
- `invalid_gstin_format` - GSTIN format is invalid
- `invalid_session` - Session not found or expired
- `invalid_captcha` - Captcha is incorrect
- `gstin_not_found` - GSTIN not found in GST portal
- `timeout_error` - Request timeout to GST portal
- `connection_error` - Connection error to GST portal
- `gst_portal_error` - Error from GST portal
- `internal_server_error` - Unexpected server error

## Session Management

- Sessions expire after 5 minutes of inactivity
- Each captcha request creates a new session
- Sessions are automatically cleaned up
- Session IDs are UUIDs for security

## GSTIN Format

Valid GSTIN format: `15 characters`
- First 2 digits: State code
- Next 10 characters: PAN of the taxpayer
- 13th character: Entity number
- 14th character: 'Z' (default)
- 15th character: Check digit

Example: `24AAACC1206D1ZM`

## Security Features

- Rate limiting to prevent abuse
- Session-based captcha validation
- Input validation and sanitization
- CORS protection
- Secure headers
- Request/response logging
- Error handling without information leakage

## Development

### Running the API

```bash
# Install dependencies
pip install -r requirements.txt

# Run development server
python app.py
```

### Running Tests

```bash
# Run all tests
pytest -v

# Run with coverage
pytest --cov=app --cov-report=html
```

### Environment Variables

- `FLASK_ENV`: Set to `development` for debug mode
- `PORT`: Server port (default: 5001)
- `SECRET_KEY`: Flask secret key for sessions

## Production Deployment

### Using Gunicorn

```bash
gunicorn --bind 0.0.0.0:5001 --workers 4 app:app_instance
```

### Using Docker

```bash
docker build -t gst-verification-api .
docker run -p 5001:5001 gst-verification-api
```

## Monitoring

- Health check endpoint for monitoring
- Comprehensive logging
- Performance metrics
- Error tracking
- Session monitoring

## Support

For issues and questions:
1. Check the logs for detailed error information
2. Verify GSTIN format using the validation endpoint
3. Ensure proper session management
4. Check rate limits
5. Verify GST portal availability

## Official GST Portal Integration

This API integrates with the following official GST portal endpoints:

- **Captcha**: `https://services.gst.gov.in/services/captcha`
- **Taxpayer Details**: `https://services.gst.gov.in/services/api/search/taxpayerDetails`
- **Goods/Services**: `https://services.gst.gov.in/services/api/search/goodservice`
- **Search Form**: `https://services.gst.gov.in/services/searchtp`

The API acts as a professional wrapper around these official endpoints, providing structured responses and enhanced error handling.