# GST Verification API Documentation

Comprehensive API documentation for the GST Verification API service.

## Table of Contents

- [Overview](#overview)
- [Base URL](#base-url)
- [Authentication](#authentication)
- [Rate Limiting](#rate-limiting)
- [Error Handling](#error-handling)
- [API Endpoints](#api-endpoints)
  - [Health Check](#health-check)
  - [Get Captcha](#get-captcha)
  - [Get GST Details](#get-gst-details)
  - [Validate GSTIN](#validate-gstin)
- [Response Formats](#response-formats)
- [Status Codes](#status-codes)
- [Examples](#examples)
- [SDKs and Libraries](#sdks-and-libraries)
- [Changelog](#changelog)

## Overview

The GST Verification API provides a robust service for fetching GST (Goods and Services Tax) details from the official GST website. The API handles captcha processing, session management, and provides structured responses for easy integration.

### Key Features

- **Captcha Handling**: Automatic captcha fetching and processing
- **Session Management**: Secure session handling with automatic cleanup
- **Rate Limiting**: Built-in protection against abuse
- **Error Handling**: Comprehensive error responses with detailed messages
- **GSTIN Validation**: Format validation for GST Identification Numbers
- **Health Monitoring**: Built-in health check endpoint

## Base URL

```
Production: https://your-domain.com
Staging: https://staging.your-domain.com
Local Development: http://localhost:5001
```

All API endpoints are prefixed with `/api/v1`.

## Authentication

Currently, the API supports the following authentication methods:

### API Key Authentication (Optional)

If API key authentication is enabled, include the API key in the request headers:

```http
X-API-Key: your-api-key-here
```

### Rate Limiting

The API implements rate limiting to prevent abuse:

- **Default Limit**: 60 requests per minute per IP
- **Burst Limit**: 10 requests in quick succession
- **Headers**: Rate limit information is included in response headers

```http
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 59
X-RateLimit-Reset: 1640995200
```

## Error Handling

The API uses standard HTTP status codes and returns detailed error information in JSON format.

### Error Response Format

```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid GSTIN format",
    "details": {
      "field": "gstin",
      "provided": "invalid-gstin",
      "expected_format": "15-character alphanumeric string"
    }
  },
  "timestamp": "2024-01-15T10:30:00Z",
  "request_id": "req_123456789"
}
```

## API Endpoints

### Health Check

Check the health and status of the API service.

#### Endpoint
```http
GET /api/v1/health
```

#### Response

```json
{
  "success": true,
  "data": {
    "status": "healthy",
    "timestamp": "2024-01-15T10:30:00Z",
    "version": "1.0.0",
    "uptime": 86400,
    "system": {
      "python_version": "3.9.18",
      "platform": "Linux-5.4.0-x86_64",
      "memory_usage": "45.2MB",
      "cpu_usage": "12.5%"
    },
    "dependencies": {
      "gst_portal": "accessible",
      "database": "connected",
      "redis": "connected"
    }
  }
}
```

#### Status Codes
- `200 OK`: Service is healthy
- `503 Service Unavailable`: Service is unhealthy

---

### Get Captcha

Fetch a captcha image and initialize a session for GST verification.

#### Endpoint
```http
POST /api/v1/getCaptcha
```

#### Request Headers
```http
Content-Type: application/json
```

#### Request Body
```json
{}
```

#### Response

**Success Response:**
```json
{
  "success": true,
  "data": {
    "session_id": "sess_1234567890abcdef",
    "captcha_image": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA...",
    "expires_at": "2024-01-15T11:00:00Z",
    "instructions": "Enter the characters shown in the captcha image"
  },
  "timestamp": "2024-01-15T10:30:00Z",
  "request_id": "req_123456789"
}
```

**Error Response:**
```json
{
  "success": false,
  "error": {
    "code": "CAPTCHA_FETCH_FAILED",
    "message": "Failed to fetch captcha from GST portal",
    "details": {
      "reason": "Connection timeout",
      "retry_after": 30
    }
  },
  "timestamp": "2024-01-15T10:30:00Z",
  "request_id": "req_123456789"
}
```

#### Status Codes
- `200 OK`: Captcha fetched successfully
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Failed to fetch captcha
- `503 Service Unavailable`: GST portal unavailable

---

### Get GST Details

Retrieve GST details using session ID, GSTIN, and captcha solution.

#### Endpoint
```http
POST /api/v1/getGSTDetails
```

#### Request Headers
```http
Content-Type: application/json
```

#### Request Body
```json
{
  "session_id": "sess_1234567890abcdef",
  "gstin": "01ABCDE0123F1Z5",
  "captcha": "ABC123"
}
```

#### Request Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| session_id | string | Yes | Session ID from getCaptcha response |
| gstin | string | Yes | 15-character GST Identification Number |
| captcha | string | Yes | Captcha solution |

#### Response

**Success Response:**
```json
{
  "success": true,
  "data": {
    "gstin": "01ABCDE0123F1Z5",
    "legal_name": "ABC PRIVATE LIMITED",
    "trade_name": "ABC Trading",
    "registration_date": "2017-07-01",
    "constitution": "Private Limited Company",
    "gstin_status": "Active",
    "taxpayer_type": "Regular",
    "administrative_office": {
      "address": "123 Business Street, Commercial Area",
      "city": "Mumbai",
      "state": "Maharashtra",
      "pincode": "400001"
    },
    "principal_business_activities": [
      {
        "code": "46900",
        "description": "Non-specialised wholesale trade",
        "percentage": 100
      }
    ],
    "filing_status": [
      {
        "return_type": "GSTR1",
        "period": "122023",
        "status": "Filed",
        "filed_date": "2024-01-10"
      },
      {
        "return_type": "GSTR3B",
        "period": "122023",
        "status": "Filed",
        "filed_date": "2024-01-15"
      }
    ],
    "compliance_rating": "Good",
    "last_updated": "2024-01-15T10:30:00Z"
  },
  "timestamp": "2024-01-15T10:30:00Z",
  "request_id": "req_123456789"
}
```

**Error Responses:**

*Invalid Session:*
```json
{
  "success": false,
  "error": {
    "code": "INVALID_SESSION",
    "message": "Session not found or expired",
    "details": {
      "session_id": "sess_1234567890abcdef",
      "action": "Please fetch a new captcha"
    }
  },
  "timestamp": "2024-01-15T10:30:00Z",
  "request_id": "req_123456789"
}
```

*Invalid GSTIN:*
```json
{
  "success": false,
  "error": {
    "code": "INVALID_GSTIN",
    "message": "GSTIN not found or invalid",
    "details": {
      "gstin": "01ABCDE0123F1Z5",
      "validation_errors": [
        "GSTIN does not exist in GST database"
      ]
    }
  },
  "timestamp": "2024-01-15T10:30:00Z",
  "request_id": "req_123456789"
}
```

*Invalid Captcha:*
```json
{
  "success": false,
  "error": {
    "code": "INVALID_CAPTCHA",
    "message": "Captcha verification failed",
    "details": {
      "captcha": "ABC123",
      "action": "Please fetch a new captcha and try again"
    }
  },
  "timestamp": "2024-01-15T10:30:00Z",
  "request_id": "req_123456789"
}
```

#### Status Codes
- `200 OK`: GST details retrieved successfully
- `400 Bad Request`: Invalid request parameters
- `404 Not Found`: GSTIN not found
- `422 Unprocessable Entity`: Invalid captcha or session
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server error
- `503 Service Unavailable`: GST portal unavailable

---

### Validate GSTIN

Validate the format of a GST Identification Number without making external requests.

#### Endpoint
```http
POST /api/v1/validateGSTIN
```

#### Request Headers
```http
Content-Type: application/json
```

#### Request Body
```json
{
  "gstin": "01ABCDE0123F1Z5"
}
```

#### Request Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| gstin | string | Yes | GST Identification Number to validate |

#### Response

**Valid GSTIN:**
```json
{
  "success": true,
  "data": {
    "gstin": "01ABCDE0123F1Z5",
    "is_valid": true,
    "format_check": {
      "length": "valid",
      "pattern": "valid",
      "checksum": "valid"
    },
    "parsed_components": {
      "state_code": "01",
      "pan": "ABCDE0123F",
      "entity_number": "1",
      "check_digit": "Z",
      "additional_digit": "5"
    },
    "state_name": "Jammu and Kashmir"
  },
  "timestamp": "2024-01-15T10:30:00Z",
  "request_id": "req_123456789"
}
```

**Invalid GSTIN:**
```json
{
  "success": true,
  "data": {
    "gstin": "INVALID_GSTIN",
    "is_valid": false,
    "format_check": {
      "length": "invalid",
      "pattern": "invalid",
      "checksum": "not_checked"
    },
    "validation_errors": [
      "GSTIN must be exactly 15 characters long",
      "Invalid GSTIN format"
    ]
  },
  "timestamp": "2024-01-15T10:30:00Z",
  "request_id": "req_123456789"
}
```

#### Status Codes
- `200 OK`: Validation completed
- `400 Bad Request`: Missing or invalid request body
- `422 Unprocessable Entity`: Invalid JSON format

## Response Formats

### Success Response Structure

```json
{
  "success": true,
  "data": {
    // Response data specific to the endpoint
  },
  "timestamp": "2024-01-15T10:30:00Z",
  "request_id": "req_123456789"
}
```

### Error Response Structure

```json
{
  "success": false,
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "details": {
      // Additional error details
    }
  },
  "timestamp": "2024-01-15T10:30:00Z",
  "request_id": "req_123456789"
}
```

### Common Fields

| Field | Type | Description |
|-------|------|-------------|
| success | boolean | Indicates if the request was successful |
| data | object | Response data (present in success responses) |
| error | object | Error information (present in error responses) |
| timestamp | string | ISO 8601 timestamp of the response |
| request_id | string | Unique identifier for the request |

## Status Codes

| Code | Description | Usage |
|------|-------------|-------|
| 200 | OK | Successful request |
| 400 | Bad Request | Invalid request parameters |
| 401 | Unauthorized | Invalid or missing authentication |
| 403 | Forbidden | Access denied |
| 404 | Not Found | Resource not found |
| 405 | Method Not Allowed | HTTP method not supported |
| 422 | Unprocessable Entity | Request validation failed |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server error |
| 503 | Service Unavailable | Service temporarily unavailable |

## Examples

### Complete GST Verification Flow

#### Step 1: Fetch Captcha

```bash
curl -X POST https://api.example.com/api/v1/getCaptcha \
  -H "Content-Type: application/json" \
  -d '{}'
```

#### Step 2: Solve Captcha and Get GST Details

```bash
curl -X POST https://api.example.com/api/v1/getGSTDetails \
  -H "Content-Type: application/json" \
  -d '{
    "session_id": "sess_1234567890abcdef",
    "gstin": "01ABCDE0123F1Z5",
    "captcha": "ABC123"
  }'
```

### JavaScript Example

```javascript
class GSTVerificationAPI {
  constructor(baseUrl, apiKey = null) {
    this.baseUrl = baseUrl;
    this.apiKey = apiKey;
  }

  async makeRequest(endpoint, method = 'GET', data = null) {
    const headers = {
      'Content-Type': 'application/json',
    };

    if (this.apiKey) {
      headers['X-API-Key'] = this.apiKey;
    }

    const config = {
      method,
      headers,
    };

    if (data) {
      config.body = JSON.stringify(data);
    }

    const response = await fetch(`${this.baseUrl}${endpoint}`, config);
    return await response.json();
  }

  async getCaptcha() {
    return await this.makeRequest('/api/v1/getCaptcha', 'POST', {});
  }

  async getGSTDetails(sessionId, gstin, captcha) {
    return await this.makeRequest('/api/v1/getGSTDetails', 'POST', {
      session_id: sessionId,
      gstin: gstin,
      captcha: captcha
    });
  }

  async validateGSTIN(gstin) {
    return await this.makeRequest('/api/v1/validateGSTIN', 'POST', {
      gstin: gstin
    });
  }

  async healthCheck() {
    return await this.makeRequest('/api/v1/health');
  }
}

// Usage
const api = new GSTVerificationAPI('https://api.example.com');

// Complete verification flow
async function verifyGST(gstin, captchaSolution) {
  try {
    // Step 1: Get captcha
    const captchaResponse = await api.getCaptcha();
    if (!captchaResponse.success) {
      throw new Error('Failed to fetch captcha');
    }

    // Step 2: Display captcha to user and get solution
    // (In a real application, you would display the captcha image)
    const sessionId = captchaResponse.data.session_id;

    // Step 3: Get GST details
    const gstResponse = await api.getGSTDetails(sessionId, gstin, captchaSolution);
    if (!gstResponse.success) {
      throw new Error(gstResponse.error.message);
    }

    return gstResponse.data;
  } catch (error) {
    console.error('GST verification failed:', error);
    throw error;
  }
}
```

### Python Example

```python
import requests
import base64
from typing import Dict, Any, Optional

class GSTVerificationAPI:
    def __init__(self, base_url: str, api_key: Optional[str] = None):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.session = requests.Session()
        
        if api_key:
            self.session.headers.update({'X-API-Key': api_key})
    
    def _make_request(self, endpoint: str, method: str = 'GET', data: Optional[Dict] = None) -> Dict[str, Any]:
        url = f"{self.base_url}{endpoint}"
        
        try:
            if method.upper() == 'GET':
                response = self.session.get(url)
            elif method.upper() == 'POST':
                response = self.session.post(url, json=data)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            response.raise_for_status()
            return response.json()
        
        except requests.exceptions.RequestException as e:
            raise Exception(f"API request failed: {str(e)}")
    
    def get_captcha(self) -> Dict[str, Any]:
        """Fetch a captcha image and session ID."""
        return self._make_request('/api/v1/getCaptcha', 'POST', {})
    
    def get_gst_details(self, session_id: str, gstin: str, captcha: str) -> Dict[str, Any]:
        """Get GST details using session ID, GSTIN, and captcha solution."""
        data = {
            'session_id': session_id,
            'gstin': gstin,
            'captcha': captcha
        }
        return self._make_request('/api/v1/getGSTDetails', 'POST', data)
    
    def validate_gstin(self, gstin: str) -> Dict[str, Any]:
        """Validate GSTIN format."""
        data = {'gstin': gstin}
        return self._make_request('/api/v1/validateGSTIN', 'POST', data)
    
    def health_check(self) -> Dict[str, Any]:
        """Check API health status."""
        return self._make_request('/api/v1/health')
    
    def save_captcha_image(self, captcha_data: str, filename: str) -> None:
        """Save base64 captcha image to file."""
        # Remove data URL prefix if present
        if captcha_data.startswith('data:image'):
            captcha_data = captcha_data.split(',')[1]
        
        # Decode and save
        image_data = base64.b64decode(captcha_data)
        with open(filename, 'wb') as f:
            f.write(image_data)

# Usage example
if __name__ == "__main__":
    api = GSTVerificationAPI('https://api.example.com')
    
    try:
        # Health check
        health = api.health_check()
        print(f"API Status: {health['data']['status']}")
        
        # Validate GSTIN format
        gstin = "01ABCDE0123F1Z5"
        validation = api.validate_gstin(gstin)
        
        if validation['data']['is_valid']:
            print(f"GSTIN {gstin} is valid")
            
            # Get captcha
            captcha_response = api.get_captcha()
            if captcha_response['success']:
                session_id = captcha_response['data']['session_id']
                
                # Save captcha image
                api.save_captcha_image(
                    captcha_response['data']['captcha_image'], 
                    'captcha.png'
                )
                print("Captcha saved as captcha.png")
                
                # In a real application, you would display the captcha
                # and get user input
                captcha_solution = input("Enter captcha solution: ")
                
                # Get GST details
                gst_details = api.get_gst_details(session_id, gstin, captcha_solution)
                
                if gst_details['success']:
                    data = gst_details['data']
                    print(f"Legal Name: {data['legal_name']}")
                    print(f"Status: {data['gstin_status']}")
                    print(f"Registration Date: {data['registration_date']}")
                else:
                    print(f"Error: {gst_details['error']['message']}")
        else:
            print(f"Invalid GSTIN: {gstin}")
            
    except Exception as e:
        print(f"Error: {str(e)}")
```

## SDKs and Libraries

### Official SDKs

- **Python SDK**: `pip install gst-verification-sdk`
- **Node.js SDK**: `npm install gst-verification-sdk`
- **PHP SDK**: `composer require gst-verification/sdk`

### Community Libraries

- **Java**: Available on Maven Central
- **C#/.NET**: Available on NuGet
- **Ruby**: Available as a gem
- **Go**: Available as a Go module

## Changelog

### Version 1.0.0 (2024-01-15)

#### Added
- Initial API release
- Health check endpoint
- Captcha fetching functionality
- GST details retrieval
- GSTIN format validation
- Rate limiting
- Comprehensive error handling
- Session management
- Security headers
- CORS support

#### Features
- Support for all Indian states
- Automatic session cleanup
- Detailed logging
- Docker support
- Kubernetes deployment manifests
- CI/CD pipeline

---

## Support

For API support and questions:

- **Documentation**: [API Documentation](https://docs.example.com)
- **GitHub Issues**: [Report Issues](https://github.com/your-username/GST-Verification-API/issues)
- **Email**: support@example.com
- **Discord**: [Join our community](https://discord.gg/example)

## License

This API documentation is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.