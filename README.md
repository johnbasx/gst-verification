# GST Verification API

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://python.org)
[![Flask Version](https://img.shields.io/badge/flask-2.3.3-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Test Coverage](https://img.shields.io/badge/coverage-95%25-brightgreen.svg)]()

A robust, professional, and secure REST API for fetching GST (Goods and Services Tax) taxpayer details from the official Indian GST portal. This API handles captcha solving, session management, and provides structured JSON responses with comprehensive error handling.

## 🚀 Features

- **Secure Session Management**: Automatic session creation and cleanup with configurable timeouts
- **GSTIN Validation**: Built-in validation for Indian GSTIN format compliance
- **Rate Limiting**: Configurable rate limiting to prevent abuse
- **Comprehensive Error Handling**: Detailed error responses with proper HTTP status codes
- **CORS Support**: Cross-origin resource sharing enabled for web applications
- **Logging**: Structured logging with configurable levels
- **Health Monitoring**: Health check endpoint for monitoring and load balancers
- **Type Safety**: Full type hints for better code maintainability
- **Testing**: Comprehensive test suite with 95%+ coverage
- **Production Ready**: Configurable for different environments

## 📋 Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [API Documentation](#api-documentation)
- [Configuration](#configuration)
- [Testing](#testing)
- [Deployment](#deployment)
- [Error Handling](#error-handling)
- [Rate Limiting](#rate-limiting)
- [Security](#security)
- [Contributing](#contributing)
- [License](#license)

## 🛠 Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package installer)
- Virtual environment (recommended)

### Step-by-Step Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/johnbasx/gst-verification.git
   cd gst-verification
   ```

2. **Create and activate virtual environment:**
   ```bash
   # On Windows
   python -m venv venv
   venv\Scripts\activate
   
   # On macOS/Linux
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set environment variables (optional):**
   ```bash
   # Create .env file
   echo "FLASK_ENV=development" > .env
   echo "LOG_LEVEL=INFO" >> .env
   echo "SESSION_TIMEOUT=300" >> .env
   ```

5. **Run the application:**
   ```bash
   python app.py
   ```

The API will be available at `http://localhost:5001`

## 🚀 Quick Start

### Basic Usage Example

```python
import requests
import json

# Base URL
base_url = "http://localhost:5001/api/v1"

# Step 1: Get captcha
captcha_response = requests.get(f"{base_url}/getCaptcha")
captcha_data = captcha_response.json()

if captcha_data['success']:
    session_id = captcha_data['data']['session_id']
    captcha_image = captcha_data['data']['captcha_image']
    
    # Display captcha image to user (in a real application)
    print(f"Session ID: {session_id}")
    print(f"Captcha Image: {captcha_image[:50]}...")  # Truncated for display
    
    # Step 2: Get user input for captcha and GSTIN
    user_captcha = input("Enter captcha: ")
    user_gstin = input("Enter GSTIN: ")
    
    # Step 3: Fetch GST details
    gst_response = requests.post(
        f"{base_url}/getGSTDetails",
        json={
            "session_id": session_id,
            "gstin": user_gstin,
            "captcha": user_captcha
        },
        headers={"Content-Type": "application/json"}
    )
    
    gst_data = gst_response.json()
    
    if gst_data['success']:
        print("GST Details:")
        print(json.dumps(gst_data['data'], indent=2))
    else:
        print(f"Error: {gst_data['message']}")
else:
    print(f"Failed to get captcha: {captcha_data['message']}")
```

## 📚 API Documentation

### Base URL
```
http://localhost:5001/api/v1
```

### Authentication
Currently, no authentication is required. For production use, consider implementing API key authentication.

### Response Format
All API responses follow a consistent format:

**Success Response:**
```json
{
  "success": true,
  "message": "Operation completed successfully",
  "data": {
    // Response data
  },
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

**Error Response:**
```json
{
  "success": false,
  "error_code": "ERROR_CODE",
  "message": "Human readable error message",
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

### Endpoints

#### 1. Health Check

**GET** `/health`

Check if the API is running and healthy.

**Response:**
```json
{
  "status": "healthy",
  "service": "GST Verification API",
  "version": "1.0.0",
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

#### 2. Get Captcha

**GET** `/getCaptcha`

Fetch a captcha image and create a session for GST verification.

**Rate Limit:** 20 requests per minute

**Response:**
```json
{
  "success": true,
  "message": "Captcha fetched successfully",
  "data": {
    "session_id": "550e8400-e29b-41d4-a716-446655440000",
    "captcha_image": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA...",
    "expires_in": 300
  },
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

**Error Codes:**
- `SESSION_INIT_FAILED`: Failed to initialize session with GST portal
- `CAPTCHA_FETCH_FAILED`: Failed to fetch captcha from GST portal
- `TIMEOUT_ERROR`: Request timeout
- `CONNECTION_ERROR`: Connection failed
- `INTERNAL_ERROR`: Unexpected server error

#### 3. Get GST Details

**POST** `/getGSTDetails`

Fetch GST taxpayer details using GSTIN and captcha.

**Rate Limit:** 10 requests per minute

**Request Body:**
```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "gstin": "01ABCDE0123F1Z5",
  "captcha": "ABC123"
}
```

**Response:**
```json
{
  "success": true,
  "message": "GST details fetched successfully",
  "data": {
    "gstin": "01ABCDE0123F1Z5",
    "lgnm": "EXAMPLE COMPANY PRIVATE LIMITED",
    "tradeNam": "EXAMPLE TRADE NAME",
    "sts": "Active",
    "rgdt": "01/07/2017",
    "ctb": "Private Limited Company",
    "pradr": {
      "adr": "123, EXAMPLE STREET, EXAMPLE CITY",
      "loc": "EXAMPLE LOCALITY",
      "dst": "EXAMPLE DISTRICT",
      "stcd": "01",
      "pncd": "110001"
    },
    "adadr": [],
    "nba": [
      "Wholesale Business",
      "Retail Business"
    ],
    "dty": "Regular",
    "cxdt": "",
    "stj": "EXAMPLE JURISDICTION",
    "ctj": "EXAMPLE CENTRAL JURISDICTION",
    "einvoiceStatus": "Yes",
    "adhrVFlag": "Yes",
    "adhrVdt": "15/08/2021",
    "ekycVFlag": "Yes",
    "cmpRt": "NA",
    "isFieldVisitConducted": "No"
  },
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

**Error Codes:**
- `INVALID_CONTENT_TYPE`: Content-Type must be application/json
- `EMPTY_REQUEST`: Request body cannot be empty
- `MISSING_FIELDS`: Required fields are missing
- `INVALID_GSTIN`: GSTIN format is invalid
- `INVALID_CAPTCHA`: Captcha is invalid or too short
- `INVALID_SESSION`: Session ID is invalid or expired
- `SESSION_EXPIRED`: Session has expired
- `GST_PORTAL_ERROR`: Error from GST portal
- `TIMEOUT_ERROR`: Request timeout
- `CONNECTION_ERROR`: Connection failed
- `INTERNAL_ERROR`: Unexpected server error

#### 4. Validate GSTIN

**POST** `/validateGSTIN`

Validate GSTIN format without making external requests.

**Request Body:**
```json
{
  "gstin": "01ABCDE0123F1Z5"
}
```

**Response:**
```json
{
  "success": true,
  "message": "GSTIN validation completed",
  "data": {
    "gstin": "01ABCDE0123F1Z5",
    "is_valid": true,
    "format_info": {
      "expected_length": 15,
      "pattern": "2 digits (state) + 10 alphanumeric (PAN) + 1 check digit + 1 alphabet + 1 number + 1 alphabet"
    }
  },
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

## ⚙️ Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FLASK_ENV` | `development` | Environment (development/testing/staging/production) |
| `PORT` | `5001` | Port to run the application |
| `DEBUG` | `False` | Enable debug mode |
| `LOG_LEVEL` | `INFO` | Logging level (DEBUG/INFO/WARNING/ERROR) |
| `LOG_FILE` | `gst_api.log` | Log file path |
| `SESSION_TIMEOUT` | `300` | Session timeout in seconds |
| `REQUEST_TIMEOUT` | `30` | HTTP request timeout in seconds |
| `RATE_LIMIT_CAPTCHA` | `20` | Rate limit for captcha endpoint (per minute) |
| `RATE_LIMIT_GST_DETAILS` | `10` | Rate limit for GST details endpoint (per minute) |
| `CORS_ORIGINS` | `*` | Allowed CORS origins |
| `SECRET_KEY` | `dev-secret-key-change-in-production` | Flask secret key |

### Configuration Files

The application uses `config.py` for environment-specific configurations:

- `DevelopmentConfig`: For local development
- `TestingConfig`: For running tests
- `StagingConfig`: For staging environment
- `ProductionConfig`: For production deployment

## 🧪 Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html

# Run specific test file
pytest test_app.py

# Run with verbose output
pytest -v
```

### Test Coverage

The test suite covers:
- ✅ All API endpoints
- ✅ GSTIN validation
- ✅ Session management
- ✅ Error handling
- ✅ Rate limiting
- ✅ Configuration validation

### Writing Tests

Tests are located in `test_app.py`. To add new tests:

```python
def test_new_functionality(client):
    """Test description."""
    response = client.get('/api/v1/endpoint')
    assert response.status_code == 200
    
    data = json.loads(response.data)
    assert data['success'] == True
```

## 🚀 Deployment

### Docker Deployment

1. **Create Dockerfile:**
   ```dockerfile
   FROM python:3.9-slim
   
   WORKDIR /app
   
   COPY requirements.txt .
   RUN pip install --no-cache-dir -r requirements.txt
   
   COPY . .
   
   EXPOSE 5001
   
   CMD ["gunicorn", "--bind", "0.0.0.0:5001", "app:app"]
   ```

2. **Build and run:**
   ```bash
   docker build -t gst-verification-api .
   docker run -p 5001:5001 -e FLASK_ENV=production gst-verification-api
   ```

### Production Deployment

1. **Using Gunicorn:**
   ```bash
   gunicorn --bind 0.0.0.0:5001 --workers 4 app:app
   ```

2. **Using systemd service:**
   ```ini
   [Unit]
   Description=GST Verification API
   After=network.target
   
   [Service]
   User=www-data
   Group=www-data
   WorkingDirectory=/path/to/GST-Verification-API
   Environment=FLASK_ENV=production
   ExecStart=/path/to/venv/bin/gunicorn --bind 0.0.0.0:5001 --workers 4 app:app
   Restart=always
   
   [Install]
   WantedBy=multi-user.target
   ```

3. **Nginx configuration:**
   ```nginx
   server {
       listen 80;
       server_name your-domain.com;
       
       location / {
           proxy_pass http://127.0.0.1:5001;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
       }
   }
   ```

### Cloud Deployment

#### Heroku
```bash
# Create Procfile
echo "web: gunicorn app:app" > Procfile

# Deploy
heroku create your-app-name
git push heroku main
```

#### AWS Lambda
Use the Serverless Framework or AWS SAM for serverless deployment.

## 🛡️ Error Handling

The API provides comprehensive error handling with standardized error codes:

### HTTP Status Codes
- `200`: Success
- `400`: Bad Request (validation errors)
- `404`: Not Found
- `405`: Method Not Allowed
- `429`: Too Many Requests (rate limiting)
- `500`: Internal Server Error
- `502`: Bad Gateway (GST portal errors)
- `503`: Service Unavailable (connection errors)
- `504`: Gateway Timeout

### Error Response Format
```json
{
  "success": false,
  "error_code": "SPECIFIC_ERROR_CODE",
  "message": "Human readable error message",
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

## 🚦 Rate Limiting

Rate limiting is implemented to prevent abuse:

- **Captcha endpoint**: 20 requests per minute
- **GST details endpoint**: 10 requests per minute
- **Validation endpoint**: No rate limit

Rate limits are configurable via environment variables and can be adjusted based on your needs.

## 🔒 Security

### Security Features
- Input validation and sanitization
- GSTIN format validation
- Session timeout management
- Rate limiting
- CORS configuration
- Security headers
- Error message sanitization

### Security Best Practices
1. Use HTTPS in production
2. Set strong `SECRET_KEY`
3. Configure appropriate CORS origins
4. Implement API key authentication for production
5. Monitor and log security events
6. Regular security updates

### Production Security Checklist
- [ ] Set `FLASK_ENV=production`
- [ ] Configure strong `SECRET_KEY`
- [ ] Enable HTTPS
- [ ] Set appropriate CORS origins
- [ ] Implement authentication
- [ ] Configure firewall rules
- [ ] Set up monitoring and alerting
- [ ] Regular security audits

## 🤝 Contributing

We welcome contributions! Please follow these steps:

1. **Fork the repository**
2. **Create a feature branch:**
   ```bash
   git checkout -b feature/amazing-feature
   ```
3. **Make your changes and add tests**
4. **Run tests:**
   ```bash
   pytest
   ```
5. **Run code formatting:**
   ```bash
   black .
   flake8
   ```
6. **Commit your changes:**
   ```bash
   git commit -m "Add amazing feature"
   ```
7. **Push to the branch:**
   ```bash
   git push origin feature/amazing-feature
   ```
8. **Open a Pull Request**

### Development Guidelines
- Follow PEP 8 style guide
- Add type hints to all functions
- Write comprehensive tests
- Update documentation
- Add logging for important operations

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📞 Support

For support and questions:

- **Email**: support@example.com
- **Issues**: [GitHub Issues](https://github.com/your-username/GST-Verification-API/issues)
- **Documentation**: [API Documentation](https://your-docs-url.com)

## 🙏 Acknowledgments

- Indian Government GST Portal for providing the verification service
- Flask community for the excellent web framework
- Contributors and users of this API

## 📈 Roadmap

- [ ] Database integration for session storage
- [ ] Redis support for distributed caching
- [ ] API key authentication
- [ ] Webhook support
- [ ] Bulk GSTIN verification
- [ ] Advanced analytics and monitoring
- [ ] GraphQL API support
- [ ] SDK for popular programming languages

---

**Made with ❤️ for the developer community**
