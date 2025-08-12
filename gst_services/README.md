# GST Services App

The GST Services app provides comprehensive GST (Goods and Services Tax) verification, validation, and compliance services for the Indian tax system. It offers both free and premium GST-related services with robust validation and caching mechanisms.

## Features

- **GSTIN Validation**: Free checksum-based GSTIN validation
- **GST Verification**: Premium GST verification with detailed business information
- **Bulk Verification**: Process multiple GSTINs simultaneously
- **Compliance Checking**: GST compliance status verification
- **GST Search**: Search GST records by various parameters
- **Caching System**: Redis-based caching for improved performance
- **Rate Limiting**: API rate limiting and credit management
- **History Tracking**: Complete verification history

## Models

### GSTService
Defines available GST services:
- `name`, `description`
- `endpoint` (API endpoint)
- `method` (HTTP method)
- `credits_required` (cost per request)
- `is_active`, `is_premium`
- `rate_limit_per_minute`
- `created_at`, `updated_at`

### GSTVerification
Stores GST verification results:
- `user` (ForeignKey to User)
- `gstin` (GST identification number)
- `verification_type` (basic/detailed/compliance)
- `status` (success/failed/pending)
- `response_data` (JSON response)
- `credits_used`
- `verification_date`
- `is_cached` (whether result was cached)

## API Endpoints

### GST Services
- `GET /api/gst/services/` - List available GST services

### GSTIN Validation (Free)
- `POST /api/gst/validate-gstin/` - Validate GSTIN format and checksum

### GST Verification (Premium)
- `POST /api/gst/verify/` - Verify GST details with complete information
- `POST /api/gst/verify/bulk/` - Bulk GST verification

### GST Compliance
- `POST /api/gst/compliance/` - Check GST compliance status

### GST Search
- `POST /api/gst/search/` - Search GST records

### History
- `GET /api/gst/history/` - Get verification history

## Serializers

### GSTINValidationSerializer
Handles GSTIN validation:
```python
{
    "gstin": "29ABCDE1234F1Z5"
}
```

### GSTVerificationSerializer
Handles GST verification requests:
```python
{
    "gstin": "29ABCDE1234F1Z5",
    "verification_type": "detailed",
    "include_compliance": true
}
```

### BulkGSTVerificationSerializer
Handles bulk verification:
```python
{
    "gstins": [
        "29ABCDE1234F1Z5",
        "27ABCDE1234F1Z3",
        "19ABCDE1234F1Z1"
    ],
    "verification_type": "basic"
}
```

### GSTSearchSerializer
Handles GST search requests:
```python
{
    "search_type": "business_name",
    "query": "Example Company",
    "state_code": "29",
    "limit": 10
}
```

## Views

### GSTServiceListView
- Lists all available GST services
- Shows pricing and rate limits
- Public endpoint (no authentication required)

### GSTINValidationView
- Validates GSTIN format and checksum
- Free service (no credits required)
- Implements GSTIN checksum algorithm

### GSTVerificationView
- Performs comprehensive GST verification
- Requires API key authentication
- Deducts credits from user balance
- Implements caching for repeated requests

### BulkGSTVerificationView
- Processes multiple GSTINs in a single request
- Optimized for batch processing
- Returns detailed results for each GSTIN

### GSTComplianceCheckView
- Checks GST compliance status
- Validates filing status and returns
- Provides compliance score

## GSTIN Validation Algorithm

### Checksum Calculation
```python
def calculate_gstin_checksum(gstin_without_checksum):
    """Calculate GSTIN checksum digit"""
    factor = 2
    sum_val = 0
    code_point_chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    
    for char in reversed(gstin_without_checksum):
        digit = code_point_chars.index(char)
        sum_val += digit * factor
        factor = 1 if factor == 2 else 2
    
    remainder = sum_val % 36
    checksum = (36 - remainder) % 36
    return code_point_chars[checksum]
```

### GSTIN Format Validation
```python
def validate_gstin_format(gstin):
    """Validate GSTIN format"""
    if len(gstin) != 15:
        return False, "GSTIN must be 15 characters long"
    
    # State code (first 2 digits)
    if not gstin[:2].isdigit():
        return False, "First 2 characters must be state code"
    
    # PAN structure (next 10 characters)
    pan_part = gstin[2:12]
    if not re.match(r'^[A-Z]{5}[0-9]{4}[A-Z]$', pan_part):
        return False, "Invalid PAN structure in GSTIN"
    
    # Entity code (13th character)
    if not gstin[12].isdigit():
        return False, "13th character must be entity code"
    
    # Z character (14th character)
    if gstin[13] != 'Z':
        return False, "14th character must be 'Z'"
    
    return True, "Valid GSTIN format"
```

## GST Verification Response

### Basic Verification
```json
{
    "gstin": "29ABCDE1234F1Z5",
    "status": "Active",
    "business_name": "Example Private Limited",
    "trade_name": "Example Corp",
    "registration_date": "2017-07-01",
    "state_code": "29",
    "state_name": "Karnataka",
    "taxpayer_type": "Regular",
    "constitution": "Private Limited Company",
    "verification_date": "2024-01-15T10:30:00Z",
    "is_valid": true
}
```

### Detailed Verification
```json
{
    "gstin": "29ABCDE1234F1Z5",
    "basic_info": {
        "business_name": "Example Private Limited",
        "trade_name": "Example Corp",
        "status": "Active",
        "registration_date": "2017-07-01"
    },
    "address_info": {
        "principal_address": {
            "building": "Tech Park",
            "street": "MG Road",
            "city": "Bangalore",
            "state": "Karnataka",
            "pincode": "560001"
        }
    },
    "business_info": {
        "taxpayer_type": "Regular",
        "constitution": "Private Limited Company",
        "business_activities": [
            "Software Development",
            "IT Services"
        ]
    },
    "compliance_info": {
        "filing_status": "Regular",
        "last_return_filed": "2024-01-10",
        "compliance_score": 95
    }
}
```

## Caching Strategy

### Redis Caching
```python
def get_cached_verification(gstin):
    """Get cached verification result"""
    cache_key = f"gst_verification:{gstin}"
    cached_result = cache.get(cache_key)
    if cached_result:
        return json.loads(cached_result)
    return None

def cache_verification_result(gstin, result, ttl=3600):
    """Cache verification result"""
    cache_key = f"gst_verification:{gstin}"
    cache.set(cache_key, json.dumps(result), ttl)
```

### Cache TTL Settings
- **Basic Verification**: 1 hour
- **Detailed Verification**: 6 hours
- **Compliance Check**: 30 minutes
- **Search Results**: 15 minutes

## Usage Examples

### Validate GSTIN (Free)
```bash
curl -X POST http://localhost:8000/api/gst/validate-gstin/ \
  -H "Content-Type: application/json" \
  -d '{"gstin": "29ABCDE1234F1Z5"}'
```

### Verify GST Details (Premium)
```bash
curl -X POST http://localhost:8000/api/gst/verify/ \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "gstin": "29ABCDE1234F1Z5",
    "verification_type": "detailed"
  }'
```

### Bulk Verification
```bash
curl -X POST http://localhost:8000/api/gst/verify/bulk/ \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "gstins": [
      "29ABCDE1234F1Z5",
      "27ABCDE1234F1Z3"
    ],
    "verification_type": "basic"
  }'
```

### Search GST Records
```bash
curl -X POST http://localhost:8000/api/gst/search/ \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "search_type": "business_name",
    "query": "Example Company",
    "state_code": "29"
  }'
```

## Service Pricing

### Credit Requirements
- **GSTIN Validation**: Free (0 credits)
- **Basic Verification**: 1 credit
- **Detailed Verification**: 3 credits
- **Compliance Check**: 2 credits
- **GST Search**: 1 credit per result
- **Bulk Verification**: Credits per GSTIN

## Error Handling

### Common Error Responses
```json
{
    "error": "invalid_gstin",
    "message": "Invalid GSTIN format",
    "details": {
        "gstin": "29ABCDE1234F1Z4",
        "reason": "Checksum validation failed"
    }
}
```

### Error Codes
- `invalid_gstin`: GSTIN format or checksum invalid
- `gstin_not_found`: GSTIN not registered
- `insufficient_credits`: Not enough credits
- `rate_limit_exceeded`: API rate limit exceeded
- `service_unavailable`: External service unavailable

## State Codes

### Indian State GST Codes
```python
STATE_CODES = {
    '01': 'Jammu and Kashmir',
    '02': 'Himachal Pradesh',
    '03': 'Punjab',
    '04': 'Chandigarh',
    '05': 'Uttarakhand',
    '06': 'Haryana',
    '07': 'Delhi',
    '08': 'Rajasthan',
    '09': 'Uttar Pradesh',
    '10': 'Bihar',
    # ... more states
    '29': 'Karnataka',
    '33': 'Tamil Nadu',
    '36': 'Telangana',
    '37': 'Andhra Pradesh'
}
```

## Performance Optimization

### Database Indexing
```python
class Meta:
    indexes = [
        models.Index(fields=['gstin']),
        models.Index(fields=['user', 'verification_date']),
        models.Index(fields=['status', 'verification_type']),
    ]
```

### Query Optimization
- Use select_related for foreign keys
- Implement pagination for large result sets
- Cache frequently accessed data
- Use database connection pooling

## Security Features

- **Input Validation**: Comprehensive GSTIN validation
- **Rate Limiting**: Per-user and per-IP rate limits
- **API Key Authentication**: Secure API access
- **Data Encryption**: Sensitive data encryption
- **Audit Logging**: Complete request/response logging

## Configuration

Add to Django settings:
```python
# GST Services Settings
GST_SERVICES = {
    'CACHE_TTL': {
        'basic': 3600,      # 1 hour
        'detailed': 21600,  # 6 hours
        'compliance': 1800, # 30 minutes
    },
    'RATE_LIMITS': {
        'validation': 100,  # per minute
        'verification': 60, # per minute
        'search': 30,       # per minute
    },
    'MOCK_MODE': False,  # Use mock responses for testing
}

# Redis Cache Settings
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': 'redis://127.0.0.1:6379/1',
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        }
    }
}
```

## Testing

### Mock Responses
For testing and development, the app supports mock responses:
```python
MOCK_GST_RESPONSES = {
    '29ABCDE1234F1Z5': {
        'status': 'Active',
        'business_name': 'Example Private Limited',
        'trade_name': 'Example Corp',
        # ... more mock data
    }
}
```

### Run Tests
```bash
python manage.py test gst_services
```

## Dependencies

- Django REST Framework
- redis (caching)
- requests (external API calls)
- celery (background tasks)
- drf-spectacular (API documentation)

## Admin Interface

The app includes admin configurations for:
- GST service management
- Verification history monitoring
- Performance analytics
- Error tracking

## Monitoring & Analytics

### Key Metrics
- Verification success rates
- Average response times
- Popular verification types
- Error frequency
- Cache hit rates
- Credit consumption patterns

### Health Checks
```python
@api_view(['GET'])
def health_check(request):
    """GST services health check"""
    return Response({
        'status': 'healthy',
        'services': {
            'validation': 'operational',
            'verification': 'operational',
            'cache': 'operational'
        },
        'timestamp': timezone.now()
    })
```