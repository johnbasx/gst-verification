# API Management App

The API Management app handles API key generation, usage tracking, credit management, rate limiting, and user statistics for the GST Verification API platform.

## Features

- **API Key Management**: Generate, regenerate, and manage API keys
- **Usage Tracking**: Detailed API usage analytics and monitoring
- **Credit System**: Credit-based API access with purchase options
- **Rate Limiting**: Configurable rate limits per API key
- **Statistics**: Comprehensive usage statistics and analytics
- **Stripe Integration**: Credit purchases through Stripe payment processing

## Models

### APIKey
Manages API keys for users:
- `user` (ForeignKey to User)
- `key_id` (unique identifier)
- `key_hash` (hashed API key)
- `name` (user-defined name)
- `is_active` (status)
- `rate_limit_per_minute`, `rate_limit_per_hour`, `rate_limit_per_day`
- `total_requests`, `last_used`
- `created_at`, `updated_at`

### APIUsage
Tracks API usage per request:
- `user` (ForeignKey to User)
- `api_key` (ForeignKey to APIKey)
- `endpoint` (API endpoint used)
- `method` (HTTP method)
- `status_code` (response status)
- `response_time` (request duration)
- `credits_used` (credits consumed)
- `ip_address`, `user_agent`
- `timestamp`

### CreditPackage
Defines available credit packages:
- `name`, `description`
- `credits` (number of credits)
- `price` (package price)
- `currency`
- `is_active`, `is_popular`
- `sort_order`

### UserCredits
Tracks user credit balance:
- `user` (OneToOne to User)
- `balance` (current credits)
- `total_purchased`, `total_used`
- `last_purchase_date`, `last_usage_date`

### RateLimitTracker
Tracks rate limit usage:
- `api_key` (ForeignKey to APIKey)
- `minute_count`, `hour_count`, `day_count`
- `minute_reset`, `hour_reset`, `day_reset`

## API Endpoints

### API Key Management
- `GET /api/management/keys/` - List user's API keys
- `POST /api/management/keys/` - Create new API key
- `GET /api/management/keys/{id}/` - Get API key details
- `PUT /api/management/keys/{id}/` - Update API key
- `DELETE /api/management/keys/{id}/` - Delete API key
- `POST /api/management/keys/{id}/regenerate/` - Regenerate API key
- `GET /api/management/keys/{id}/stats/` - Get API key statistics

### Usage Tracking
- `GET /api/management/usage/` - Get API usage history
- `GET /api/management/rate-limit/` - Check rate limit status

### Credit Management
- `GET /api/management/credits/` - Get user credit balance
- `GET /api/management/credit-packages/` - List available credit packages
- `POST /api/management/credits/purchase/` - Purchase credits

### Statistics
- `GET /api/management/stats/` - Get comprehensive user statistics

## Serializers

### APIKeyCreateSerializer
Handles API key creation:
```python
{
    "name": "Production API Key",
    "rate_limit_per_minute": 100,
    "rate_limit_per_hour": 1000,
    "rate_limit_per_day": 10000
}
```

### APIUsageSerializer
Tracks API usage data:
```python
{
    "endpoint": "/api/gst/verify/",
    "method": "POST",
    "status_code": 200,
    "response_time": 0.25,
    "credits_used": 1,
    "timestamp": "2024-01-15T10:30:00Z"
}
```

### CreditPurchaseSerializer
Handles credit purchases:
```python
{
    "package_id": 1,
    "payment_method_id": "pm_1234567890"
}
```

## Views

### APIKeyListCreateView
- Lists user's API keys
- Creates new API keys with secure generation
- Applies rate limits and validation

### APIKeyDetailView
- Retrieves, updates, and deletes API keys
- Enforces ownership validation
- Logs key management activities

### APIKeyRegenerateView
- Regenerates API key securely
- Invalidates old key immediately
- Maintains usage statistics

### CreditPurchaseView
- Processes credit purchases via Stripe
- Updates user credit balance
- Creates purchase records

### UserStatsView
- Provides comprehensive usage analytics
- Calculates performance metrics
- Generates usage reports

## Authentication & Authorization

### API Key Authentication
```python
# Custom authentication class
class APIKeyAuthentication(BaseAuthentication):
    def authenticate(self, request):
        api_key = request.META.get('HTTP_X_API_KEY')
        if not api_key:
            return None
        
        # Validate and return user
        return self.get_user_from_api_key(api_key)
```

### Rate Limiting
```python
# Rate limit decorator
@rate_limit_check
def api_endpoint(request):
    # API logic here
    pass
```

## Credit System

### Credit Deduction
```python
def deduct_credits(user, amount):
    """Deduct credits from user balance"""
    user_credits = UserCredits.objects.get(user=user)
    if user_credits.balance >= amount:
        user_credits.balance -= amount
        user_credits.total_used += amount
        user_credits.save()
        return True
    return False
```

### Credit Packages
- **Starter**: 1,000 credits - $10
- **Professional**: 5,000 credits - $40
- **Enterprise**: 25,000 credits - $150
- **Custom**: Tailored packages available

## Usage Examples

### Create API Key
```bash
curl -X POST http://localhost:8000/api/management/keys/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production Key",
    "rate_limit_per_minute": 100
  }'
```

### Use API Key
```bash
curl -X POST http://localhost:8000/api/gst/verify/ \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"gstin": "29ABCDE1234F1Z5"}'
```

### Purchase Credits
```bash
curl -X POST http://localhost:8000/api/management/credits/purchase/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "package_id": 1,
    "payment_method_id": "pm_1234567890"
  }'
```

### Check Usage Statistics
```bash
curl -X GET http://localhost:8000/api/management/stats/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## Rate Limiting

### Default Limits
- **Free Tier**: 10 requests/minute, 100/hour, 1000/day
- **Premium Tier**: 100 requests/minute, 1000/hour, 10000/day
- **Enterprise**: Custom limits

### Rate Limit Headers
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1642248000
```

## Monitoring & Analytics

### Key Metrics
- Total API requests
- Success/error rates
- Average response time
- Credit consumption
- Popular endpoints
- Geographic usage

### Real-time Monitoring
- Live usage dashboard
- Alert notifications
- Performance metrics
- Error tracking

## Security Features

- **Secure Key Generation**: Cryptographically secure API keys
- **Key Hashing**: API keys stored as hashes
- **IP Whitelisting**: Optional IP restrictions
- **Request Signing**: HMAC request signing support
- **Audit Logging**: Comprehensive usage logs

## Configuration

Add to Django settings:
```python
# API Management Settings
API_KEY_LENGTH = 32
DEFAULT_RATE_LIMITS = {
    'per_minute': 60,
    'per_hour': 1000,
    'per_day': 10000,
}

# Stripe Settings
STRIPE_PUBLISHABLE_KEY = 'pk_test_...'
STRIPE_SECRET_KEY = 'sk_test_...'
```

## Dependencies

- Django REST Framework
- stripe (payment processing)
- redis (rate limiting cache)
- celery (background tasks)
- drf-spectacular (API documentation)

## Testing

Run tests for the API management app:
```bash
python manage.py test api_management
```

## Admin Interface

The app includes admin configurations for:
- API key management
- Usage analytics
- Credit package management
- User credit monitoring

## Background Tasks

### Credit Expiration
```python
@periodic_task(run_every=crontab(hour=0, minute=0))
def expire_unused_credits():
    """Expire unused credits after 1 year"""
    pass
```

### Usage Aggregation
```python
@periodic_task(run_every=crontab(minute=0))
def aggregate_hourly_usage():
    """Aggregate usage statistics hourly"""
    pass
```