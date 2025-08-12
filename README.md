# GST Verification API - Django SaaS Platform

A comprehensive Django-based SaaS platform for GST (Goods and Services Tax) verification and validation services in India. This platform provides REST API endpoints for GSTIN validation, GST verification, compliance checking, and related services with subscription-based billing.

## 🚀 Features

### Core Services
- **GSTIN Validation**: Free checksum-based GSTIN format validation
- **GST Verification**: Premium GST verification with detailed business information
- **Bulk Verification**: Process multiple GSTINs simultaneously
- **Compliance Checking**: GST compliance status and filing verification
- **GST Search**: Search GST records by business name, location, etc.

### Platform Features
- **User Authentication**: JWT-based authentication with email verification
- **API Key Management**: Secure API key generation and management
- **Credit System**: Credit-based usage tracking and billing
- **Subscription Management**: Multiple subscription tiers with Stripe integration
- **Rate Limiting**: API rate limiting and usage monitoring
- **Caching**: Redis-based caching for improved performance
- **Documentation**: Comprehensive Swagger/OpenAPI documentation
- **Admin Interface**: Django admin for platform management

## 🏗️ Architecture

### Django Apps Structure
```
gst_saas/
├── authentication/     # User management and authentication
├── api_management/     # API keys, usage tracking, credits
├── gst_services/       # GST verification and validation services
├── billing/           # Subscription and payment management
└── gst_saas/          # Main project configuration
```

### Technology Stack
- **Backend**: Django 4.2+ with Django REST Framework
- **Database**: PostgreSQL (production) / SQLite (development)
- **Cache**: Redis
- **Payment**: Stripe integration
- **Documentation**: drf-spectacular (Swagger/OpenAPI)
- **Task Queue**: Celery with Redis broker
- **Authentication**: JWT tokens

## 📋 Prerequisites

- Python 3.8+
- PostgreSQL (for production)
- Redis
- Node.js (for frontend, if applicable)

## 🛠️ Installation

### 1. Clone the Repository
```bash
git clone <repository-url>
cd GST-Verification-API
```

### 2. Create Virtual Environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements_saas.txt
```

### 4. Environment Configuration
Create a `.env` file in the project root:
```env
# Django Settings
SECRET_KEY=your-secret-key-here
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1

# Database (PostgreSQL for production)
DATABASE_URL=postgresql://username:password@localhost:5432/gst_saas_db

# Redis
REDIS_URL=redis://localhost:6379/0

# Stripe
STRIPE_PUBLISHABLE_KEY=pk_test_...
STRIPE_SECRET_KEY=sk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...

# Email Configuration
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password

# JWT Settings
JWT_SECRET_KEY=your-jwt-secret-key
JWT_ACCESS_TOKEN_LIFETIME=60  # minutes
JWT_REFRESH_TOKEN_LIFETIME=7  # days
```

### 5. Database Setup
```bash
# Run migrations
python manage.py makemigrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser

# Load initial data (optional)
python manage.py loaddata fixtures/initial_data.json
```

### 6. Start Development Server
```bash
python manage.py runserver
```

The API will be available at `http://localhost:8000/`

## 📚 API Documentation

### Interactive Documentation
- **Swagger UI**: `http://localhost:8000/api/schema/swagger-ui/`
- **ReDoc**: `http://localhost:8000/api/schema/redoc/`
- **OpenAPI Schema**: `http://localhost:8000/api/schema/`

### API Endpoints Overview

#### Authentication (`/api/auth/`)
- `POST /register/` - User registration
- `POST /login/` - User login
- `POST /logout/` - User logout
- `GET /profile/` - Get user profile
- `PUT /profile/` - Update user profile
- `POST /change-password/` - Change password
- `POST /reset-password/` - Request password reset
- `POST /verify-email/` - Verify email address

#### API Management (`/api/management/`)
- `GET /api-keys/` - List API keys
- `POST /api-keys/` - Create API key
- `GET /api-keys/{id}/` - Get API key details
- `DELETE /api-keys/{id}/` - Delete API key
- `POST /api-keys/{id}/regenerate/` - Regenerate API key
- `GET /usage/` - Get API usage statistics
- `GET /credits/` - Get credit balance
- `GET /stats/` - Get user statistics

#### GST Services (`/api/gst/`)
- `GET /services/` - List available GST services
- `POST /validate-gstin/` - Validate GSTIN (Free)
- `POST /verify/` - Verify GST details (Premium)
- `POST /verify/bulk/` - Bulk GST verification
- `POST /compliance/` - Check GST compliance
- `POST /search/` - Search GST records
- `GET /history/` - Get verification history

#### Billing (`/api/billing/`)
- `GET /plans/` - List subscription plans
- `GET /subscription/` - Get current subscription
- `POST /subscription/` - Create subscription
- `PUT /subscription/` - Update subscription
- `DELETE /subscription/cancel/` - Cancel subscription
- `GET /invoices/` - List invoices
- `GET /invoices/{id}/` - Get invoice details
- `POST /payments/` - Create payment
- `POST /discounts/validate/` - Validate discount code

## 🔐 Authentication

### API Key Authentication
For API endpoints, include the API key in the header:
```bash
curl -H "X-API-Key: your-api-key-here" \
     -H "Content-Type: application/json" \
     http://localhost:8000/api/gst/verify/
```

### JWT Authentication
For user-specific endpoints, use JWT tokens:
```bash
curl -H "Authorization: Bearer your-jwt-token-here" \
     -H "Content-Type: application/json" \
     http://localhost:8000/api/auth/profile/
```

## 💳 Subscription Plans

### Free Plan
- 100 API calls/month
- GSTIN validation only
- Basic support
- **Price**: Free

### Starter Plan
- 1,000 API calls/month
- GSTIN validation + Basic verification
- Email support
- **Price**: ₹499/month

### Professional Plan
- 10,000 API calls/month
- All verification features
- Bulk verification
- Priority support
- **Price**: ₹999/month

### Enterprise Plan
- Unlimited API calls
- All features
- Custom integrations
- Dedicated support
- **Price**: ₹2,999/month

## 🧪 Usage Examples

### 1. User Registration
```bash
curl -X POST http://localhost:8000/api/auth/register/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword123",
    "first_name": "John",
    "last_name": "Doe",
    "company_name": "Example Corp"
  }'
```

### 2. GSTIN Validation (Free)
```bash
curl -X POST http://localhost:8000/api/gst/validate-gstin/ \
  -H "Content-Type: application/json" \
  -d '{"gstin": "29ABCDE1234F1Z5"}'
```

### 3. GST Verification (Premium)
```bash
curl -X POST http://localhost:8000/api/gst/verify/ \
  -H "X-API-Key: your-api-key-here" \
  -H "Content-Type: application/json" \
  -d '{
    "gstin": "29ABCDE1234F1Z5",
    "verification_type": "detailed"
  }'
```

### 4. Bulk Verification
```bash
curl -X POST http://localhost:8000/api/gst/verify/bulk/ \
  -H "X-API-Key: your-api-key-here" \
  -H "Content-Type: application/json" \
  -d '{
    "gstins": [
      "29ABCDE1234F1Z5",
      "27ABCDE1234F1Z3",
      "19ABCDE1234F1Z1"
    ],
    "verification_type": "basic"
  }'
```

## 🔧 Configuration

### Django Settings
Key configuration options in `gst_saas/settings.py`:

```python
# API Rate Limiting
REST_FRAMEWORK = {
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle'
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '100/hour',
        'user': '1000/hour'
    }
}

# Cache Configuration
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': 'redis://127.0.0.1:6379/1',
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        }
    }
}

# Celery Configuration
CELERY_BROKER_URL = 'redis://localhost:6379/0'
CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'
```

### Environment Variables
Create a `.env` file with the following variables:
- `SECRET_KEY`: Django secret key
- `DEBUG`: Debug mode (True/False)
- `DATABASE_URL`: Database connection string
- `REDIS_URL`: Redis connection string
- `STRIPE_SECRET_KEY`: Stripe secret key
- `EMAIL_HOST_USER`: SMTP email username
- `EMAIL_HOST_PASSWORD`: SMTP email password

## 🧪 Testing

### Run Tests
```bash
# Run all tests
python manage.py test

# Run tests for specific app
python manage.py test authentication
python manage.py test api_management
python manage.py test gst_services
python manage.py test billing

# Run with coverage
coverage run --source='.' manage.py test
coverage report
coverage html
```

### Test Data
Use the provided fixtures for testing:
```bash
python manage.py loaddata fixtures/test_data.json
```

## 🚀 Deployment

### Production Setup

1. **Environment Variables**
   ```bash
   export DEBUG=False
   export ALLOWED_HOSTS=yourdomain.com
   export DATABASE_URL=postgresql://...
   ```

2. **Static Files**
   ```bash
   python manage.py collectstatic
   ```

3. **Database Migration**
   ```bash
   python manage.py migrate
   ```

4. **Start Services**
   ```bash
   # Django application
   gunicorn gst_saas.wsgi:application
   
   # Celery worker
   celery -A gst_saas worker -l info
   
   # Celery beat (for scheduled tasks)
   celery -A gst_saas beat -l info
   ```

### Docker Deployment
```dockerfile
# Dockerfile
FROM python:3.9

WORKDIR /app
COPY requirements_saas.txt .
RUN pip install -r requirements_saas.txt

COPY . .
EXPOSE 8000

CMD ["gunicorn", "gst_saas.wsgi:application", "--bind", "0.0.0.0:8000"]
```

```yaml
# docker-compose.yml
version: '3.8'
services:
  web:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DEBUG=False
      - DATABASE_URL=postgresql://postgres:password@db:5432/gst_saas
    depends_on:
      - db
      - redis
  
  db:
    image: postgres:13
    environment:
      POSTGRES_DB: gst_saas
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: password
    volumes:
      - postgres_data:/var/lib/postgresql/data
  
  redis:
    image: redis:6
    ports:
      - "6379:6379"

volumes:
  postgres_data:
```

## 📊 Monitoring & Analytics

### Key Metrics
- API request volume and response times
- User registration and subscription rates
- Credit consumption patterns
- Error rates and types
- Revenue and billing metrics

### Health Checks
```bash
# API health check
curl http://localhost:8000/api/health/

# Database health check
python manage.py check --database default

# Cache health check
python manage.py shell -c "from django.core.cache import cache; print(cache.get('test') or 'Cache OK')"
```

## 🔒 Security Features

- **Input Validation**: Comprehensive request validation
- **Rate Limiting**: API rate limiting per user/IP
- **Authentication**: JWT-based secure authentication
- **API Keys**: Secure API key management
- **Data Encryption**: Sensitive data encryption
- **CORS**: Configurable CORS policies
- **HTTPS**: SSL/TLS encryption support
- **Audit Logging**: Complete request/response logging

## 📖 App Documentation

Detailed documentation for each Django app:

- [Authentication App](authentication/README.md) - User management and authentication
- [API Management App](api_management/README.md) - API keys, usage tracking, credits
- [GST Services App](gst_services/README.md) - GST verification and validation
- [Billing App](billing/README.md) - Subscription and payment management

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines
- Follow PEP 8 style guidelines
- Write comprehensive tests
- Update documentation
- Use meaningful commit messages

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: Check the app-specific README files
- **Issues**: Create an issue on GitHub
- **Email**: support@gstverificationapi.com
- **API Status**: Check status page for service updates

## 🚧 Roadmap

### Upcoming Features
- [ ] GraphQL API support
- [ ] Webhook notifications
- [ ] Advanced analytics dashboard
- [ ] Mobile app integration
- [ ] Multi-language support
- [ ] Advanced fraud detection
- [ ] Custom reporting tools
- [ ] Third-party integrations (Zapier, etc.)

### Version History
- **v1.0.0** - Initial release with core GST verification features
- **v1.1.0** - Added subscription management and billing
- **v1.2.0** - Enhanced API management and rate limiting
- **v1.3.0** - Added bulk verification and caching

---

**Built with ❤️ using Django and Django REST Framework**
