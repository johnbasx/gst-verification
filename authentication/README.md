# Authentication App

The Authentication app handles user registration, login, profile management, email verification, and activity tracking for the GST Verification API platform.

## Features

- **User Registration & Login**: Email-based authentication with JWT tokens
- **Email Verification**: Secure email verification process
- **Password Management**: Password change and reset functionality
- **User Profiles**: Comprehensive user profile management
- **Activity Tracking**: Detailed logging of user activities
- **Premium Features**: Support for premium user accounts

## Models

### User
Extends Django's AbstractUser with additional fields:
- `email` (primary identifier)
- `first_name`, `last_name`
- `company_name`, `phone_number`
- `is_verified`, `is_premium`
- `subscription_start_date`, `subscription_end_date`
- `credits_balance`

### UserActivity
Tracks user actions and system events:
- `user` (ForeignKey to User)
- `action` (type of activity)
- `description` (detailed description)
- `ip_address`, `user_agent`
- `timestamp`

## API Endpoints

### Authentication
- `POST /api/auth/register/` - User registration
- `POST /api/auth/login/` - User login
- `POST /api/auth/logout/` - User logout
- `POST /api/auth/refresh/` - Refresh JWT token

### Email Verification
- `POST /api/auth/verify-email/` - Verify email with token
- `POST /api/auth/resend-verification/` - Resend verification email

### Password Management
- `POST /api/auth/change-password/` - Change password (authenticated)
- `POST /api/auth/reset-password/` - Request password reset
- `POST /api/auth/reset-password/confirm/` - Confirm password reset

### User Profile
- `GET /api/auth/profile/` - Get user profile
- `PUT /api/auth/profile/` - Update user profile
- `PATCH /api/auth/profile/` - Partial update user profile
- `GET /api/auth/user/` - Get user details

### Activity Tracking
- `GET /api/auth/activity/` - Get user activity history

## Serializers

### UserRegistrationSerializer
Handles user registration with validation:
```python
{
    "email": "user@example.com",
    "password": "securepassword123",
    "password_confirm": "securepassword123",
    "first_name": "John",
    "last_name": "Doe",
    "company_name": "Example Corp",
    "phone_number": "+1234567890"
}
```

### UserLoginSerializer
Handles user authentication:
```python
{
    "email": "user@example.com",
    "password": "securepassword123"
}
```

### UserProfileSerializer
Manages user profile data:
```python
{
    "first_name": "John",
    "last_name": "Doe",
    "company_name": "Example Corp",
    "phone_number": "+1234567890"
}
```

## Views

### UserRegistrationView
- Creates new user accounts
- Sends verification emails
- Logs registration activity

### UserLoginView
- Authenticates users
- Returns JWT tokens
- Logs login activity

### UserProfileView
- Manages user profile CRUD operations
- Supports partial updates
- Logs profile changes

### EmailVerificationView
- Verifies email addresses using tokens
- Updates user verification status
- Handles expired tokens

### PasswordResetView
- Initiates password reset process
- Sends reset emails
- Validates email addresses

## Authentication

The app uses JWT (JSON Web Tokens) for authentication:
- Access tokens for API requests
- Refresh tokens for token renewal
- Token expiration handling

## Security Features

- **Password Validation**: Strong password requirements
- **Email Verification**: Mandatory email verification
- **Rate Limiting**: Protection against brute force attacks
- **Activity Logging**: Comprehensive audit trail
- **Secure Tokens**: Cryptographically secure verification tokens

## Usage Examples

### Register a new user
```bash
curl -X POST http://localhost:8000/api/auth/register/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword123",
    "password_confirm": "securepassword123",
    "first_name": "John",
    "last_name": "Doe"
  }'
```

### Login
```bash
curl -X POST http://localhost:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword123"
  }'
```

### Get user profile
```bash
curl -X GET http://localhost:8000/api/auth/profile/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## Configuration

Add to Django settings:
```python
# JWT Settings
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=60),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'ROTATE_REFRESH_TOKENS': True,
}

# Email Settings
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'your-email@gmail.com'
EMAIL_HOST_PASSWORD = 'your-app-password'
```

## Dependencies

- Django REST Framework
- djangorestframework-simplejwt
- drf-spectacular (for API documentation)
- Django (core framework)

## Testing

Run tests for the authentication app:
```bash
python manage.py test authentication
```

## Admin Interface

The app includes custom admin configurations for:
- User management with enhanced fields
- User activity monitoring
- Bulk operations and filtering

Access the admin interface at `/admin/` after creating a superuser.