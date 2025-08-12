import os
from datetime import timedelta


class BaseConfig:
    """Base configuration class with common settings."""

    # Flask settings
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")
    JSON_SORT_KEYS = False
    JSONIFY_PRETTYPRINT_REGULAR = True

    # GST Portal URLs
    GST_BASE_URL = "https://services.gst.gov.in/services"
    CAPTCHA_URL = f"{GST_BASE_URL}/captcha"
    SEARCH_URL = f"{GST_BASE_URL}/searchtp"
    GST_DETAILS_URL = f"{GST_BASE_URL}/api/search/taxpayerDetails"

    # Session settings
    SESSION_TIMEOUT = int(os.environ.get("SESSION_TIMEOUT", 300))  # 5 minutes
    MAX_RETRY_ATTEMPTS = int(os.environ.get("MAX_RETRY_ATTEMPTS", 3))
    REQUEST_TIMEOUT = int(os.environ.get("REQUEST_TIMEOUT", 30))

    # Rate limiting settings
    RATE_LIMIT_CAPTCHA = int(
        os.environ.get("RATE_LIMIT_CAPTCHA", 20)
    )  # requests per minute
    RATE_LIMIT_GST_DETAILS = int(
        os.environ.get("RATE_LIMIT_GST_DETAILS", 10)
    )  # requests per minute
    RATE_LIMIT_WINDOW = int(os.environ.get("RATE_LIMIT_WINDOW", 60))  # seconds

    # Logging settings
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
    LOG_FILE = os.environ.get("LOG_FILE", "gst_api.log")
    LOG_MAX_BYTES = int(os.environ.get("LOG_MAX_BYTES", 10485760))  # 10MB
    LOG_BACKUP_COUNT = int(os.environ.get("LOG_BACKUP_COUNT", 5))

    # CORS settings
    CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "*")

    # Security headers
    SECURITY_HEADERS = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
    }


class DevelopmentConfig(BaseConfig):
    """Development configuration."""

    DEBUG = True
    TESTING = False

    # More lenient rate limits for development
    RATE_LIMIT_CAPTCHA = 100
    RATE_LIMIT_GST_DETAILS = 50

    # Shorter session timeout for testing
    SESSION_TIMEOUT = 600  # 10 minutes

    # Development logging
    LOG_LEVEL = "DEBUG"


class TestingConfig(BaseConfig):
    """Testing configuration."""

    DEBUG = True
    TESTING = True

    # Disable rate limiting for tests
    RATE_LIMIT_CAPTCHA = 1000
    RATE_LIMIT_GST_DETAILS = 1000

    # Short session timeout for testing
    SESSION_TIMEOUT = 60  # 1 minute

    # Test logging
    LOG_LEVEL = "DEBUG"
    LOG_FILE = "test_gst_api.log"


class ProductionConfig(BaseConfig):
    """Production configuration."""

    DEBUG = False
    TESTING = False

    # Strict rate limits for production
    RATE_LIMIT_CAPTCHA = 10  # More restrictive
    RATE_LIMIT_GST_DETAILS = 5  # More restrictive

    # Production logging
    LOG_LEVEL = "WARNING"

    # Security settings
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    # Require HTTPS in production
    PREFERRED_URL_SCHEME = "https"


class StagingConfig(BaseConfig):
    """Staging configuration."""

    DEBUG = False
    TESTING = False

    # Moderate rate limits for staging
    RATE_LIMIT_CAPTCHA = 15
    RATE_LIMIT_GST_DETAILS = 8

    # Staging logging
    LOG_LEVEL = "INFO"


# Configuration mapping
config = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "staging": StagingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}


def get_config(config_name=None):
    """Get configuration based on environment variable or parameter."""
    if config_name is None:
        config_name = os.environ.get("FLASK_ENV", "default")

    return config.get(config_name, config["default"])


# Environment-specific settings
class EnvironmentConfig:
    """Environment-specific configuration helper."""

    @staticmethod
    def is_development():
        return os.environ.get("FLASK_ENV") == "development"

    @staticmethod
    def is_production():
        return os.environ.get("FLASK_ENV") == "production"

    @staticmethod
    def is_testing():
        return os.environ.get("FLASK_ENV") == "testing"

    @staticmethod
    def get_database_url():
        """Get database URL for session storage (if using database)."""
        return os.environ.get("DATABASE_URL")

    @staticmethod
    def get_redis_url():
        """Get Redis URL for session storage (if using Redis)."""
        return os.environ.get("REDIS_URL")

    @staticmethod
    def get_sentry_dsn():
        """Get Sentry DSN for error tracking."""
        return os.environ.get("SENTRY_DSN")

    @staticmethod
    def get_api_key():
        """Get API key for authentication (if required)."""
        return os.environ.get("API_KEY")


# Validation functions
def validate_config(config_obj):
    """Validate configuration settings."""
    errors = []

    # Check required settings
    secret_key = (
        config_obj.get("SECRET_KEY")
        if hasattr(config_obj, "get")
        else config_obj.SECRET_KEY
    )
    if not secret_key or secret_key == "dev-secret-key-change-in-production":
        flask_env = (
            getattr(config_obj, "FLASK_ENV", "development")
            if hasattr(config_obj, "FLASK_ENV")
            else "development"
        )
        if (
            flask_env == "production"
            or config_obj.__class__.__name__ == "ProductionConfig"
        ):
            errors.append("SECRET_KEY must be set for production")

    # Check timeout values
    session_timeout = getattr(config_obj, "SESSION_TIMEOUT", 300)
    if session_timeout <= 0:
        errors.append("SESSION_TIMEOUT must be positive")

    request_timeout = getattr(config_obj, "REQUEST_TIMEOUT", 30)
    if request_timeout <= 0:
        errors.append("REQUEST_TIMEOUT must be positive")

    # Check rate limit values
    rate_limit_captcha = getattr(config_obj, "RATE_LIMIT_CAPTCHA", 20)
    if rate_limit_captcha <= 0:
        errors.append("RATE_LIMIT_CAPTCHA must be positive")

    rate_limit_gst = getattr(config_obj, "RATE_LIMIT_GST_DETAILS", 10)
    if rate_limit_gst <= 0:
        errors.append("RATE_LIMIT_GST_DETAILS must be positive")

    if errors:
        raise ValueError(f"Configuration validation failed: {', '.join(errors)}")

    return errors


# Default configuration instance
default_config = get_config()
