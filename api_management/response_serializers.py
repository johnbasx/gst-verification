from rest_framework import serializers
from typing import Any, Dict, Optional


class StandardResponseSerializer(serializers.Serializer):
    """Standard API response format for all endpoints"""
    
    success = serializers.BooleanField(
        default=True,
        help_text="Indicates if the request was successful"
    )
    message = serializers.CharField(
        max_length=255,
        help_text="Human-readable message describing the result"
    )
    data = serializers.JSONField(
        allow_null=True,
        required=False,
        help_text="Response data payload"
    )
    timestamp = serializers.DateTimeField(
        read_only=True,
        help_text="ISO 8601 timestamp of the response"
    )
    request_id = serializers.CharField(
        max_length=36,
        read_only=True,
        help_text="Unique identifier for request tracing"
    )
    
    class Meta:
        ref_name = "StandardResponse"


class ErrorResponseSerializer(serializers.Serializer):
    """Standard error response format"""
    
    success = serializers.BooleanField(
        default=False,
        help_text="Always false for error responses"
    )
    error = serializers.CharField(
        max_length=100,
        help_text="Error code for programmatic handling"
    )
    message = serializers.CharField(
        max_length=255,
        help_text="Human-readable error message"
    )
    details = serializers.JSONField(
        allow_null=True,
        required=False,
        help_text="Additional error details and context"
    )
    timestamp = serializers.DateTimeField(
        read_only=True,
        help_text="ISO 8601 timestamp of the error"
    )
    request_id = serializers.CharField(
        max_length=36,
        read_only=True,
        help_text="Unique identifier for request tracing"
    )
    
    class Meta:
        ref_name = "ErrorResponse"


class PaginatedResponseSerializer(serializers.Serializer):
    """Paginated response format"""
    
    success = serializers.BooleanField(
        default=True,
        help_text="Indicates if the request was successful"
    )
    message = serializers.CharField(
        max_length=255,
        help_text="Human-readable message describing the result"
    )
    data = serializers.JSONField(
        help_text="Array of response data items"
    )
    pagination = serializers.JSONField(
        help_text="Pagination metadata"
    )
    timestamp = serializers.DateTimeField(
        read_only=True,
        help_text="ISO 8601 timestamp of the response"
    )
    request_id = serializers.CharField(
        max_length=36,
        read_only=True,
        help_text="Unique identifier for request tracing"
    )
    
    class Meta:
        ref_name = "PaginatedResponse"


class ValidationErrorResponseSerializer(serializers.Serializer):
    """Validation error response format"""
    
    success = serializers.BooleanField(
        default=False,
        help_text="Always false for validation errors"
    )
    error = serializers.CharField(
        default="VALIDATION_ERROR",
        help_text="Error code for validation errors"
    )
    message = serializers.CharField(
        default="Validation failed",
        help_text="Human-readable error message"
    )
    field_errors = serializers.JSONField(
        help_text="Field-specific validation errors"
    )
    timestamp = serializers.DateTimeField(
        read_only=True,
        help_text="ISO 8601 timestamp of the error"
    )
    request_id = serializers.CharField(
        max_length=36,
        read_only=True,
        help_text="Unique identifier for request tracing"
    )
    
    class Meta:
        ref_name = "ValidationErrorResponse"


class RateLimitErrorResponseSerializer(serializers.Serializer):
    """Rate limit error response format"""
    
    success = serializers.BooleanField(
        default=False,
        help_text="Always false for rate limit errors"
    )
    error = serializers.CharField(
        default="RATE_LIMIT_EXCEEDED",
        help_text="Error code for rate limiting"
    )
    message = serializers.CharField(
        help_text="Human-readable rate limit message"
    )
    retry_after = serializers.IntegerField(
        help_text="Seconds to wait before retrying"
    )
    limit_info = serializers.JSONField(
        help_text="Rate limit details"
    )
    timestamp = serializers.DateTimeField(
        read_only=True,
        help_text="ISO 8601 timestamp of the error"
    )
    request_id = serializers.CharField(
        max_length=36,
        read_only=True,
        help_text="Unique identifier for request tracing"
    )
    
    class Meta:
        ref_name = "RateLimitErrorResponse"