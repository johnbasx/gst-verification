from django.contrib import admin
from django.urls import reverse
from django.utils.html import format_html
from django.utils.safestring import mark_safe

from .models import (
    GSTBulkRequest,
    GSTCache,
    GSTRequest,
    GSTService,
    GSTVerificationResult,
    GSTWebhook,
    GSTWebhookDelivery,
)


@admin.register(GSTService)
class GSTServiceAdmin(admin.ModelAdmin):
    """GST Service admin"""

    list_display = (
        "name",
        "slug",
        "credit_cost",
        "is_active",
        "rate_limit_per_minute",
        "created_at",
    )
    list_filter = ("is_active", "is_premium", "created_at")
    search_fields = ("name", "description", "slug")
    readonly_fields = ("created_at", "updated_at")

    fieldsets = (
        (
            "Service Details",
            {"fields": ("name", "slug", "description", "endpoint_path")},
        ),
        (
            "Pricing & Limits",
            {
                "fields": (
                    "credit_cost",
                    "rate_limit_per_minute",
                    "rate_limit_per_hour",
                    "rate_limit_per_day",
                )
            },
        ),
        ("Configuration", {"fields": ("is_active", "is_premium")}),
        (
            "Documentation",
            {
                "fields": ("documentation_url", "example_request", "example_response"),
                "classes": ("collapse",),
            },
        ),
        (
            "Metadata",
            {"fields": ("created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )


@admin.register(GSTRequest)
class GSTRequestAdmin(admin.ModelAdmin):
    """GST Request admin"""

    list_display = (
        "user",
        "service",
        "endpoint",
        "status",
        "credits_consumed",
        "response_time_ms",
        "billing_status",
        "created_at",
    )
    list_filter = ("status", "service", "billing_status", "created_at")
    search_fields = ("user__email", "api_key__name", "endpoint")
    readonly_fields = ("request_id", "created_at")
    date_hierarchy = "created_at"

    fieldsets = (
        (
            "Request Information",
            {
                "fields": (
                    "request_id",
                    "user",
                    "api_key",
                    "service",
                    "method",
                    "endpoint",
                )
            },
        ),
        (
            "Request Data",
            {
                "fields": ("request_headers", "request_body", "request_params"),
                "classes": ("collapse",),
            },
        ),
        (
            "Response Details",
            {
                "fields": (
                    "response_status_code",
                    "response_headers",
                    "response_body",
                    "response_time_ms",
                    "status",
                    "error_message",
                    "error_code",
                )
            },
        ),
        ("Billing", {"fields": ("credits_consumed", "billing_status")}),
        (
            "Client Info",
            {"fields": ("ip_address", "user_agent"), "classes": ("collapse",)},
        ),
        ("Metadata", {"fields": ("created_at",), "classes": ("collapse",)}),
    )

    def get_queryset(self, request):
        return (
            super().get_queryset(request).select_related("user", "api_key", "service")
        )


@admin.register(GSTVerificationResult)
class GSTVerificationResultAdmin(admin.ModelAdmin):
    """GST Verification Result admin"""

    list_display = (
        "gstin",
        "legal_name",
        "status",
        "is_verified",
        "registration_date",
        "created_at",
    )
    list_filter = ("status", "is_verified", "created_at", "registration_date")
    search_fields = ("gstin", "legal_name", "trade_name")
    readonly_fields = ("created_at", "updated_at")
    date_hierarchy = "created_at"

    fieldsets = (
        ("Request Link", {"fields": ("request",)}),
        (
            "GST Information",
            {"fields": ("gstin", "legal_name", "trade_name", "status")},
        ),
        (
            "Business Details",
            {
                "fields": (
                    "business_type",
                    "constitution",
                    "registration_date",
                    "cancellation_date",
                )
            },
        ),
        (
            "Address Information",
            {
                "fields": ("address", "state_code", "state_name", "pincode"),
                "classes": ("collapse",),
            },
        ),
        (
            "Verification Details",
            {"fields": ("is_verified", "verification_confidence")},
        ),
        ("Additional Data", {"fields": ("additional_data",), "classes": ("collapse",)}),
        (
            "Metadata",
            {"fields": ("created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )


@admin.register(GSTCache)
class GSTCacheAdmin(admin.ModelAdmin):
    """GST Cache admin"""

    list_display = (
        "gstin",
        "cache_hit_count",
        "last_verified_at",
        "expires_at",
        "is_valid",
        "created_at",
    )
    list_filter = ("is_valid", "created_at", "expires_at")
    search_fields = ("gstin",)
    readonly_fields = ("cache_hit_count", "created_at", "updated_at")
    date_hierarchy = "created_at"

    fieldsets = (
        ("Cache Information", {"fields": ("gstin", "is_valid")}),
        ("Cache Data", {"fields": ("cached_data",), "classes": ("collapse",)}),
        (
            "Statistics",
            {"fields": ("cache_hit_count", "last_verified_at", "expires_at")},
        ),
        (
            "Metadata",
            {"fields": ("created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )


@admin.register(GSTBulkRequest)
class GSTBulkRequestAdmin(admin.ModelAdmin):
    """GST Bulk Request admin"""

    list_display = (
        "user",
        "status",
        "total_records",
        "processed_records",
        "progress_percentage",
        "created_at",
    )
    list_filter = ("status", "created_at")
    search_fields = ("user__email", "api_key__name", "input_file_name")
    readonly_fields = ("batch_id", "progress_percentage", "created_at", "updated_at")
    date_hierarchy = "created_at"

    fieldsets = (
        (
            "Bulk Request Information",
            {"fields": ("batch_id", "user", "api_key", "status")},
        ),
        (
            "Progress Tracking",
            {
                "fields": (
                    "total_records",
                    "processed_records",
                    "successful_records",
                    "failed_records",
                    "progress_percentage",
                )
            },
        ),
        ("File Information", {"fields": ("input_file_name", "output_file_url")}),
        ("Billing", {"fields": ("total_credits_consumed",)}),
        (
            "Timing",
            {"fields": ("estimated_completion_time", "started_at", "completed_at")},
        ),
        (
            "Metadata",
            {"fields": ("created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )

    def progress_percentage(self, obj):
        """Display progress as percentage"""
        if obj.total_records > 0:
            percentage = (obj.processed_records / obj.total_records) * 100
            return f"{percentage:.1f}%"
        return "0%"

    progress_percentage.short_description = "Progress"

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("user", "api_key")


@admin.register(GSTWebhook)
class GSTWebhookAdmin(admin.ModelAdmin):
    """GST Webhook admin"""

    list_display = (
        "user",
        "name",
        "url",
        "is_active",
        "total_deliveries",
        "last_delivery_at",
        "created_at",
    )
    list_filter = ("is_active", "created_at")
    search_fields = ("user__email", "name", "url")
    readonly_fields = (
        "total_deliveries",
        "successful_deliveries",
        "failed_deliveries",
        "last_delivery_at",
        "created_at",
        "updated_at",
    )

    fieldsets = (
        ("Webhook Configuration", {"fields": ("user", "name", "url", "is_active")}),
        ("Events", {"fields": ("events",)}),
        ("Security", {"fields": ("secret_key",)}),
        ("Retry Configuration", {"fields": ("max_retries", "retry_delay_seconds")}),
        (
            "Statistics",
            {
                "fields": (
                    "total_deliveries",
                    "successful_deliveries",
                    "failed_deliveries",
                    "last_delivery_at",
                )
            },
        ),
        (
            "Metadata",
            {"fields": ("created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("user")


@admin.register(GSTWebhookDelivery)
class GSTWebhookDeliveryAdmin(admin.ModelAdmin):
    """GST Webhook Delivery admin"""

    list_display = (
        "webhook",
        "event_type",
        "status",
        "attempt_number",
        "http_status_code",
        "delivered_at",
        "created_at",
    )
    list_filter = ("status", "event_type", "created_at")
    search_fields = ("webhook__user__email", "webhook__url")
    readonly_fields = ("created_at",)
    date_hierarchy = "created_at"

    fieldsets = (
        (
            "Delivery Information",
            {"fields": ("webhook", "request", "event_type", "status")},
        ),
        ("Attempt Details", {"fields": ("attempt_number", "max_attempts")}),
        (
            "Response Details",
            {
                "fields": (
                    "http_status_code",
                    "response_body",
                    "response_time_ms",
                    "error_message",
                )
            },
        ),
        ("Timing", {"fields": ("scheduled_at", "delivered_at")}),
        ("Payload", {"fields": ("payload",), "classes": ("collapse",)}),
        ("Metadata", {"fields": ("created_at",), "classes": ("collapse",)}),
    )

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("webhook__user")
