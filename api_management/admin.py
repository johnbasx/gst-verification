from django.contrib import admin
from django.urls import reverse
from django.utils.html import format_html
from django.utils.safestring import mark_safe

from .models import (
    APIKey,
    APIUsage,
    APIUsageAnalytics,
    CreditPackage,
    PaymentMethod,
    RateLimitTracker,
    ReferralProgram,
    UserCredits,
)


@admin.register(APIKey)
class APIKeyAdmin(admin.ModelAdmin):
    """API Key admin"""

    list_display = (
        "name",
        "user",
        "key_id",
        "is_active",
        "total_requests",
        "last_used_at",
        "created_at",
    )
    list_filter = ("is_active", "created_at", "last_used_at")
    search_fields = ("name", "user__email", "key_id")
    readonly_fields = (
        "key_id",
        "key_secret",
        "total_requests",
        "created_at",
        "updated_at",
    )

    fieldsets = (
        ("API Key Information", {"fields": ("user", "name", "key_id", "key_secret")}),
        ("Permissions", {"fields": ("is_active", "allowed_ips")}),
        (
            "Rate Limiting",
            {
                "fields": (
                    "rate_limit_per_minute",
                    "rate_limit_per_hour",
                    "rate_limit_per_day",
                )
            },
        ),
        ("Usage Statistics", {"fields": ("total_requests", "last_used_at")}),
        (
            "Metadata",
            {
                "fields": ("created_at", "updated_at", "expires_at"),
                "classes": ("collapse",),
            },
        ),
    )

    def key_preview(self, obj):
        """Display masked API key"""
        if obj.key:
            return f"{obj.key[:8]}...{obj.key[-4:]}"
        return "-"

    key_preview.short_description = "API Key"

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("user")


@admin.register(APIUsage)
class APIUsageAdmin(admin.ModelAdmin):
    """API Usage admin"""

    list_display = (
        "user",
        "api_key_name",
        "endpoint",
        "method",
        "credits_used",
        "status_code",
        "response_time_ms",
        "created_at",
    )
    list_filter = ("method", "status_code", "endpoint", "created_at")
    search_fields = ("user__email", "api_key__name", "endpoint", "ip_address")
    readonly_fields = ("created_at",)
    date_hierarchy = "created_at"

    fieldsets = (
        ("Request Information", {"fields": ("user", "api_key", "endpoint", "method")}),
        (
            "Response Details",
            {"fields": ("status_code", "response_time_ms", "credits_used")},
        ),
        ("Client Information", {"fields": ("ip_address", "user_agent")}),
        ("Data Size", {"fields": ("request_size_bytes", "response_size_bytes")}),
        ("Error Information", {"fields": ("error_message",), "classes": ("collapse",)}),
        ("Metadata", {"fields": ("created_at",), "classes": ("collapse",)}),
    )

    def api_key_name(self, obj):
        """Display API key name"""
        return obj.api_key.name if obj.api_key else "-"

    api_key_name.short_description = "API Key"

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("user", "api_key")


@admin.register(CreditPackage)
class CreditPackageAdmin(admin.ModelAdmin):
    """Credit Package admin"""

    list_display = (
        "name",
        "credits",
        "price",
        "price_per_credit",
        "is_active",
        "is_popular",
        "sort_order",
        "created_at",
    )
    list_filter = ("is_active", "is_popular", "created_at")
    search_fields = ("name", "description")
    readonly_fields = ("price_per_credit", "created_at", "updated_at")

    fieldsets = (
        ("Package Details", {"fields": ("name", "description", "credits", "price")}),
        ("Stripe Integration", {"fields": ("stripe_price_id", "stripe_product_id")}),
        ("Display Options", {"fields": ("is_active", "is_popular", "sort_order")}),
        (
            "Calculated Fields",
            {"fields": ("price_per_credit",), "classes": ("collapse",)},
        ),
        (
            "Metadata",
            {"fields": ("created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )

    def price_per_credit(self, obj):
        """Display price per credit"""
        if obj.credits > 0:
            return f"${obj.price / obj.credits:.4f}"
        return "-"

    price_per_credit.short_description = "Price per Credit"


@admin.register(UserCredits)
class UserCreditsAdmin(admin.ModelAdmin):
    """User Credits admin"""

    list_display = (
        "user",
        "available_credits",
        "total_purchased",
        "total_used",
        "trial_credits_granted",
        "trial_credits_used",
    )
    list_filter = ("created_at", "updated_at")
    search_fields = ("user__email",)
    readonly_fields = ("created_at", "updated_at")

    fieldsets = (
        ("User Information", {"fields": ("user",)}),
        (
            "Credit Balance",
            {"fields": ("available_credits", "total_purchased", "total_used")},
        ),
        ("Trial Credits", {"fields": ("trial_credits_granted", "trial_credits_used")}),
        (
            "Metadata",
            {"fields": ("created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )

    def total_credits(self, obj):
        """Display total available credits"""
        return obj.trial_credits + obj.purchased_credits

    total_credits.short_description = "Total Credits"

    def credits_remaining(self, obj):
        """Display remaining credits"""
        total = obj.trial_credits + obj.purchased_credits
        return max(0, total - obj.credits_used)

    credits_remaining.short_description = "Credits Remaining"

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("user")


@admin.register(RateLimitTracker)
class RateLimitTrackerAdmin(admin.ModelAdmin):
    """Rate Limit Tracker admin"""

    list_display = (
        "api_key",
        "window_type",
        "window_start",
        "request_count",
        "created_at",
    )
    list_filter = ("window_type", "created_at")
    search_fields = ("api_key__user__email", "api_key__name")
    readonly_fields = ("created_at", "updated_at")
    date_hierarchy = "created_at"

    fieldsets = (
        (
            "Rate Limit Information",
            {"fields": ("api_key", "window_type", "window_start")},
        ),
        ("Usage Statistics", {"fields": ("request_count",)}),
        (
            "Metadata",
            {"fields": ("created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )

    def api_key_name(self, obj):
        """Display API key name"""
        return obj.api_key.name if obj.api_key else "-"

    api_key_name.short_description = "API Key"

    def user(self, obj):
        """Display user email"""
        return obj.api_key.user.email if obj.api_key and obj.api_key.user else "-"

    user.short_description = "User"

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("api_key__user")


@admin.register(ReferralProgram)
class ReferralProgramAdmin(admin.ModelAdmin):
    """Referral Program admin"""

    list_display = (
        "referrer",
        "referred_user",
        "referral_code",
        "status",
        "referrer_bonus_credits",
        "referred_bonus_credits",
        "bonus_awarded",
        "created_at",
    )
    list_filter = ("status", "bonus_awarded", "created_at")
    search_fields = ("referrer__email", "referred_user__email", "referral_code")
    readonly_fields = ("referral_code", "created_at", "updated_at", "bonus_awarded_at")
    date_hierarchy = "created_at"

    fieldsets = (
        (
            "Referral Information",
            {"fields": ("referrer", "referred_user", "referral_code", "status")},
        ),
        (
            "Bonus Configuration",
            {"fields": ("referrer_bonus_credits", "referred_bonus_credits")},
        ),
        (
            "Bonus Status",
            {"fields": ("bonus_awarded", "bonus_awarded_at")},
        ),
        (
            "Metadata",
            {
                "fields": ("created_at", "updated_at", "expires_at"),
                "classes": ("collapse",),
            },
        ),
    )

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("referrer", "referred_user")


@admin.register(PaymentMethod)
class PaymentMethodAdmin(admin.ModelAdmin):
    """Payment Method admin"""

    list_display = (
        "country_name",
        "country_code",
        "provider",
        "currency",
        "currency_symbol",
        "is_active",
        "is_default",
    )
    list_filter = ("provider", "currency", "is_active", "is_default")
    search_fields = ("country_name", "country_code", "provider")
    readonly_fields = ("created_at", "updated_at")

    fieldsets = (
        (
            "Location Information",
            {"fields": ("country_code", "country_name")},
        ),
        (
            "Payment Configuration",
            {"fields": ("provider", "currency", "currency_symbol")},
        ),
        ("Status", {"fields": ("is_active", "is_default")}),
        (
            "Metadata",
            {"fields": ("created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )


@admin.register(APIUsageAnalytics)
class APIUsageAnalyticsAdmin(admin.ModelAdmin):
    """API Usage Analytics admin"""

    list_display = (
        "user",
        "date",
        "period_type",
        "total_requests",
        "successful_requests",
        "failed_requests",
        "success_rate",
        "total_credits_used",
    )
    list_filter = ("period_type", "date", "created_at")
    search_fields = ("user__email",)
    readonly_fields = ("created_at", "updated_at")
    date_hierarchy = "date"

    fieldsets = (
        ("Analytics Information", {"fields": ("user", "date", "period_type")}),
        (
            "Request Statistics",
            {
                "fields": (
                    "total_requests",
                    "successful_requests",
                    "failed_requests",
                )
            },
        ),
        (
            "Performance Metrics",
            {
                "fields": (
                    "total_credits_used",
                    "avg_response_time_ms",
                    "total_data_transferred_mb",
                )
            },
        ),
        ("Endpoint Usage", {"fields": ("endpoint_usage",)}),
        (
            "Metadata",
            {"fields": ("created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )

    def success_rate(self, obj):
        """Calculate and display success rate"""
        if obj.total_requests == 0:
            return "0.00%"
        rate = (obj.successful_requests / obj.total_requests) * 100
        return f"{rate:.2f}%"

    success_rate.short_description = "Success Rate"

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("user")
