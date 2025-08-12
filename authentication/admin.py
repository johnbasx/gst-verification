from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.html import format_html

from .models import User, UserActivity, UserProfile


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """Custom User admin"""

    list_display = (
        "email",
        "full_name",
        "company_name",
        "subscription_status",
        "is_verified",
        "is_active",
        "created_at",
    )
    list_filter = ("subscription_status", "is_verified", "is_active", "created_at")
    search_fields = ("email", "first_name", "last_name", "company_name")
    readonly_fields = ("created_at", "updated_at", "last_login_at")
    ordering = ("-created_at",)

    fieldsets = (
        (None, {"fields": ("email", "password")}),
        ("Personal info", {"fields": ("name", "company", "phone")}),
        (
            "Subscription",
            {
                "fields": (
                    "subscription_status",
                    "is_trial_active",
                    "trial_ends_at",
                    "stripe_customer_id",
                )
            },
        ),
        (
            "Permissions",
            {
                "fields": (
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "groups",
                    "user_permissions",
                )
            },
        ),
        ("Important dates", {"fields": ("last_login", "date_joined")}),
    )

    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": ("email", "name", "password1", "password2"),
            },
        ),
    )

    readonly_fields = ("date_joined", "last_login")

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("profile")


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    """User Profile admin"""

    list_display = ("user", "business_type", "country", "timezone", "created_at")
    list_filter = ("business_type", "country", "timezone")
    search_fields = ("user__email", "user__first_name", "user__last_name")
    readonly_fields = ("created_at", "updated_at")

    fieldsets = (
        ("Business Information", {"fields": ("user", "business_type")}),
        (
            "Location",
            {
                "fields": (
                    "address_line_1",
                    "address_line_2",
                    "city",
                    "state",
                    "postal_code",
                    "country",
                )
            },
        ),
        ("Preferences", {"fields": ("timezone", "language")}),
        ("Notifications", {"fields": ("marketing_emails", "product_updates")}),
        (
            "Metadata",
            {"fields": ("created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )


@admin.register(UserActivity)
class UserActivityAdmin(admin.ModelAdmin):
    """User Activity admin"""

    list_display = (
        "user",
        "activity_type",
        "description",
        "ip_address",
        "short_user_agent",
        "created_at",
    )
    list_filter = ("activity_type", "created_at")
    search_fields = ("user__email", "description", "ip_address")
    readonly_fields = ("created_at",)
    date_hierarchy = "created_at"

    def short_user_agent(self, obj):
        """Display shortened user agent"""
        if obj.user_agent:
            return (
                obj.user_agent[:50] + "..."
                if len(obj.user_agent) > 50
                else obj.user_agent
            )
        return "-"

    short_user_agent.short_description = "User Agent"

    fieldsets = (
        ("Activity Information", {"fields": ("user", "activity_type", "description")}),
        ("Session Details", {"fields": ("ip_address", "user_agent")}),
        ("Metadata", {"fields": ("metadata", "created_at"), "classes": ("collapse",)}),
    )

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("user")
