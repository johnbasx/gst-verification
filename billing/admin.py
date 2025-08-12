from django.contrib import admin
from django.urls import reverse
from django.utils.html import format_html
from django.utils.safestring import mark_safe

from .models import (
    Invoice,
    InvoiceItem,
    Payment,
    Subscription,
    SubscriptionPlan,
    UsageAlert,
)


@admin.register(SubscriptionPlan)
class SubscriptionPlanAdmin(admin.ModelAdmin):
    """Subscription Plan admin"""

    list_display = (
        "name",
        "monthly_price",
        "yearly_price",
        "monthly_credits",
        "is_active",
        "is_popular",
        "sort_order",
    )
    list_filter = ("is_active", "is_popular", "support_level")
    search_fields = ("name", "description")
    readonly_fields = ("created_at", "updated_at")

    fieldsets = (
        ("Basic Information", {"fields": ("name", "description")}),
        ("Pricing", {"fields": ("monthly_price", "yearly_price")}),
        ("Credits", {"fields": ("monthly_credits", "yearly_credits")}),
        (
            "Features",
            {
                "fields": (
                    "max_api_keys",
                    "rate_limit_per_minute",
                    "rate_limit_per_hour",
                    "rate_limit_per_day",
                )
            },
        ),
        ("Support", {"fields": ("support_level",)}),
        (
            "Stripe Integration",
            {
                "fields": (
                    "stripe_monthly_price_id",
                    "stripe_yearly_price_id",
                    "stripe_product_id",
                ),
                "classes": ("collapse",),
            },
        ),
        ("Display", {"fields": ("is_active", "is_popular", "sort_order")}),
        (
            "Metadata",
            {"fields": ("created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )


@admin.register(Subscription)
class SubscriptionAdmin(admin.ModelAdmin):
    """Subscription admin"""

    list_display = (
        "user",
        "plan",
        "status",
        "current_period_start",
        "current_period_end",
        "is_active",
        "created_at",
    )
    list_filter = ("status", "plan", "created_at", "current_period_end")
    search_fields = ("user__email", "user__name", "stripe_subscription_id")
    readonly_fields = ("created_at", "updated_at")
    date_hierarchy = "created_at"

    fieldsets = (
        ("Subscription Information", {"fields": ("user", "plan", "status")}),
        (
            "Billing Period",
            {
                "fields": (
                    "current_period_start",
                    "current_period_end",
                    "trial_end",
                    "canceled_at",
                )
            },
        ),
        (
            "Stripe Integration",
            {"fields": ("stripe_subscription_id", "stripe_customer_id")},
        ),
        (
            "Metadata",
            {
                "fields": ("metadata", "created_at", "updated_at"),
                "classes": ("collapse",),
            },
        ),
    )

    def is_active(self, obj):
        """Display if subscription is active"""
        return obj.status in ["active", "trialing"]

    is_active.boolean = True
    is_active.short_description = "Active"

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("user", "plan")


@admin.register(Invoice)
class InvoiceAdmin(admin.ModelAdmin):
    """Invoice admin"""

    list_display = (
        "invoice_number",
        "user",
        "status",
        "total_amount",
        "due_date",
        "paid_at",
        "created_at",
    )
    list_filter = ("status", "created_at", "due_date", "paid_at")
    search_fields = ("invoice_number", "user__email", "user__name", "stripe_invoice_id")
    readonly_fields = ("invoice_number", "created_at", "updated_at")
    date_hierarchy = "created_at"

    fieldsets = (
        (
            "Invoice Information",
            {"fields": ("invoice_number", "user", "subscription", "status")},
        ),
        (
            "Amounts",
            {
                "fields": (
                    "subtotal",
                    "tax_amount",
                    "discount_amount",
                    "total_amount",
                    "currency",
                )
            },
        ),
        ("Dates", {"fields": ("due_date", "paid_at")}),
        (
            "Stripe Integration",
            {"fields": ("stripe_invoice_id", "stripe_payment_intent_id")},
        ),
        (
            "Metadata",
            {
                "fields": ("metadata", "created_at", "updated_at"),
                "classes": ("collapse",),
            },
        ),
    )

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("user", "subscription")


@admin.register(InvoiceItem)
class InvoiceItemAdmin(admin.ModelAdmin):
    """Invoice Item admin"""

    list_display = (
        "invoice",
        "description",
        "quantity",
        "unit_price",
        "total_price",
        "created_at",
    )
    list_filter = ("created_at",)
    search_fields = ("invoice__invoice_number", "description")
    readonly_fields = ("total_price", "created_at")

    fieldsets = (
        (
            "Item Details",
            {"fields": ("invoice", "description", "quantity", "unit_price")},
        ),
        ("Calculated Fields", {"fields": ("total_price",)}),
        ("Metadata", {"fields": ("metadata", "created_at"), "classes": ("collapse",)}),
    )

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("invoice")


@admin.register(Payment)
class PaymentAdmin(admin.ModelAdmin):
    """Payment admin"""

    list_display = (
        "user",
        "amount",
        "currency",
        "status",
        "payment_method",
        "processed_at",
        "created_at",
    )
    list_filter = ("status", "payment_method", "created_at", "processed_at")
    search_fields = (
        "user__email",
        "user__name",
        "stripe_payment_intent_id",
        "transaction_id",
    )
    readonly_fields = ("created_at", "updated_at")
    date_hierarchy = "created_at"

    fieldsets = (
        (
            "Payment Information",
            {
                "fields": (
                    "user",
                    "invoice",
                    "subscription",
                    "amount",
                    "currency",
                    "status",
                )
            },
        ),
        (
            "Payment Details",
            {
                "fields": (
                    "payment_method",
                    "transaction_id",
                    "processed_at",
                    "failure_reason",
                )
            },
        ),
        (
            "Stripe Integration",
            {"fields": ("stripe_payment_intent_id", "stripe_charge_id")},
        ),
        (
            "Metadata",
            {
                "fields": ("metadata", "created_at", "updated_at"),
                "classes": ("collapse",),
            },
        ),
    )

    def get_queryset(self, request):
        return (
            super()
            .get_queryset(request)
            .select_related("user", "invoice", "subscription")
        )


@admin.register(UsageAlert)
class UsageAlertAdmin(admin.ModelAdmin):
    """Usage Alert admin"""

    list_display = (
        "user",
        "alert_type",
        "threshold_percentage",
        "is_active",
        "last_triggered_at",
    )
    list_filter = ("alert_type", "is_active", "last_triggered_at")
    search_fields = ("user__email",)
    readonly_fields = ("last_triggered_at", "created_at", "updated_at")

    fieldsets = (
        (
            "Alert Configuration",
            {"fields": ("user", "alert_type", "threshold_percentage", "is_active")},
        ),
        (
            "Notification Settings",
            {"fields": ("email_notification", "webhook_notification", "webhook_url")},
        ),
        ("Status", {"fields": ("last_triggered_at",)}),
        (
            "Metadata",
            {"fields": ("created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("user")
