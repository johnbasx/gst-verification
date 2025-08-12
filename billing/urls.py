from django.urls import path

from . import views
from . import webhooks

app_name = "billing"

urlpatterns = [
    # Subscription Plans
    path("plans/", views.SubscriptionPlanListView.as_view(), name="plan-list"),
    # User Subscription Management
    path(
        "subscription/", views.UserSubscriptionView.as_view(), name="user-subscription"
    ),
    path(
        "subscription/cancel/",
        views.SubscriptionCancelView.as_view(),
        name="subscription-cancel",
    ),
    # Invoices
    path("invoices/", views.InvoiceListView.as_view(), name="invoice-list"),
    path(
        "invoices/<int:pk>/", views.InvoiceDetailView.as_view(), name="invoice-detail"
    ),
    # Payments
    path("payments/create/", views.PaymentCreateView.as_view(), name="payment-create"),
    # Discounts (not implemented)
    # path('discounts/validate/', views.DiscountValidationView.as_view(), name='discount-validate'),
    # Statistics
    path("stats/", views.UserBillingStatsView.as_view(), name="user-billing-stats"),
    # Webhooks
    path("webhooks/stripe/", webhooks.stripe_webhook, name="stripe-webhook"),
    path("webhooks/razorpay/", webhooks.razorpay_webhook, name="razorpay-webhook"),
]
