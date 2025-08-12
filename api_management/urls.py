from django.urls import path

from . import views

app_name = "api_management"

urlpatterns = [
    # API Key management
    path("api-keys/", views.APIKeyListCreateView.as_view(), name="api-key-list-create"),
    path("api-keys/<int:pk>/", views.APIKeyDetailView.as_view(), name="api-key-detail"),
    path(
        "api-keys/<int:pk>/regenerate/",
        views.APIKeyRegenerateView.as_view(),
        name="api-key-regenerate",
    ),
    path(
        "api-keys/<int:pk>/stats/",
        views.APIKeyStatsView.as_view(),
        name="api-key-stats",
    ),
    # API Usage
    path("usage/", views.APIUsageListView.as_view(), name="api-usage-list"),
    # Credits management
    path("credits/", views.UserCreditsView.as_view(), name="user-credits"),
    path(
        "credit-packages/",
        views.CreditPackageListView.as_view(),
        name="credit-packages",
    ),
    path(
        "purchase-credits/", views.CreditPurchaseView.as_view(), name="purchase-credits"
    ),
    # Statistics and monitoring
    path("stats/", views.UserStatsView.as_view(), name="user-stats"),
    path("rate-limits/", views.RateLimitStatusView.as_view(), name="rate-limit-status"),
    # Referral management
    path("referrals/", views.ReferralProgramListView.as_view(), name="referral-list"),
    path("referrals/use/", views.ReferralCreateView.as_view(), name="referral-use"),
    path("referrals/stats/", views.ReferralStatsView.as_view(), name="referral-stats"),
    # Location-based payments
    path(
        "payment-methods/location/",
        views.LocationBasedPaymentView.as_view(),
        name="payment-methods-location",
    ),
    # Usage analytics
    path(
        "analytics/usage/",
        views.APIUsageAnalyticsView.as_view(),
        name="usage-analytics",
    ),
    path("track-usage/", views.track_api_usage, name="track-usage"),
]
