from django.urls import path

from . import views

app_name = "gst_services"

urlpatterns = [
    # GST Services
    path("services/", views.GSTServiceListView.as_view(), name="service-list"),
    # GSTIN Validation (free)
    path(
        "validate-gstin/", views.GSTINValidationView.as_view(), name="gstin-validation"
    ),
    # GST Verification (paid)
    path("verify/", views.GSTVerificationView.as_view(), name="gst-verification"),
    path(
        "verify/bulk/",
        views.BulkGSTVerificationView.as_view(),
        name="bulk-gst-verification",
    ),
    # GST Compliance
    path("compliance/", views.GSTComplianceCheckView.as_view(), name="gst-compliance"),
    # GST Search
    path("search/", views.GSTSearchView.as_view(), name="gst-search"),
    # History and tracking
    path(
        "history/",
        views.GSTVerificationHistoryView.as_view(),
        name="verification-history",
    ),
]
