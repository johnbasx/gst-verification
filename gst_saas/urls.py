"""
URL configuration for gst_saas project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response

from django.contrib import admin
from django.urls import include, path


@api_view(["GET"])
def api_root(request):
    """API Root endpoint with available endpoints"""
    return Response(
        {
            "message": "Welcome to GST Verification API",
            "version": "1.0.0",
            "documentation": {
                "swagger": request.build_absolute_uri("/api/docs/"),
                "redoc": request.build_absolute_uri("/api/redoc/"),
                "schema": request.build_absolute_uri("/api/schema/"),
            },
            "endpoints": {
                "authentication": request.build_absolute_uri("/api/auth/"),
                "api_management": request.build_absolute_uri("/api/management/"),
                "gst_services": request.build_absolute_uri("/api/gst/"),
                "billing": request.build_absolute_uri("/api/billing/"),
                "admin": request.build_absolute_uri("/admin/"),
            },
        }
    )


urlpatterns = [
    # Admin
    path("admin/", admin.site.urls),
    # API Root
    path("api/", api_root, name="api-root"),
    # API Documentation
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    path(
        "api/docs/",
        SpectacularSwaggerView.as_view(url_name="schema"),
        name="swagger-ui",
    ),
    path("api/redoc/", SpectacularRedocView.as_view(url_name="schema"), name="redoc"),
    # App URLs
    path("api/auth/", include("authentication.urls")),
    path("api/management/", include("api_management.urls")),
    path("api/gst/", include("gst_services.urls")),
    path("api/billing/", include("billing.urls")),
]
