from django.urls import path

from . import views

app_name = "authentication"

urlpatterns = [
    # Authentication endpoints
    path("register/", views.UserRegistrationView.as_view(), name="register"),
    path("login/", views.UserLoginView.as_view(), name="login"),
    path("logout/", views.UserLogoutView.as_view(), name="logout"),
    # Email verification
    path(
        "verify-email/<str:uid>/<str:token>/",
        views.EmailVerificationView.as_view(),
        name="verify-email",
    ),
    path(
        "resend-verification/",
        views.ResendVerificationView.as_view(),
        name="resend-verification",
    ),
    # Password management
    path(
        "password-change/", views.PasswordChangeView.as_view(), name="password-change"
    ),
    path("password-reset/", views.PasswordResetView.as_view(), name="password-reset"),
    path(
        "password-reset-confirm/<str:uid>/<str:token>/",
        views.PasswordResetConfirmView.as_view(),
        name="password-reset-confirm",
    ),
    # User profile and details
    path("profile/", views.UserProfileView.as_view(), name="profile"),
    path("user/", views.UserDetailView.as_view(), name="user-detail"),
    # User activity
    path("activity/", views.UserActivityListView.as_view(), name="activity"),
]
