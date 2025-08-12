from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import generics, permissions, status
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from django.conf import settings
from django.contrib.auth import login, logout
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.shortcuts import get_object_or_404
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode

from .models import User, UserActivity, UserProfile
from .serializers import (
    EmailVerificationSerializer,
    PasswordChangeSerializer,
    PasswordResetConfirmSerializer,
    PasswordResetSerializer,
    UserActivitySerializer,
    UserLoginSerializer,
    UserProfileSerializer,
    UserRegistrationSerializer,
    UserSerializer,
)


class UserRegistrationView(generics.CreateAPIView):
    """User registration endpoint"""

    queryset = User.objects.all()
    serializer_class = UserRegistrationSerializer
    permission_classes = [AllowAny]

    @extend_schema(
        summary="Register a new user",
        description="Create a new user account with email verification",
        responses={
            201: {
                "type": "object",
                "properties": {
                    "message": {"type": "string"},
                    "user_id": {"type": "integer"},
                    "email": {"type": "string"},
                },
            }
        },
        tags=["Authentication"],
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()

            # Create user profile
            UserProfile.objects.create(user=user)

            # Log activity
            UserActivity.objects.create(
                user=user,
                activity_type="api_call",
                description="User registered successfully",
                ip_address=self.get_client_ip(request),
                user_agent=request.META.get("HTTP_USER_AGENT", ""),
            )

            # Send verification email
            self.send_verification_email(user, request)

            return Response(
                {
                    "message": "Registration successful. Please check your email for verification.",
                    "user_id": user.id,
                    "email": user.email,
                },
                status=status.HTTP_201_CREATED,
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0]
        else:
            ip = request.META.get("REMOTE_ADDR")
        return ip

    def send_verification_email(self, user, request):
        """Send email verification"""
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))

        verification_url = (
            f"{request.build_absolute_uri('/api/v1/auth/verify-email/')}{uid}/{token}/"
        )

        subject = "Verify your email address"
        message = f"""
        Hi {user.first_name},
        
        Thank you for registering with GST Verification SaaS!
        
        Please click the link below to verify your email address:
        {verification_url}
        
        If you didn't create this account, please ignore this email.
        
        Best regards,
        GST Verification Team
        """

        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            fail_silently=False,
        )


class UserLoginView(APIView):
    """User login endpoint"""

    permission_classes = [AllowAny]

    @extend_schema(
        summary="User login",
        description="Authenticate user and return access token",
        request=UserLoginSerializer,
        responses={
            200: {
                "type": "object",
                "properties": {
                    "token": {"type": "string"},
                    "user": {"type": "object"},
                    "message": {"type": "string"},
                },
            }
        },
        tags=["Authentication"],
    )
    def post(self, request):
        serializer = UserLoginSerializer(
            data=request.data, context={"request": request}
        )

        if serializer.is_valid():
            user = serializer.validated_data["user"]

            # Create or get token
            token, created = Token.objects.get_or_create(user=user)

            # Log activity
            UserActivity.objects.create(
                user=user,
                activity_type="login",
                description="User logged in successfully",
                ip_address=self.get_client_ip(request),
                user_agent=request.META.get("HTTP_USER_AGENT", ""),
            )

            # Serialize user data
            user_serializer = UserSerializer(user)

            return Response(
                {
                    "token": token.key,
                    "user": user_serializer.data,
                    "message": "Login successful",
                },
                status=status.HTTP_200_OK,
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0]
        else:
            ip = request.META.get("REMOTE_ADDR")
        return ip


class UserLogoutView(APIView):
    """User logout endpoint"""

    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="User logout",
        description="Logout user and invalidate token",
        responses={
            200: {"type": "object", "properties": {"message": {"type": "string"}}}
        },
        tags=["Authentication"],
    )
    def post(self, request):
        try:
            # Delete the user's token
            request.user.auth_token.delete()

            # Log activity
            UserActivity.objects.create(
                user=request.user,
                action="LOGOUT",
                description="User logged out successfully",
                ip_address=self.get_client_ip(request),
                user_agent=request.META.get("HTTP_USER_AGENT", ""),
            )

            return Response({"message": "Logout successful"}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"error": "Logout failed"}, status=status.HTTP_400_BAD_REQUEST
            )

    def get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0]
        else:
            ip = request.META.get("REMOTE_ADDR")
        return ip


class UserProfileView(generics.RetrieveUpdateAPIView):
    """User profile endpoint"""

    serializer_class = UserProfileSerializer
    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="Get user profile",
        description="Retrieve current user's profile information",
        tags=["Authentication"],
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    @extend_schema(
        summary="Update user profile",
        description="Update current user's profile information",
        tags=["Authentication"],
    )
    def put(self, request, *args, **kwargs):
        return super().put(request, *args, **kwargs)

    @extend_schema(
        summary="Partially update user profile",
        description="Partially update current user's profile information",
        tags=["User Profile"],
    )
    def patch(self, request, *args, **kwargs):
        return super().patch(request, *args, **kwargs)

    def get_object(self):
        profile, created = UserProfile.objects.get_or_create(user=self.request.user)
        return profile


class UserDetailView(generics.RetrieveUpdateAPIView):
    """User detail endpoint"""

    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="Get user details",
        description="Retrieve current user's account information",
        tags=["Authentication"],
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    @extend_schema(
        summary="Update user details",
        description="Update current user's account information",
        tags=["Authentication"],
    )
    def put(self, request, *args, **kwargs):
        return super().put(request, *args, **kwargs)

    @extend_schema(
        summary="Partially update user details",
        description="Partially update current user's account information",
        tags=["User Management"],
    )
    def patch(self, request, *args, **kwargs):
        return super().patch(request, *args, **kwargs)

    def get_object(self):
        return self.request.user


class PasswordChangeView(APIView):
    """Password change endpoint"""

    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="Change password",
        description="Change current user's password",
        request=PasswordChangeSerializer,
        responses={
            200: {"type": "object", "properties": {"message": {"type": "string"}}}
        },
        tags=["Authentication"],
    )
    def post(self, request):
        serializer = PasswordChangeSerializer(
            data=request.data, context={"request": request}
        )

        if serializer.is_valid():
            serializer.save()

            # Log activity
            UserActivity.objects.create(
                user=request.user,
                action="PASSWORD_CHANGE",
                description="Password changed successfully",
                ip_address=self.get_client_ip(request),
                user_agent=request.META.get("HTTP_USER_AGENT", ""),
            )

            return Response(
                {"message": "Password changed successfully"}, status=status.HTTP_200_OK
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0]
        else:
            ip = request.META.get("REMOTE_ADDR")
        return ip


class PasswordResetView(APIView):
    """Password reset request endpoint"""

    permission_classes = [AllowAny]

    @extend_schema(
        summary="Request password reset",
        description="Send password reset email to user",
        request=PasswordResetSerializer,
        responses={
            200: {"type": "object", "properties": {"message": {"type": "string"}}}
        },
        tags=["Authentication"],
    )
    def post(self, request):
        serializer = PasswordResetSerializer(data=request.data)

        if serializer.is_valid():
            email = serializer.validated_data["email"]
            user = User.objects.get(email=email)

            # Generate reset token
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))

            # Send reset email
            reset_url = f"{request.build_absolute_uri('/api/v1/auth/password-reset-confirm/')}{uid}/{token}/"

            subject = "Password Reset Request"
            message = f"""
            Hi {user.first_name},
            
            You requested a password reset for your GST Verification SaaS account.
            
            Please click the link below to reset your password:
            {reset_url}
            
            If you didn't request this, please ignore this email.
            
            Best regards,
            GST Verification Team
            """

            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )

            # Log activity
            UserActivity.objects.create(
                user=user,
                activity_type="profile_update",
                description="Password reset requested",
                ip_address=self.get_client_ip(request),
                user_agent=request.META.get("HTTP_USER_AGENT", ""),
            )

            return Response(
                {"message": "Password reset email sent successfully"},
                status=status.HTTP_200_OK,
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0]
        else:
            ip = request.META.get("REMOTE_ADDR")
        return ip


class PasswordResetConfirmView(APIView):
    """Password reset confirmation endpoint"""

    permission_classes = [AllowAny]

    @extend_schema(
        summary="Confirm password reset",
        description="Reset password using token from email",
        request=PasswordResetConfirmSerializer,
        parameters=[
            OpenApiParameter(
                name="uid",
                type=OpenApiTypes.STR,
                location=OpenApiParameter.PATH,
                description="User ID (base64 encoded)",
            ),
            OpenApiParameter(
                name="token",
                type=OpenApiTypes.STR,
                location=OpenApiParameter.PATH,
                description="Password reset token",
            ),
        ],
        responses={
            200: {"type": "object", "properties": {"message": {"type": "string"}}}
        },
        tags=["Authentication"],
    )
    def post(self, request, uid, token):
        try:
            # Decode user ID
            user_id = force_str(urlsafe_base64_decode(uid))
            user = User.objects.get(pk=user_id)

            # Verify token
            if not default_token_generator.check_token(user, token):
                return Response(
                    {"error": "Invalid or expired token"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Validate new password
            serializer = PasswordResetConfirmSerializer(data=request.data)

            if serializer.is_valid():
                # Set new password
                user.set_password(serializer.validated_data["new_password"])
                user.save()

                # Log activity
                UserActivity.objects.create(
                    user=user,
                    action="PASSWORD_RESET_CONFIRM",
                    description="Password reset completed",
                    ip_address=self.get_client_ip(request),
                    user_agent=request.META.get("HTTP_USER_AGENT", ""),
                )

                return Response(
                    {"message": "Password reset successful"}, status=status.HTTP_200_OK
                )

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response(
                {"error": "Invalid user ID"}, status=status.HTTP_400_BAD_REQUEST
            )

    def get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0]
        else:
            ip = request.META.get("REMOTE_ADDR")
        return ip


class EmailVerificationView(APIView):
    """Email verification endpoint"""

    permission_classes = [AllowAny]

    @extend_schema(
        summary="Verify email address",
        description="Verify user's email address using token from email",
        parameters=[
            OpenApiParameter(
                name="uid",
                type=OpenApiTypes.STR,
                location=OpenApiParameter.PATH,
                description="User ID (base64 encoded)",
            ),
            OpenApiParameter(
                name="token",
                type=OpenApiTypes.STR,
                location=OpenApiParameter.PATH,
                description="Email verification token",
            ),
        ],
        responses={
            200: {"type": "object", "properties": {"message": {"type": "string"}}}
        },
        tags=["Authentication"],
    )
    def get(self, request, uid, token):
        try:
            # Decode user ID
            user_id = force_str(urlsafe_base64_decode(uid))
            user = User.objects.get(pk=user_id)

            # Verify token
            if not default_token_generator.check_token(user, token):
                return Response(
                    {"error": "Invalid or expired verification link"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Verify email
            if not user.is_verified:
                user.is_verified = True
                user.save()

                # Log activity
                UserActivity.objects.create(
                    user=user,
                    action="EMAIL_VERIFICATION",
                    description="Email verified successfully",
                    ip_address=self.get_client_ip(request),
                    user_agent=request.META.get("HTTP_USER_AGENT", ""),
                )

                return Response(
                    {"message": "Email verified successfully"},
                    status=status.HTTP_200_OK,
                )
            else:
                return Response(
                    {"message": "Email is already verified"}, status=status.HTTP_200_OK
                )

        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response(
                {"error": "Invalid verification link"},
                status=status.HTTP_400_BAD_REQUEST,
            )

    def get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0]
        else:
            ip = request.META.get("REMOTE_ADDR")
        return ip


class ResendVerificationView(APIView):
    """Resend email verification endpoint"""

    permission_classes = [AllowAny]

    @extend_schema(
        summary="Resend verification email",
        description="Resend email verification link to user",
        request=EmailVerificationSerializer,
        responses={
            200: {"type": "object", "properties": {"message": {"type": "string"}}}
        },
        tags=["Authentication"],
    )
    def post(self, request):
        serializer = EmailVerificationSerializer(data=request.data)

        if serializer.is_valid():
            email = serializer.validated_data["email"]
            user = User.objects.get(email=email)

            # Generate verification token
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))

            # Send verification email
            verification_url = f"{request.build_absolute_uri('/api/v1/auth/verify-email/')}{uid}/{token}/"

            subject = "Verify your email address"
            message = f"""
            Hi {user.first_name},
            
            Please click the link below to verify your email address:
            {verification_url}
            
            If you didn't create this account, please ignore this email.
            
            Best regards,
            GST Verification Team
            """

            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )

            return Response(
                {"message": "Verification email sent successfully"},
                status=status.HTTP_200_OK,
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserActivityListView(generics.ListAPIView):
    """User activity list endpoint"""

    serializer_class = UserActivitySerializer
    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="Get user activity log",
        description="Retrieve current user's activity history",
        tags=["Authentication"],
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def get_queryset(self):
        return UserActivity.objects.filter(user=self.request.user).order_by(
            "-created_at"
        )
