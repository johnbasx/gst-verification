from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.exceptions import ValidationError, NotFound, PermissionDenied
from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError
from typing import Any, Dict, Optional
import logging

from .response_utils import APIResponse, PaginationHelper
from .response_serializers import (
    StandardResponseSerializer,
    ErrorResponseSerializer,
    PaginatedResponseSerializer,
    ValidationErrorResponseSerializer
)

logger = logging.getLogger(__name__)


class BaseAPIView(APIView):
    """Base API view with standardized response handling"""
    
    def handle_exception(self, exc):
        """Handle exceptions with standardized error responses"""
        request_id = getattr(self.request, 'request_id', None)
        
        if isinstance(exc, ValidationError):
            if hasattr(exc, 'detail') and isinstance(exc.detail, dict):
                return APIResponse.validation_error(
                    field_errors=exc.detail,
                    request_id=request_id
                )
            else:
                return APIResponse.error(
                    error_code="VALIDATION_ERROR",
                    message=str(exc),
                    status_code=status.HTTP_400_BAD_REQUEST,
                    request_id=request_id
                )
        
        elif isinstance(exc, (ObjectDoesNotExist, NotFound)):
            return APIResponse.not_found(
                message="The requested resource was not found",
                request_id=request_id
            )
        
        elif isinstance(exc, PermissionDenied):
            return APIResponse.forbidden(
                message="You don't have permission to access this resource",
                request_id=request_id
            )
        
        elif isinstance(exc, IntegrityError):
            return APIResponse.error(
                error_code="INTEGRITY_ERROR",
                message="Data integrity constraint violation",
                status_code=status.HTTP_400_BAD_REQUEST,
                request_id=request_id
            )
        
        else:
            # Log unexpected errors
            logger.error(f"Unexpected error in {self.__class__.__name__}: {exc}", exc_info=True)
            return APIResponse.server_error(
                message="An unexpected error occurred",
                request_id=request_id
            )
    
    def dispatch(self, request, *args, **kwargs):
        """Add request ID to request for tracing"""
        request.request_id = APIResponse._generate_request_id()
        return super().dispatch(request, *args, **kwargs)


class BaseListCreateAPIView(BaseAPIView, generics.ListCreateAPIView):
    """Base view for list and create operations with standardized responses"""
    
    def list(self, request, *args, **kwargs):
        """List objects with standardized pagination"""
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)
        
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            pagination_info = PaginationHelper.get_pagination_info(
                self.paginator.page, request
            )
            return APIResponse.paginated(
                data=serializer.data,
                pagination_info=pagination_info,
                message=f"{self.get_queryset().model._meta.verbose_name_plural.title()} retrieved successfully",
                request_id=request.request_id
            )
        
        serializer = self.get_serializer(queryset, many=True)
        return APIResponse.success(
            data=serializer.data,
            message=f"{self.get_queryset().model._meta.verbose_name_plural.title()} retrieved successfully",
            request_id=request.request_id
        )
    
    def create(self, request, *args, **kwargs):
        """Create object with standardized response"""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        instance = serializer.save()
        
        return APIResponse.success(
            data=serializer.data,
            message=f"{instance._meta.verbose_name.title()} created successfully",
            status_code=status.HTTP_201_CREATED,
            request_id=request.request_id
        )


class BaseRetrieveUpdateDestroyAPIView(BaseAPIView, generics.RetrieveUpdateDestroyAPIView):
    """Base view for retrieve, update, and destroy operations"""
    
    def retrieve(self, request, *args, **kwargs):
        """Retrieve object with standardized response"""
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        
        return APIResponse.success(
            data=serializer.data,
            message=f"{instance._meta.verbose_name.title()} retrieved successfully",
            request_id=request.request_id
        )
    
    def update(self, request, *args, **kwargs):
        """Update object with standardized response"""
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        instance = serializer.save()
        
        action = "updated" if not partial else "partially updated"
        return APIResponse.success(
            data=serializer.data,
            message=f"{instance._meta.verbose_name.title()} {action} successfully",
            request_id=request.request_id
        )
    
    def destroy(self, request, *args, **kwargs):
        """Delete object with standardized response"""
        instance = self.get_object()
        model_name = instance._meta.verbose_name.title()
        instance.delete()
        
        return APIResponse.success(
            data=None,
            message=f"{model_name} deleted successfully",
            status_code=status.HTTP_204_NO_CONTENT,
            request_id=request.request_id
        )


class BaseListAPIView(BaseAPIView, generics.ListAPIView):
    """Base view for list-only operations"""
    
    def list(self, request, *args, **kwargs):
        """List objects with standardized pagination"""
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)
        
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            pagination_info = PaginationHelper.get_pagination_info(
                self.paginator.page, request
            )
            return APIResponse.paginated(
                data=serializer.data,
                pagination_info=pagination_info,
                message=f"{self.get_queryset().model._meta.verbose_name_plural.title()} retrieved successfully",
                request_id=request.request_id
            )
        
        serializer = self.get_serializer(queryset, many=True)
        return APIResponse.success(
            data=serializer.data,
            message=f"{self.get_queryset().model._meta.verbose_name_plural.title()} retrieved successfully",
            request_id=request.request_id
        )


class BaseCreateAPIView(BaseAPIView, generics.CreateAPIView):
    """Base view for create-only operations"""
    
    def create(self, request, *args, **kwargs):
        """Create object with standardized response"""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        instance = serializer.save()
        
        return APIResponse.success(
            data=serializer.data,
            message=f"{instance._meta.verbose_name.title()} created successfully",
            status_code=status.HTTP_201_CREATED,
            request_id=request.request_id
        )


class BaseRetrieveAPIView(BaseAPIView, generics.RetrieveAPIView):
    """Base view for retrieve-only operations"""
    
    def retrieve(self, request, *args, **kwargs):
        """Retrieve object with standardized response"""
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        
        return APIResponse.success(
            data=serializer.data,
            message=f"{instance._meta.verbose_name.title()} retrieved successfully",
            request_id=request.request_id
        )