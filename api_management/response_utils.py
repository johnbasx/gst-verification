import uuid
from datetime import datetime
from typing import Any, Dict, Optional, Union
from rest_framework.response import Response
from rest_framework import status
from django.utils import timezone


class APIResponse:
    """Utility class for creating standardized API responses"""
    
    @staticmethod
    def _generate_request_id() -> str:
        """Generate a unique request ID for tracing"""
        return str(uuid.uuid4())
    
    @staticmethod
    def _get_timestamp() -> str:
        """Get current timestamp in ISO 8601 format"""
        return timezone.now().isoformat()
    
    @staticmethod
    def success(
        data: Any = None,
        message: str = "Request completed successfully",
        status_code: int = status.HTTP_200_OK,
        request_id: Optional[str] = None
    ) -> Response:
        """Create a successful response"""
        response_data = {
            "success": True,
            "message": message,
            "data": data,
            "timestamp": APIResponse._get_timestamp(),
            "request_id": request_id or APIResponse._generate_request_id()
        }
        return Response(response_data, status=status_code)
    
    @staticmethod
    def error(
        error_code: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        status_code: int = status.HTTP_400_BAD_REQUEST,
        request_id: Optional[str] = None
    ) -> Response:
        """Create an error response"""
        response_data = {
            "success": False,
            "error": error_code,
            "message": message,
            "details": details,
            "timestamp": APIResponse._get_timestamp(),
            "request_id": request_id or APIResponse._generate_request_id()
        }
        return Response(response_data, status=status_code)
    
    @staticmethod
    def validation_error(
        field_errors: Dict[str, Any],
        message: str = "Validation failed",
        request_id: Optional[str] = None
    ) -> Response:
        """Create a validation error response"""
        response_data = {
            "success": False,
            "error": "VALIDATION_ERROR",
            "message": message,
            "field_errors": field_errors,
            "timestamp": APIResponse._get_timestamp(),
            "request_id": request_id or APIResponse._generate_request_id()
        }
        return Response(response_data, status=status.HTTP_400_BAD_REQUEST)
    
    @staticmethod
    def paginated(
        data: list,
        pagination_info: Dict[str, Any],
        message: str = "Data retrieved successfully",
        request_id: Optional[str] = None
    ) -> Response:
        """Create a paginated response"""
        response_data = {
            "success": True,
            "message": message,
            "data": data,
            "pagination": pagination_info,
            "timestamp": APIResponse._get_timestamp(),
            "request_id": request_id or APIResponse._generate_request_id()
        }
        return Response(response_data, status=status.HTTP_200_OK)
    
    @staticmethod
    def rate_limit_error(
        retry_after: int,
        limit_info: Dict[str, Any],
        message: str = "Rate limit exceeded",
        request_id: Optional[str] = None
    ) -> Response:
        """Create a rate limit error response"""
        response_data = {
            "success": False,
            "error": "RATE_LIMIT_EXCEEDED",
            "message": message,
            "retry_after": retry_after,
            "limit_info": limit_info,
            "timestamp": APIResponse._get_timestamp(),
            "request_id": request_id or APIResponse._generate_request_id()
        }
        return Response(response_data, status=status.HTTP_429_TOO_MANY_REQUESTS)
    
    @staticmethod
    def not_found(
        message: str = "Resource not found",
        request_id: Optional[str] = None
    ) -> Response:
        """Create a not found error response"""
        return APIResponse.error(
            error_code="NOT_FOUND",
            message=message,
            status_code=status.HTTP_404_NOT_FOUND,
            request_id=request_id
        )
    
    @staticmethod
    def unauthorized(
        message: str = "Authentication required",
        request_id: Optional[str] = None
    ) -> Response:
        """Create an unauthorized error response"""
        return APIResponse.error(
            error_code="UNAUTHORIZED",
            message=message,
            status_code=status.HTTP_401_UNAUTHORIZED,
            request_id=request_id
        )
    
    @staticmethod
    def forbidden(
        message: str = "Access denied",
        request_id: Optional[str] = None
    ) -> Response:
        """Create a forbidden error response"""
        return APIResponse.error(
            error_code="FORBIDDEN",
            message=message,
            status_code=status.HTTP_403_FORBIDDEN,
            request_id=request_id
        )
    
    @staticmethod
    def server_error(
        message: str = "Internal server error",
        request_id: Optional[str] = None
    ) -> Response:
        """Create a server error response"""
        return APIResponse.error(
            error_code="INTERNAL_SERVER_ERROR",
            message=message,
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            request_id=request_id
        )


class PaginationHelper:
    """Helper class for pagination metadata"""
    
    @staticmethod
    def get_pagination_info(
        page_obj,
        request,
        total_count: Optional[int] = None
    ) -> Dict[str, Any]:
        """Generate pagination metadata"""
        if hasattr(page_obj, 'paginator'):
            paginator = page_obj.paginator
            current_page = page_obj.number
            total_pages = paginator.num_pages
            total_items = total_count or paginator.count
            per_page = paginator.per_page
        else:
            # Handle cases where pagination might not be available
            current_page = 1
            total_pages = 1
            total_items = total_count or len(page_obj) if hasattr(page_obj, '__len__') else 0
            per_page = total_items
        
        # Build URLs for navigation
        base_url = request.build_absolute_uri().split('?')[0]
        query_params = request.GET.copy()
        
        def build_url(page_num):
            if page_num:
                query_params['page'] = page_num
                return f"{base_url}?{query_params.urlencode()}"
            return None
        
        next_page = current_page + 1 if current_page < total_pages else None
        prev_page = current_page - 1 if current_page > 1 else None
        
        return {
            "current_page": current_page,
            "total_pages": total_pages,
            "total_items": total_items,
            "per_page": per_page,
            "has_next": next_page is not None,
            "has_previous": prev_page is not None,
            "next_url": build_url(next_page),
            "previous_url": build_url(prev_page),
            "first_url": build_url(1) if total_pages > 0 else None,
            "last_url": build_url(total_pages) if total_pages > 0 else None
        }