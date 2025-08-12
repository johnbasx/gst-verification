#!/usr/bin/env python3
"""
Logging Configuration Module for GST Verification API

This module provides comprehensive logging configuration including:
- Structured logging with JSON format
- Log rotation and archival
- Different log levels for different environments
- Security-aware logging (no sensitive data)
- Performance logging
- Audit logging
"""

import json
import logging
import logging.config
import logging.handlers
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional


class SecurityFilter(logging.Filter):
    """Filter to remove sensitive information from logs."""

    SENSITIVE_KEYS = {
        "password",
        "passwd",
        "pwd",
        "secret",
        "key",
        "token",
        "auth",
        "authorization",
        "api_key",
        "apikey",
        "session_id",
        "sessionid",
        "captcha_solution",
        "captcha_text",
        "otp",
        "pin",
        "ssn",
        "credit_card",
        "card_number",
        "cvv",
        "pan",
        "aadhaar",
        "gstin_details",
    }

    def filter(self, record):
        """Filter sensitive information from log records."""
        if hasattr(record, "msg") and isinstance(record.msg, str):
            # Check if message contains sensitive keywords
            msg_lower = record.msg.lower()
            for sensitive_key in self.SENSITIVE_KEYS:
                if sensitive_key in msg_lower:
                    # Replace the sensitive part with [REDACTED]
                    record.msg = self._redact_sensitive_data(record.msg)
                    break

        # Filter sensitive data from args
        if hasattr(record, "args") and record.args:
            record.args = self._redact_args(record.args)

        return True

    def _redact_sensitive_data(self, message: str) -> str:
        """Redact sensitive data from message."""
        # Simple redaction - in production, use more sophisticated regex patterns
        for sensitive_key in self.SENSITIVE_KEYS:
            if sensitive_key in message.lower():
                # Find and replace patterns like "key=value" or "key: value"
                import re

                patterns = [
                    rf"{sensitive_key}[\s]*[=:][\s]*[^\s,}}]+",
                    rf'"{sensitive_key}"[\s]*:[\s]*"[^"]+"',
                    rf"'{sensitive_key}'[\s]*:[\s]*'[^']+'",
                ]

                for pattern in patterns:
                    message = re.sub(
                        pattern,
                        f"{sensitive_key}=[REDACTED]",
                        message,
                        flags=re.IGNORECASE,
                    )

        return message

    def _redact_args(self, args):
        """Redact sensitive data from log arguments."""
        if isinstance(args, (list, tuple)):
            return [self._redact_value(arg) for arg in args]
        elif isinstance(args, dict):
            return {
                key: self._redact_value(value)
                if key.lower() in self.SENSITIVE_KEYS
                else value
                for key, value in args.items()
            }
        else:
            return args

    def _redact_value(self, value):
        """Redact a single value."""
        if isinstance(value, str) and len(value) > 0:
            return "[REDACTED]"
        elif isinstance(value, (dict, list)):
            return "[REDACTED]"
        else:
            return value


class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging."""

    def __init__(self, include_extra=True):
        super().__init__()
        self.include_extra = include_extra

    def format(self, record):
        """Format log record as JSON."""
        log_entry = {
            "timestamp": datetime.utcfromtimestamp(record.created).isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "process_id": record.process,
            "thread_id": record.thread,
        }

        # Add exception information if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        # Add stack trace if present
        if hasattr(record, "stack_info") and record.stack_info:
            log_entry["stack_trace"] = record.stack_info

        # Add extra fields if enabled
        if self.include_extra:
            extra_fields = {}
            for key, value in record.__dict__.items():
                if key not in {
                    "name",
                    "msg",
                    "args",
                    "levelname",
                    "levelno",
                    "pathname",
                    "filename",
                    "module",
                    "lineno",
                    "funcName",
                    "created",
                    "msecs",
                    "relativeCreated",
                    "thread",
                    "threadName",
                    "processName",
                    "process",
                    "getMessage",
                    "exc_info",
                    "exc_text",
                    "stack_info",
                }:
                    extra_fields[key] = value

            if extra_fields:
                log_entry["extra"] = extra_fields

        return json.dumps(log_entry, default=str, ensure_ascii=False)


class PerformanceFilter(logging.Filter):
    """Filter for performance-related logs."""

    def filter(self, record):
        """Only allow performance-related log records."""
        performance_keywords = {
            "duration",
            "response_time",
            "latency",
            "performance",
            "slow",
            "timeout",
            "benchmark",
            "profiling",
        }

        if hasattr(record, "msg") and isinstance(record.msg, str):
            msg_lower = record.msg.lower()
            return any(keyword in msg_lower for keyword in performance_keywords)

        return False


class AuditFilter(logging.Filter):
    """Filter for audit-related logs."""

    def filter(self, record):
        """Only allow audit-related log records."""
        audit_keywords = {
            "audit",
            "access",
            "login",
            "logout",
            "authentication",
            "authorization",
            "permission",
            "security",
            "violation",
            "attempt",
            "failed",
            "success",
            "user_action",
        }

        if hasattr(record, "msg") and isinstance(record.msg, str):
            msg_lower = record.msg.lower()
            return any(keyword in msg_lower for keyword in audit_keywords)

        # Check if record has audit-specific attributes
        return hasattr(record, "audit") or hasattr(record, "user_id")


class GST_API_Logger:
    """Main logging configuration class for GST Verification API."""

    def __init__(self, config=None):
        self.config = config or {}
        self.log_dir = Path(self.config.get("LOG_DIR", "logs"))
        self.log_level = self.config.get("LOG_LEVEL", "INFO")
        self.environment = self.config.get("FLASK_ENV", "development")
        self.enable_json_logging = self.config.get("JSON_LOGGING", True)
        self.enable_file_logging = self.config.get("FILE_LOGGING", True)
        self.enable_console_logging = self.config.get("CONSOLE_LOGGING", True)

        # Create log directory if it doesn't exist
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Initialize logging
        self._setup_logging()

    def _setup_logging(self):
        """Setup logging configuration."""
        # Clear existing handlers
        logging.getLogger().handlers.clear()

        # Create logging configuration
        config = self._create_logging_config()

        # Apply configuration
        logging.config.dictConfig(config)

        # Set root logger level
        logging.getLogger().setLevel(getattr(logging, self.log_level.upper()))

        # Create specialized loggers
        self._setup_specialized_loggers()

    def _create_logging_config(self) -> Dict[str, Any]:
        """Create comprehensive logging configuration."""
        config = {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "standard": {
                    "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                    "datefmt": "%Y-%m-%d %H:%M:%S",
                },
                "detailed": {
                    "format": "%(asctime)s [%(levelname)s] %(name)s:%(lineno)d %(funcName)s(): %(message)s",
                    "datefmt": "%Y-%m-%d %H:%M:%S",
                },
                "json": {"()": JSONFormatter, "include_extra": True},
            },
            "filters": {
                "security_filter": {"()": SecurityFilter},
                "performance_filter": {"()": PerformanceFilter},
                "audit_filter": {"()": AuditFilter},
            },
            "handlers": {},
            "loggers": {
                "": {"level": self.log_level, "handlers": []},  # Root logger
                "gst_api": {
                    "level": self.log_level,
                    "handlers": [],
                    "propagate": False,
                },
                "werkzeug": {"level": "WARNING", "handlers": [], "propagate": False},
                "urllib3": {"level": "WARNING", "handlers": [], "propagate": False},
            },
        }

        # Add handlers based on configuration
        handlers = []

        # Console handler
        if self.enable_console_logging:
            console_handler = {
                "class": "logging.StreamHandler",
                "level": self.log_level,
                "formatter": "json" if self.enable_json_logging else "standard",
                "filters": ["security_filter"],
                "stream": "ext://sys.stdout",
            }
            config["handlers"]["console"] = console_handler
            handlers.append("console")

        # File handlers
        if self.enable_file_logging:
            # Main application log
            main_log_handler = {
                "class": "logging.handlers.RotatingFileHandler",
                "level": self.log_level,
                "formatter": "json" if self.enable_json_logging else "detailed",
                "filters": ["security_filter"],
                "filename": str(self.log_dir / "gst_api.log"),
                "maxBytes": 10 * 1024 * 1024,  # 10MB
                "backupCount": 5,
                "encoding": "utf-8",
            }
            config["handlers"]["main_file"] = main_log_handler
            handlers.append("main_file")

            # Error log
            error_log_handler = {
                "class": "logging.handlers.RotatingFileHandler",
                "level": "ERROR",
                "formatter": "json" if self.enable_json_logging else "detailed",
                "filters": ["security_filter"],
                "filename": str(self.log_dir / "error.log"),
                "maxBytes": 10 * 1024 * 1024,  # 10MB
                "backupCount": 10,
                "encoding": "utf-8",
            }
            config["handlers"]["error_file"] = error_log_handler
            handlers.append("error_file")

            # Performance log
            performance_log_handler = {
                "class": "logging.handlers.RotatingFileHandler",
                "level": "INFO",
                "formatter": "json" if self.enable_json_logging else "detailed",
                "filters": ["security_filter", "performance_filter"],
                "filename": str(self.log_dir / "performance.log"),
                "maxBytes": 5 * 1024 * 1024,  # 5MB
                "backupCount": 3,
                "encoding": "utf-8",
            }
            config["handlers"]["performance_file"] = performance_log_handler

            # Audit log
            audit_log_handler = {
                "class": "logging.handlers.RotatingFileHandler",
                "level": "INFO",
                "formatter": "json" if self.enable_json_logging else "detailed",
                "filters": ["security_filter", "audit_filter"],
                "filename": str(self.log_dir / "audit.log"),
                "maxBytes": 5 * 1024 * 1024,  # 5MB
                "backupCount": 10,
                "encoding": "utf-8",
            }
            config["handlers"]["audit_file"] = audit_log_handler

            # Access log (for web requests)
            access_log_handler = {
                "class": "logging.handlers.TimedRotatingFileHandler",
                "level": "INFO",
                "formatter": "json" if self.enable_json_logging else "standard",
                "filters": ["security_filter"],
                "filename": str(self.log_dir / "access.log"),
                "when": "midnight",
                "interval": 1,
                "backupCount": 30,
                "encoding": "utf-8",
            }
            config["handlers"]["access_file"] = access_log_handler

        # Assign handlers to loggers
        config["loggers"][""]["handlers"] = handlers
        config["loggers"]["gst_api"]["handlers"] = handlers
        config["loggers"]["werkzeug"]["handlers"] = handlers
        config["loggers"]["urllib3"]["handlers"] = handlers

        return config

    def _setup_specialized_loggers(self):
        """Setup specialized loggers for different purposes."""
        # Performance logger
        self.performance_logger = logging.getLogger("gst_api.performance")
        if self.enable_file_logging:
            perf_handler = logging.handlers.RotatingFileHandler(
                self.log_dir / "performance.log",
                maxBytes=5 * 1024 * 1024,
                backupCount=3,
            )
            perf_handler.setFormatter(
                JSONFormatter()
                if self.enable_json_logging
                else logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
            )
            perf_handler.addFilter(PerformanceFilter())
            perf_handler.addFilter(SecurityFilter())
            self.performance_logger.addHandler(perf_handler)

        # Audit logger
        self.audit_logger = logging.getLogger("gst_api.audit")
        if self.enable_file_logging:
            audit_handler = logging.handlers.RotatingFileHandler(
                self.log_dir / "audit.log", maxBytes=5 * 1024 * 1024, backupCount=10
            )
            audit_handler.setFormatter(
                JSONFormatter()
                if self.enable_json_logging
                else logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
            )
            audit_handler.addFilter(AuditFilter())
            audit_handler.addFilter(SecurityFilter())
            self.audit_logger.addHandler(audit_handler)

        # Access logger
        self.access_logger = logging.getLogger("gst_api.access")
        if self.enable_file_logging:
            access_handler = logging.handlers.TimedRotatingFileHandler(
                self.log_dir / "access.log", when="midnight", interval=1, backupCount=30
            )
            access_handler.setFormatter(
                JSONFormatter()
                if self.enable_json_logging
                else logging.Formatter("%(asctime)s %(message)s")
            )
            access_handler.addFilter(SecurityFilter())
            self.access_logger.addHandler(access_handler)

    def get_logger(self, name: str = "gst_api") -> logging.Logger:
        """Get a logger instance."""
        return logging.getLogger(name)

    def log_request(
        self,
        method: str,
        path: str,
        status_code: int,
        duration: float,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
    ):
        """Log HTTP request information."""
        extra = {
            "method": method,
            "path": path,
            "status_code": status_code,
            "duration": duration,
            "user_id": user_id,
            "ip_address": ip_address,
            "request_type": "http_request",
        }

        message = f"{method} {path} - {status_code} - {duration:.3f}s"
        if user_id:
            message += f" - User: {user_id}"
        if ip_address:
            message += f" - IP: {ip_address}"

        self.access_logger.info(message, extra=extra)

    def log_performance(
        self, operation: str, duration: float, details: Optional[Dict[str, Any]] = None
    ):
        """Log performance metrics."""
        extra = {
            "operation": operation,
            "duration": duration,
            "performance_metric": True,
        }

        if details:
            extra.update(details)

        message = f"Performance: {operation} took {duration:.3f}s"
        self.performance_logger.info(message, extra=extra)

    def log_audit(
        self,
        action: str,
        user_id: Optional[str] = None,
        resource: Optional[str] = None,
        result: str = "success",
        details: Optional[Dict[str, Any]] = None,
    ):
        """Log audit events."""
        extra = {
            "action": action,
            "user_id": user_id,
            "resource": resource,
            "result": result,
            "audit": True,
        }

        if details:
            extra.update(details)

        message = f"Audit: {action}"
        if user_id:
            message += f" by user {user_id}"
        if resource:
            message += f" on {resource}"
        message += f" - {result}"

        self.audit_logger.info(message, extra=extra)

    def log_security_event(
        self,
        event_type: str,
        severity: str = "warning",
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        """Log security events."""
        extra = {
            "event_type": event_type,
            "severity": severity,
            "user_id": user_id,
            "ip_address": ip_address,
            "security_event": True,
        }

        if details:
            extra.update(details)

        message = f"Security Event: {event_type}"
        if user_id:
            message += f" - User: {user_id}"
        if ip_address:
            message += f" - IP: {ip_address}"

        logger = self.get_logger("gst_api.security")

        if severity.lower() == "critical":
            logger.critical(message, extra=extra)
        elif severity.lower() == "error":
            logger.error(message, extra=extra)
        else:
            logger.warning(message, extra=extra)

    def configure_flask_logging(self, app):
        """Configure Flask application logging."""
        # Disable Flask's default logging
        app.logger.handlers.clear()

        # Add our handlers to Flask's logger
        flask_logger = logging.getLogger("flask")
        flask_logger.handlers.clear()

        # Use our main logger for Flask
        main_logger = self.get_logger("gst_api")
        for handler in main_logger.handlers:
            flask_logger.addHandler(handler)

        flask_logger.setLevel(getattr(logging, self.log_level.upper()))

        # Configure Werkzeug logging
        werkzeug_logger = logging.getLogger("werkzeug")
        werkzeug_logger.setLevel(logging.WARNING)

    def setup_request_logging(self, app):
        """Setup request logging middleware for Flask."""

        @app.before_request
        def before_request():
            import time

            from flask import g, request

            g.start_time = time.time()

            # Log request start
            self.get_logger("gst_api.requests").debug(
                f"Request started: {request.method} {request.path}",
                extra={
                    "method": request.method,
                    "path": request.path,
                    "remote_addr": request.remote_addr,
                    "user_agent": request.headers.get("User-Agent", ""),
                    "request_id": getattr(g, "request_id", None),
                },
            )

        @app.after_request
        def after_request(response):
            import time

            from flask import g, request

            if hasattr(g, "start_time"):
                duration = time.time() - g.start_time

                # Log request completion
                self.log_request(
                    method=request.method,
                    path=request.path,
                    status_code=response.status_code,
                    duration=duration,
                    ip_address=request.remote_addr,
                )

            return response

        @app.teardown_request
        def teardown_request(exception):
            if exception:
                from flask import request

                self.get_logger("gst_api.errors").error(
                    f"Request failed with exception: {exception}",
                    exc_info=True,
                    extra={
                        "exception_type": type(exception).__name__,
                        "request_path": getattr(request, "path", "unknown"),
                        "request_method": getattr(request, "method", "unknown"),
                    },
                )


def setup_logging(config: Optional[Dict[str, Any]] = None) -> GST_API_Logger:
    """Setup logging for the GST Verification API."""
    if config is None:
        config = {
            "LOG_DIR": os.getenv("LOG_DIR", "logs"),
            "LOG_LEVEL": os.getenv("LOG_LEVEL", "INFO"),
            "FLASK_ENV": os.getenv("FLASK_ENV", "development"),
            "JSON_LOGGING": os.getenv("JSON_LOGGING", "true").lower() == "true",
            "FILE_LOGGING": os.getenv("FILE_LOGGING", "true").lower() == "true",
            "CONSOLE_LOGGING": os.getenv("CONSOLE_LOGGING", "true").lower() == "true",
        }

    return GST_API_Logger(config)


if __name__ == "__main__":
    # Example usage
    logger_config = setup_logging()
    logger = logger_config.get_logger()

    # Test different log levels
    logger.debug("This is a debug message")
    logger.info("This is an info message")
    logger.warning("This is a warning message")
    logger.error("This is an error message")

    # Test specialized logging
    logger_config.log_performance("test_operation", 1.234)
    logger_config.log_audit("user_login", user_id="test_user", result="success")
    logger_config.log_security_event(
        "failed_login_attempt",
        severity="warning",
        user_id="test_user",
        ip_address="192.168.1.1",
    )

    # Test sensitive data filtering
    logger.info("User login with password=secret123 and token=abc123")
    logger.info("Processing GSTIN details: {gstin_details: 'sensitive_data'}")

    print("Logging test completed. Check the logs directory for output files.")
