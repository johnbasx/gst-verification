#!/usr/bin/env python3
"""
Monitoring and Observability Module for GST Verification API

This module provides comprehensive monitoring capabilities including:
- Prometheus metrics collection
- Health checks
- Performance monitoring
- Error tracking
- Custom alerts
"""

import time
import psutil
import logging
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict, deque
from threading import Lock
from typing import Dict, List, Optional, Any

try:
    from prometheus_client import (
        Counter, Histogram, Gauge, Info, generate_latest,
        CollectorRegistry, CONTENT_TYPE_LATEST
    )
    PROMETHEUS_AVAILABLE = True
except ImportError:
    print("Warning: prometheus_client not available. Metrics collection disabled.")
    PROMETHEUS_AVAILABLE = False
    # Create dummy classes when prometheus is not available
    class Counter:
        def __init__(self, *args, **kwargs): pass
        def inc(self, *args, **kwargs): pass
        def labels(self, *args, **kwargs): return self
    
    class Histogram:
        def __init__(self, *args, **kwargs): pass
        def observe(self, *args, **kwargs): pass
        def labels(self, *args, **kwargs): return self
        def time(self): return self
        def __enter__(self): return self
        def __exit__(self, *args): pass
    
    class Gauge:
        def __init__(self, *args, **kwargs): pass
        def set(self, *args, **kwargs): pass
        def inc(self, *args, **kwargs): pass
        def dec(self, *args, **kwargs): pass
        def labels(self, *args, **kwargs): return self
    
    class Info:
        def __init__(self, *args, **kwargs): pass
        def info(self, *args, **kwargs): pass
    
    class CollectorRegistry:
        def __init__(self, *args, **kwargs): pass
    
    def generate_latest(*args, **kwargs): return b''
    CONTENT_TYPE_LATEST = 'text/plain'


class MetricsCollector:
    """Centralized metrics collection for the GST Verification API."""
    
    def __init__(self, registry=None):
        self.registry = registry or CollectorRegistry()
        self._lock = Lock()
        self.start_time = time.time()
        
        if PROMETHEUS_AVAILABLE:
            self._init_prometheus_metrics()
        
        # In-memory metrics for basic monitoring
        self.request_counts = defaultdict(int)
        self.response_times = defaultdict(list)
        self.error_counts = defaultdict(int)
        self.active_sessions = 0
        self.recent_requests = deque(maxlen=1000)
        
        # System metrics
        self.system_metrics = {
            'cpu_usage': 0.0,
            'memory_usage': 0.0,
            'disk_usage': 0.0,
            'network_io': {'bytes_sent': 0, 'bytes_recv': 0}
        }
        
        self.logger = logging.getLogger(__name__)
    
    def _init_prometheus_metrics(self):
        """Initialize Prometheus metrics."""
        # Request metrics
        self.request_counter = Counter(
            'gst_api_requests_total',
            'Total number of requests',
            ['method', 'endpoint', 'status_code'],
            registry=self.registry
        )
        
        self.request_duration = Histogram(
            'gst_api_request_duration_seconds',
            'Request duration in seconds',
            ['method', 'endpoint'],
            registry=self.registry
        )
        
        # Business metrics
        self.captcha_requests = Counter(
            'gst_api_captcha_requests_total',
            'Total captcha requests',
            ['status'],
            registry=self.registry
        )
        
        self.gst_verification_requests = Counter(
            'gst_api_gst_verifications_total',
            'Total GST verification requests',
            ['status', 'error_type'],
            registry=self.registry
        )
        
        self.gstin_validation_requests = Counter(
            'gst_api_gstin_validations_total',
            'Total GSTIN validation requests',
            ['is_valid'],
            registry=self.registry
        )
        
        # System metrics
        self.active_sessions_gauge = Gauge(
            'gst_api_active_sessions',
            'Number of active sessions',
            registry=self.registry
        )
        
        self.system_cpu_usage = Gauge(
            'gst_api_system_cpu_usage_percent',
            'System CPU usage percentage',
            registry=self.registry
        )
        
        self.system_memory_usage = Gauge(
            'gst_api_system_memory_usage_percent',
            'System memory usage percentage',
            registry=self.registry
        )
        
        self.system_disk_usage = Gauge(
            'gst_api_system_disk_usage_percent',
            'System disk usage percentage',
            registry=self.registry
        )
        
        # Rate limiting metrics
        self.rate_limit_hits = Counter(
            'gst_api_rate_limit_hits_total',
            'Total rate limit hits',
            ['endpoint'],
            registry=self.registry
        )
        
        # Error metrics
        self.error_counter = Counter(
            'gst_api_errors_total',
            'Total number of errors',
            ['error_type', 'endpoint'],
            registry=self.registry
        )
        
        # Application info
        self.app_info = Info(
            'gst_api_info',
            'Application information',
            registry=self.registry
        )
        
        # Uptime
        self.uptime_gauge = Gauge(
            'gst_api_uptime_seconds',
            'Application uptime in seconds',
            registry=self.registry
        )
    
    def record_request(self, method: str, endpoint: str, status_code: int, duration: float):
        """Record a request with its metrics."""
        with self._lock:
            # Update in-memory metrics
            key = f"{method}:{endpoint}"
            self.request_counts[key] += 1
            self.response_times[key].append(duration)
            
            # Keep only recent response times (last 100)
            if len(self.response_times[key]) > 100:
                self.response_times[key] = self.response_times[key][-100:]
            
            # Record recent request
            self.recent_requests.append({
                'timestamp': datetime.utcnow(),
                'method': method,
                'endpoint': endpoint,
                'status_code': status_code,
                'duration': duration
            })
            
            # Update Prometheus metrics
            if PROMETHEUS_AVAILABLE:
                self.request_counter.labels(
                    method=method,
                    endpoint=endpoint,
                    status_code=status_code
                ).inc()
                
                self.request_duration.labels(
                    method=method,
                    endpoint=endpoint
                ).observe(duration)
    
    def record_captcha_request(self, status: str):
        """Record captcha request metrics."""
        if PROMETHEUS_AVAILABLE:
            self.captcha_requests.labels(status=status).inc()
    
    def record_gst_verification(self, status: str, error_type: str = 'none'):
        """Record GST verification metrics."""
        if PROMETHEUS_AVAILABLE:
            self.gst_verification_requests.labels(
                status=status,
                error_type=error_type
            ).inc()
    
    def record_gstin_validation(self, is_valid: bool):
        """Record GSTIN validation metrics."""
        if PROMETHEUS_AVAILABLE:
            self.gstin_validation_requests.labels(
                is_valid=str(is_valid).lower()
            ).inc()
    
    def record_rate_limit_hit(self, endpoint: str):
        """Record rate limit hit."""
        if PROMETHEUS_AVAILABLE:
            self.rate_limit_hits.labels(endpoint=endpoint).inc()
    
    def record_error(self, error_type: str, endpoint: str):
        """Record error occurrence."""
        with self._lock:
            self.error_counts[f"{error_type}:{endpoint}"] += 1
        
        if PROMETHEUS_AVAILABLE:
            self.error_counter.labels(
                error_type=error_type,
                endpoint=endpoint
            ).inc()
    
    def update_active_sessions(self, count: int):
        """Update active sessions count."""
        with self._lock:
            self.active_sessions = count
        
        if PROMETHEUS_AVAILABLE:
            self.active_sessions_gauge.set(count)
    
    def update_system_metrics(self):
        """Update system metrics."""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Memory usage
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            
            # Disk usage
            disk = psutil.disk_usage('/')
            disk_percent = (disk.used / disk.total) * 100
            
            # Network I/O
            network = psutil.net_io_counters()
            
            with self._lock:
                self.system_metrics.update({
                    'cpu_usage': cpu_percent,
                    'memory_usage': memory_percent,
                    'disk_usage': disk_percent,
                    'network_io': {
                        'bytes_sent': network.bytes_sent,
                        'bytes_recv': network.bytes_recv
                    }
                })
            
            if PROMETHEUS_AVAILABLE:
                self.system_cpu_usage.set(cpu_percent)
                self.system_memory_usage.set(memory_percent)
                self.system_disk_usage.set(disk_percent)
                
                # Update uptime
                uptime = time.time() - self.start_time
                self.uptime_gauge.set(uptime)
        
        except Exception as e:
            self.logger.error(f"Failed to update system metrics: {e}")
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get a summary of current metrics."""
        with self._lock:
            # Calculate request rates
            now = datetime.utcnow()
            recent_requests_1min = [
                req for req in self.recent_requests
                if now - req['timestamp'] <= timedelta(minutes=1)
            ]
            recent_requests_5min = [
                req for req in self.recent_requests
                if now - req['timestamp'] <= timedelta(minutes=5)
            ]
            
            # Calculate average response times
            avg_response_times = {}
            for key, times in self.response_times.items():
                if times:
                    avg_response_times[key] = sum(times) / len(times)
            
            return {
                'request_counts': dict(self.request_counts),
                'error_counts': dict(self.error_counts),
                'active_sessions': self.active_sessions,
                'system_metrics': self.system_metrics.copy(),
                'request_rates': {
                    'per_minute': len(recent_requests_1min),
                    'per_5_minutes': len(recent_requests_5min)
                },
                'average_response_times': avg_response_times,
                'uptime_seconds': time.time() - self.start_time
            }
    
    def export_prometheus_metrics(self) -> str:
        """Export metrics in Prometheus format."""
        if not PROMETHEUS_AVAILABLE:
            return "# Prometheus client not available\n"
        
        # Update system metrics before export
        self.update_system_metrics()
        
        return generate_latest(self.registry)


class HealthChecker:
    """Comprehensive health checking for the GST Verification API."""
    
    def __init__(self, metrics_collector: MetricsCollector):
        self.metrics = metrics_collector
        self.logger = logging.getLogger(__name__)
        self.checks = {}
        self._register_default_checks()
    
    def _register_default_checks(self):
        """Register default health checks."""
        self.register_check('system_resources', self._check_system_resources)
        self.register_check('memory_usage', self._check_memory_usage)
        self.register_check('disk_space', self._check_disk_space)
        self.register_check('response_times', self._check_response_times)
        self.register_check('error_rates', self._check_error_rates)
    
    def register_check(self, name: str, check_function):
        """Register a custom health check."""
        self.checks[name] = check_function
    
    def _check_system_resources(self) -> Dict[str, Any]:
        """Check system resource usage."""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            
            status = 'healthy'
            issues = []
            
            if cpu_percent > 80:
                status = 'warning'
                issues.append(f'High CPU usage: {cpu_percent:.1f}%')
            
            if memory.percent > 85:
                status = 'critical' if memory.percent > 95 else 'warning'
                issues.append(f'High memory usage: {memory.percent:.1f}%')
            
            return {
                'status': status,
                'cpu_usage': cpu_percent,
                'memory_usage': memory.percent,
                'issues': issues
            }
        
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def _check_memory_usage(self) -> Dict[str, Any]:
        """Check memory usage patterns."""
        try:
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()
            
            status = 'healthy'
            issues = []
            
            if memory.percent > 90:
                status = 'critical'
                issues.append('Critical memory usage')
            elif memory.percent > 75:
                status = 'warning'
                issues.append('High memory usage')
            
            if swap.percent > 50:
                status = 'warning'
                issues.append('High swap usage')
            
            return {
                'status': status,
                'memory_percent': memory.percent,
                'swap_percent': swap.percent,
                'available_mb': memory.available // (1024 * 1024),
                'issues': issues
            }
        
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def _check_disk_space(self) -> Dict[str, Any]:
        """Check disk space usage."""
        try:
            disk = psutil.disk_usage('/')
            percent_used = (disk.used / disk.total) * 100
            
            status = 'healthy'
            issues = []
            
            if percent_used > 90:
                status = 'critical'
                issues.append('Critical disk space usage')
            elif percent_used > 80:
                status = 'warning'
                issues.append('High disk space usage')
            
            return {
                'status': status,
                'disk_usage_percent': percent_used,
                'free_gb': disk.free // (1024 ** 3),
                'total_gb': disk.total // (1024 ** 3),
                'issues': issues
            }
        
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def _check_response_times(self) -> Dict[str, Any]:
        """Check API response times."""
        try:
            summary = self.metrics.get_metrics_summary()
            avg_times = summary.get('average_response_times', {})
            
            status = 'healthy'
            issues = []
            slow_endpoints = []
            
            for endpoint, avg_time in avg_times.items():
                if avg_time > 5.0:  # 5 seconds threshold
                    status = 'warning'
                    slow_endpoints.append(f'{endpoint}: {avg_time:.2f}s')
            
            if slow_endpoints:
                issues.append(f'Slow endpoints: {", ".join(slow_endpoints)}')
            
            return {
                'status': status,
                'average_response_times': avg_times,
                'issues': issues
            }
        
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def _check_error_rates(self) -> Dict[str, Any]:
        """Check error rates."""
        try:
            summary = self.metrics.get_metrics_summary()
            error_counts = summary.get('error_counts', {})
            request_counts = summary.get('request_counts', {})
            
            total_requests = sum(request_counts.values())
            total_errors = sum(error_counts.values())
            
            error_rate = (total_errors / total_requests * 100) if total_requests > 0 else 0
            
            status = 'healthy'
            issues = []
            
            if error_rate > 10:  # 10% error rate threshold
                status = 'critical'
                issues.append(f'High error rate: {error_rate:.1f}%')
            elif error_rate > 5:  # 5% error rate threshold
                status = 'warning'
                issues.append(f'Elevated error rate: {error_rate:.1f}%')
            
            return {
                'status': status,
                'error_rate_percent': error_rate,
                'total_errors': total_errors,
                'total_requests': total_requests,
                'issues': issues
            }
        
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def run_health_checks(self) -> Dict[str, Any]:
        """Run all registered health checks."""
        results = {}
        overall_status = 'healthy'
        all_issues = []
        
        for check_name, check_function in self.checks.items():
            try:
                result = check_function()
                results[check_name] = result
                
                # Determine overall status
                check_status = result.get('status', 'unknown')
                if check_status == 'critical':
                    overall_status = 'critical'
                elif check_status == 'warning' and overall_status != 'critical':
                    overall_status = 'warning'
                elif check_status == 'error' and overall_status == 'healthy':
                    overall_status = 'degraded'
                
                # Collect issues
                if 'issues' in result:
                    all_issues.extend(result['issues'])
            
            except Exception as e:
                self.logger.error(f"Health check '{check_name}' failed: {e}")
                results[check_name] = {
                    'status': 'error',
                    'error': str(e)
                }
                if overall_status == 'healthy':
                    overall_status = 'degraded'
        
        return {
            'overall_status': overall_status,
            'timestamp': datetime.utcnow().isoformat(),
            'checks': results,
            'issues': all_issues,
            'summary': self.metrics.get_metrics_summary()
        }


class AlertManager:
    """Alert management for the GST Verification API."""
    
    def __init__(self, metrics_collector: MetricsCollector, health_checker: HealthChecker):
        self.metrics = metrics_collector
        self.health_checker = health_checker
        self.logger = logging.getLogger(__name__)
        
        # Alert thresholds
        self.thresholds = {
            'error_rate': 5.0,  # 5% error rate
            'response_time': 3.0,  # 3 seconds
            'cpu_usage': 80.0,  # 80% CPU usage
            'memory_usage': 85.0,  # 85% memory usage
            'disk_usage': 80.0,  # 80% disk usage
            'request_rate': 100,  # 100 requests per minute
        }
        
        # Alert history to prevent spam
        self.alert_history = defaultdict(list)
        self.alert_cooldown = 300  # 5 minutes cooldown
    
    def check_alerts(self) -> List[Dict[str, Any]]:
        """Check for alert conditions."""
        alerts = []
        
        # Get current metrics
        summary = self.metrics.get_metrics_summary()
        health_status = self.health_checker.run_health_checks()
        
        # Check error rate
        alerts.extend(self._check_error_rate_alerts(summary))
        
        # Check response times
        alerts.extend(self._check_response_time_alerts(summary))
        
        # Check system resources
        alerts.extend(self._check_system_alerts(summary))
        
        # Check health status
        alerts.extend(self._check_health_alerts(health_status))
        
        # Filter out alerts in cooldown
        filtered_alerts = self._filter_cooldown_alerts(alerts)
        
        return filtered_alerts
    
    def _check_error_rate_alerts(self, summary: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for error rate alerts."""
        alerts = []
        
        error_counts = summary.get('error_counts', {})
        request_counts = summary.get('request_counts', {})
        
        total_requests = sum(request_counts.values())
        total_errors = sum(error_counts.values())
        
        if total_requests > 0:
            error_rate = (total_errors / total_requests) * 100
            
            if error_rate > self.thresholds['error_rate']:
                alerts.append({
                    'type': 'error_rate',
                    'severity': 'critical' if error_rate > 10 else 'warning',
                    'message': f'High error rate: {error_rate:.1f}%',
                    'value': error_rate,
                    'threshold': self.thresholds['error_rate'],
                    'timestamp': datetime.utcnow().isoformat()
                })
        
        return alerts
    
    def _check_response_time_alerts(self, summary: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for response time alerts."""
        alerts = []
        
        avg_times = summary.get('average_response_times', {})
        
        for endpoint, avg_time in avg_times.items():
            if avg_time > self.thresholds['response_time']:
                alerts.append({
                    'type': 'response_time',
                    'severity': 'critical' if avg_time > 5 else 'warning',
                    'message': f'Slow response time for {endpoint}: {avg_time:.2f}s',
                    'endpoint': endpoint,
                    'value': avg_time,
                    'threshold': self.thresholds['response_time'],
                    'timestamp': datetime.utcnow().isoformat()
                })
        
        return alerts
    
    def _check_system_alerts(self, summary: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for system resource alerts."""
        alerts = []
        
        system_metrics = summary.get('system_metrics', {})
        
        # CPU usage alert
        cpu_usage = system_metrics.get('cpu_usage', 0)
        if cpu_usage > self.thresholds['cpu_usage']:
            alerts.append({
                'type': 'cpu_usage',
                'severity': 'critical' if cpu_usage > 90 else 'warning',
                'message': f'High CPU usage: {cpu_usage:.1f}%',
                'value': cpu_usage,
                'threshold': self.thresholds['cpu_usage'],
                'timestamp': datetime.utcnow().isoformat()
            })
        
        # Memory usage alert
        memory_usage = system_metrics.get('memory_usage', 0)
        if memory_usage > self.thresholds['memory_usage']:
            alerts.append({
                'type': 'memory_usage',
                'severity': 'critical' if memory_usage > 95 else 'warning',
                'message': f'High memory usage: {memory_usage:.1f}%',
                'value': memory_usage,
                'threshold': self.thresholds['memory_usage'],
                'timestamp': datetime.utcnow().isoformat()
            })
        
        # Disk usage alert
        disk_usage = system_metrics.get('disk_usage', 0)
        if disk_usage > self.thresholds['disk_usage']:
            alerts.append({
                'type': 'disk_usage',
                'severity': 'critical' if disk_usage > 90 else 'warning',
                'message': f'High disk usage: {disk_usage:.1f}%',
                'value': disk_usage,
                'threshold': self.thresholds['disk_usage'],
                'timestamp': datetime.utcnow().isoformat()
            })
        
        return alerts
    
    def _check_health_alerts(self, health_status: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for health status alerts."""
        alerts = []
        
        overall_status = health_status.get('overall_status', 'unknown')
        
        if overall_status in ['critical', 'degraded']:
            severity = 'critical' if overall_status == 'critical' else 'warning'
            
            issues = health_status.get('issues', [])
            message = f'Health check status: {overall_status}'
            if issues:
                message += f' - Issues: {"; ".join(issues)}'
            
            alerts.append({
                'type': 'health_status',
                'severity': severity,
                'message': message,
                'status': overall_status,
                'issues': issues,
                'timestamp': datetime.utcnow().isoformat()
            })
        
        return alerts
    
    def _filter_cooldown_alerts(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter out alerts that are in cooldown period."""
        filtered_alerts = []
        current_time = datetime.utcnow()
        
        for alert in alerts:
            alert_key = f"{alert['type']}:{alert.get('endpoint', 'global')}"
            
            # Check if this alert type is in cooldown
            recent_alerts = [
                alert_time for alert_time in self.alert_history[alert_key]
                if (current_time - alert_time).total_seconds() < self.alert_cooldown
            ]
            
            if not recent_alerts:
                # Not in cooldown, add to filtered alerts
                filtered_alerts.append(alert)
                
                # Add to history
                self.alert_history[alert_key].append(current_time)
                
                # Keep only recent history
                self.alert_history[alert_key] = [
                    alert_time for alert_time in self.alert_history[alert_key]
                    if (current_time - alert_time).total_seconds() < self.alert_cooldown * 2
                ]
        
        return filtered_alerts
    
    def send_alert(self, alert: Dict[str, Any]):
        """Send alert to configured channels."""
        try:
            # Log the alert
            self.logger.warning(f"ALERT: {alert['message']}")
            
            # Here you would integrate with your alerting systems:
            # - Slack/Discord webhooks
            # - Email notifications
            # - PagerDuty
            # - SMS alerts
            # - etc.
            
            # Example webhook notification (implement as needed)
            # self._send_webhook_alert(alert)
            
        except Exception as e:
            self.logger.error(f"Failed to send alert: {e}")


def monitor_request(metrics_collector: MetricsCollector):
    """Decorator to monitor API requests."""
    def monitor_decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            start_time = time.time()
            
            try:
                # Execute the function
                result = f(*args, **kwargs)
                
                # Calculate duration
                duration = time.time() - start_time
                
                # Extract request info
                from flask import request
                method = request.method
                endpoint = request.endpoint or 'unknown'
                
                # Determine status code
                if hasattr(result, 'status_code'):
                    status_code = result.status_code
                elif isinstance(result, tuple) and len(result) > 1:
                    status_code = result[1]
                else:
                    status_code = 200
                
                # Record metrics
                metrics_collector.record_request(method, endpoint, status_code, duration)
                
                return result
            
            except Exception as e:
                # Record error
                duration = time.time() - start_time
                from flask import request
                method = request.method
                endpoint = request.endpoint or 'unknown'
                
                metrics_collector.record_request(method, endpoint, 500, duration)
                metrics_collector.record_error(type(e).__name__, endpoint)
                
                raise
        
        return decorated_function
    return monitor_decorator


# Global instances (to be initialized in main application)
metrics_collector = None
health_checker = None
alert_manager = None


def initialize_monitoring():
    """Initialize monitoring components."""
    global metrics_collector, health_checker, alert_manager
    
    metrics_collector = MetricsCollector()
    health_checker = HealthChecker(metrics_collector)
    alert_manager = AlertManager(metrics_collector, health_checker)
    
    return metrics_collector, health_checker, alert_manager


if __name__ == "__main__":
    # Example usage
    metrics, health, alerts = initialize_monitoring()
    
    # Simulate some metrics
    metrics.record_request('GET', '/api/v1/health', 200, 0.1)
    metrics.record_captcha_request('success')
    metrics.record_gstin_validation(True)
    
    # Run health checks
    health_status = health.run_health_checks()
    print("Health Status:", health_status['overall_status'])
    
    # Check for alerts
    current_alerts = alerts.check_alerts()
    print(f"Active Alerts: {len(current_alerts)}")
    
    # Export Prometheus metrics
    if PROMETHEUS_AVAILABLE:
        prometheus_metrics = metrics.export_prometheus_metrics()
        print("\nPrometheus Metrics:")
        print(prometheus_metrics[:500] + "..." if len(prometheus_metrics) > 500 else prometheus_metrics)