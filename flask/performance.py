#!/usr/bin/env python3
"""
Performance Optimization Module for GST Verification API

This module provides comprehensive performance optimization including:
- Intelligent caching strategies
- Connection pooling
- Request optimization
- Memory management
- Database query optimization
- Async processing capabilities
"""

import asyncio
import hashlib
import logging
import threading
import time
from collections import OrderedDict, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from functools import lru_cache, wraps
from typing import Any, Callable, Dict, List, Optional, Union

try:
    import redis

    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    print("Warning: redis not available. Using in-memory cache only.")

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("Warning: requests not available. HTTP optimization disabled.")


class InMemoryCache:
    """High-performance in-memory cache with TTL support."""

    def __init__(self, max_size: int = 1000, default_ttl: int = 300):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.cache = OrderedDict()
        self.expiry_times = {}
        self.access_counts = defaultdict(int)
        self.lock = threading.RLock()

        # Statistics
        self.hits = 0
        self.misses = 0
        self.evictions = 0

    def _is_expired(self, key: str) -> bool:
        """Check if a cache entry is expired."""
        if key not in self.expiry_times:
            return True
        return datetime.utcnow() > self.expiry_times[key]

    def _evict_expired(self):
        """Remove expired entries from cache."""
        current_time = datetime.utcnow()
        expired_keys = [
            key
            for key, expiry_time in self.expiry_times.items()
            if current_time > expiry_time
        ]

        for key in expired_keys:
            self._remove_key(key)

    def _remove_key(self, key: str):
        """Remove a key from all cache structures."""
        if key in self.cache:
            del self.cache[key]
        if key in self.expiry_times:
            del self.expiry_times[key]
        if key in self.access_counts:
            del self.access_counts[key]

    def _evict_lru(self):
        """Evict least recently used items to make space."""
        while len(self.cache) >= self.max_size:
            # Find least recently used key
            lru_key = min(
                self.access_counts.keys(), key=lambda k: self.access_counts[k]
            )
            self._remove_key(lru_key)
            self.evictions += 1

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        with self.lock:
            # Clean expired entries periodically
            if len(self.cache) % 100 == 0:
                self._evict_expired()

            if key not in self.cache or self._is_expired(key):
                self.misses += 1
                if key in self.cache:
                    self._remove_key(key)
                return None

            # Update access count and move to end (most recently used)
            self.access_counts[key] += 1
            value = self.cache[key]
            del self.cache[key]
            self.cache[key] = value

            self.hits += 1
            return value

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in cache with optional TTL."""
        with self.lock:
            ttl = ttl or self.default_ttl

            # Evict expired entries
            self._evict_expired()

            # Evict LRU if necessary
            if len(self.cache) >= self.max_size:
                self._evict_lru()

            # Set new value
            self.cache[key] = value
            self.expiry_times[key] = datetime.utcnow() + timedelta(seconds=ttl)
            self.access_counts[key] = 1

            return True

    def delete(self, key: str) -> bool:
        """Delete key from cache."""
        with self.lock:
            if key in self.cache:
                self._remove_key(key)
                return True
            return False

    def clear(self):
        """Clear all cache entries."""
        with self.lock:
            self.cache.clear()
            self.expiry_times.clear()
            self.access_counts.clear()

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self.lock:
            total_requests = self.hits + self.misses
            hit_rate = (self.hits / total_requests * 100) if total_requests > 0 else 0

            return {
                "size": len(self.cache),
                "max_size": self.max_size,
                "hits": self.hits,
                "misses": self.misses,
                "hit_rate": hit_rate,
                "evictions": self.evictions,
                "memory_usage_mb": self._estimate_memory_usage(),
            }

    def _estimate_memory_usage(self) -> float:
        """Estimate memory usage in MB."""
        import sys

        total_size = 0

        for key, value in self.cache.items():
            total_size += sys.getsizeof(key) + sys.getsizeof(value)

        return total_size / (1024 * 1024)


class CacheManager:
    """Unified cache manager supporting multiple backends."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        # Initialize cache backends
        self.memory_cache = InMemoryCache(
            max_size=self.config.get("MEMORY_CACHE_SIZE", 1000),
            default_ttl=self.config.get("DEFAULT_TTL", 300),
        )

        self.redis_cache = None
        if REDIS_AVAILABLE and self.config.get("REDIS_URL"):
            try:
                self.redis_cache = redis.from_url(
                    self.config["REDIS_URL"],
                    decode_responses=True,
                    socket_connect_timeout=5,
                    socket_timeout=5,
                    retry_on_timeout=True,
                )
                # Test connection
                self.redis_cache.ping()
                self.logger.info("Redis cache initialized successfully")
            except Exception as e:
                self.logger.warning(f"Failed to initialize Redis cache: {e}")
                self.redis_cache = None

    def _generate_key(self, prefix: str, *args, **kwargs) -> str:
        """Generate cache key from arguments."""
        key_parts = [prefix]

        # Add positional arguments
        for arg in args:
            if isinstance(arg, (str, int, float, bool)):
                key_parts.append(str(arg))
            else:
                # Hash complex objects
                key_parts.append(hashlib.md5(str(arg).encode()).hexdigest()[:8])

        # Add keyword arguments
        for k, v in sorted(kwargs.items()):
            if isinstance(v, (str, int, float, bool)):
                key_parts.append(f"{k}:{v}")
            else:
                key_parts.append(f"{k}:{hashlib.md5(str(v).encode()).hexdigest()[:8]}")

        return ":".join(key_parts)

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache (tries Redis first, then memory)."""
        # Try Redis first
        if self.redis_cache:
            try:
                value = self.redis_cache.get(key)
                if value is not None:
                    # Also store in memory cache for faster access
                    import json

                    try:
                        parsed_value = json.loads(value)
                        self.memory_cache.set(
                            key, parsed_value, ttl=60
                        )  # Short TTL for memory
                        return parsed_value
                    except json.JSONDecodeError:
                        return value
            except Exception as e:
                self.logger.warning(f"Redis get failed: {e}")

        # Fallback to memory cache
        return self.memory_cache.get(key)

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in cache (both Redis and memory)."""
        success = False

        # Set in Redis
        if self.redis_cache:
            try:
                import json

                serialized_value = json.dumps(value, default=str)
                if ttl:
                    success = self.redis_cache.setex(key, ttl, serialized_value)
                else:
                    success = self.redis_cache.set(key, serialized_value)
            except Exception as e:
                self.logger.warning(f"Redis set failed: {e}")

        # Set in memory cache
        memory_success = self.memory_cache.set(key, value, ttl)

        return success or memory_success

    def delete(self, key: str) -> bool:
        """Delete key from all caches."""
        redis_success = False
        if self.redis_cache:
            try:
                redis_success = bool(self.redis_cache.delete(key))
            except Exception as e:
                self.logger.warning(f"Redis delete failed: {e}")

        memory_success = self.memory_cache.delete(key)
        return redis_success or memory_success

    def clear(self):
        """Clear all caches."""
        if self.redis_cache:
            try:
                self.redis_cache.flushdb()
            except Exception as e:
                self.logger.warning(f"Redis clear failed: {e}")

        self.memory_cache.clear()

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        stats = {"memory_cache": self.memory_cache.get_stats()}

        if self.redis_cache:
            try:
                redis_info = self.redis_cache.info()
                stats["redis_cache"] = {
                    "connected": True,
                    "used_memory_mb": redis_info.get("used_memory", 0) / (1024 * 1024),
                    "keyspace_hits": redis_info.get("keyspace_hits", 0),
                    "keyspace_misses": redis_info.get("keyspace_misses", 0),
                    "connected_clients": redis_info.get("connected_clients", 0),
                }
            except Exception as e:
                stats["redis_cache"] = {"connected": False, "error": str(e)}
        else:
            stats["redis_cache"] = {"connected": False}

        return stats


class HTTPConnectionPool:
    """Optimized HTTP connection pool for external API calls."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        if not REQUESTS_AVAILABLE:
            self.logger.warning(
                "Requests library not available. HTTP optimization disabled."
            )
            self.session = None
            return

        # Create optimized session
        self.session = requests.Session()

        # Configure retry strategy
        retry_strategy = Retry(
            total=self.config.get("HTTP_RETRIES", 3),
            backoff_factor=self.config.get("HTTP_BACKOFF_FACTOR", 0.3),
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST"],
        )

        # Configure HTTP adapter
        adapter = HTTPAdapter(
            pool_connections=self.config.get("HTTP_POOL_CONNECTIONS", 10),
            pool_maxsize=self.config.get("HTTP_POOL_MAXSIZE", 20),
            max_retries=retry_strategy,
            pool_block=False,
        )

        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Set default timeouts
        self.default_timeout = (
            self.config.get("HTTP_CONNECT_TIMEOUT", 5),
            self.config.get("HTTP_READ_TIMEOUT", 30),
        )

        # Set default headers
        self.session.headers.update(
            {
                "User-Agent": self.config.get("USER_AGENT", "GST-Verification-API/1.0"),
                "Accept": "application/json, text/html, */*",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
            }
        )

    def get(self, url: str, **kwargs) -> requests.Response:
        """Optimized GET request."""
        if not self.session:
            raise RuntimeError("HTTP session not available")

        kwargs.setdefault("timeout", self.default_timeout)
        return self.session.get(url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        """Optimized POST request."""
        if not self.session:
            raise RuntimeError("HTTP session not available")

        kwargs.setdefault("timeout", self.default_timeout)
        return self.session.post(url, **kwargs)

    def close(self):
        """Close the session and cleanup connections."""
        if self.session:
            self.session.close()


class PerformanceMonitor:
    """Monitor and track performance metrics."""

    def __init__(self):
        self.metrics = defaultdict(list)
        self.lock = threading.Lock()
        self.logger = logging.getLogger(__name__)

    def record_timing(
        self, operation: str, duration: float, metadata: Optional[Dict[str, Any]] = None
    ):
        """Record timing for an operation."""
        with self.lock:
            self.metrics[operation].append(
                {
                    "duration": duration,
                    "timestamp": datetime.utcnow(),
                    "metadata": metadata or {},
                }
            )

            # Keep only recent metrics (last 1000 per operation)
            if len(self.metrics[operation]) > 1000:
                self.metrics[operation] = self.metrics[operation][-1000:]

    def get_stats(self, operation: Optional[str] = None) -> Dict[str, Any]:
        """Get performance statistics."""
        with self.lock:
            if operation:
                return self._calculate_stats(operation, self.metrics[operation])

            stats = {}
            for op, timings in self.metrics.items():
                stats[op] = self._calculate_stats(op, timings)

            return stats

    def _calculate_stats(
        self, operation: str, timings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Calculate statistics for a set of timings."""
        if not timings:
            return {"count": 0}

        durations = [t["duration"] for t in timings]
        durations.sort()

        count = len(durations)
        total = sum(durations)
        avg = total / count

        # Calculate percentiles
        p50_idx = int(count * 0.5)
        p95_idx = int(count * 0.95)
        p99_idx = int(count * 0.99)

        return {
            "operation": operation,
            "count": count,
            "total_time": total,
            "avg_time": avg,
            "min_time": min(durations),
            "max_time": max(durations),
            "p50_time": durations[p50_idx] if p50_idx < count else durations[-1],
            "p95_time": durations[p95_idx] if p95_idx < count else durations[-1],
            "p99_time": durations[p99_idx] if p99_idx < count else durations[-1],
            "recent_avg": sum(durations[-10:]) / min(10, count),  # Last 10 requests
        }


class AsyncProcessor:
    """Asynchronous processing for non-blocking operations."""

    def __init__(self, max_workers: int = 5):
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.logger = logging.getLogger(__name__)
        self.pending_tasks = {}
        self.completed_tasks = {}
        self.task_counter = 0
        self.lock = threading.Lock()

    def submit_task(self, func: Callable, *args, **kwargs) -> str:
        """Submit a task for asynchronous execution."""
        with self.lock:
            task_id = f"task_{self.task_counter}"
            self.task_counter += 1

        future = self.executor.submit(func, *args, **kwargs)

        with self.lock:
            self.pending_tasks[task_id] = {
                "future": future,
                "submitted_at": datetime.utcnow(),
                "function": func.__name__,
            }

        # Add callback to move completed tasks
        future.add_done_callback(lambda f: self._task_completed(task_id, f))

        return task_id

    def _task_completed(self, task_id: str, future):
        """Handle task completion."""
        with self.lock:
            if task_id in self.pending_tasks:
                task_info = self.pending_tasks.pop(task_id)

                try:
                    result = future.result()
                    self.completed_tasks[task_id] = {
                        "result": result,
                        "completed_at": datetime.utcnow(),
                        "duration": (
                            datetime.utcnow() - task_info["submitted_at"]
                        ).total_seconds(),
                        "function": task_info["function"],
                        "status": "success",
                    }
                except Exception as e:
                    self.completed_tasks[task_id] = {
                        "error": str(e),
                        "completed_at": datetime.utcnow(),
                        "duration": (
                            datetime.utcnow() - task_info["submitted_at"]
                        ).total_seconds(),
                        "function": task_info["function"],
                        "status": "error",
                    }
                    self.logger.error(f"Async task {task_id} failed: {e}")

    def get_task_status(self, task_id: str) -> Dict[str, Any]:
        """Get status of a task."""
        with self.lock:
            if task_id in self.pending_tasks:
                task_info = self.pending_tasks[task_id]
                return {
                    "status": "pending",
                    "submitted_at": task_info["submitted_at"].isoformat(),
                    "function": task_info["function"],
                }
            elif task_id in self.completed_tasks:
                return self.completed_tasks[task_id]
            else:
                return {"status": "not_found"}

    def get_task_result(self, task_id: str, timeout: Optional[float] = None) -> Any:
        """Get result of a completed task."""
        with self.lock:
            if task_id in self.completed_tasks:
                task_info = self.completed_tasks[task_id]
                if task_info["status"] == "success":
                    return task_info["result"]
                else:
                    raise Exception(task_info["error"])
            elif task_id in self.pending_tasks:
                future = self.pending_tasks[task_id]["future"]

        if "future" in locals():
            return future.result(timeout=timeout)
        else:
            raise ValueError(f"Task {task_id} not found")

    def cleanup_completed_tasks(self, max_age_hours: int = 24):
        """Clean up old completed tasks."""
        cutoff_time = datetime.utcnow() - timedelta(hours=max_age_hours)

        with self.lock:
            to_remove = [
                task_id
                for task_id, task_info in self.completed_tasks.items()
                if task_info["completed_at"] < cutoff_time
            ]

            for task_id in to_remove:
                del self.completed_tasks[task_id]

    def get_stats(self) -> Dict[str, Any]:
        """Get async processor statistics."""
        with self.lock:
            return {
                "pending_tasks": len(self.pending_tasks),
                "completed_tasks": len(self.completed_tasks),
                "total_tasks": self.task_counter,
                "executor_stats": {
                    "max_workers": self.executor._max_workers,
                    "active_threads": len(self.executor._threads),
                },
            }

    def shutdown(self, wait: bool = True):
        """Shutdown the async processor."""
        self.executor.shutdown(wait=wait)


def cached(ttl: int = 300, key_prefix: str = "cached"):
    """Decorator for caching function results."""

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Get cache manager from global context or create one
            cache_manager = getattr(wrapper, "_cache_manager", None)
            if cache_manager is None:
                cache_manager = CacheManager()
                wrapper._cache_manager = cache_manager

            # Generate cache key
            cache_key = cache_manager._generate_key(
                key_prefix, func.__name__, *args, **kwargs
            )

            # Try to get from cache
            cached_result = cache_manager.get(cache_key)
            if cached_result is not None:
                return cached_result

            # Execute function and cache result
            result = func(*args, **kwargs)
            cache_manager.set(cache_key, result, ttl=ttl)

            return result

        return wrapper

    return decorator


def timed(monitor: Optional[PerformanceMonitor] = None):
    """Decorator for timing function execution."""

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()

            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time

                # Record timing
                perf_monitor = monitor or getattr(wrapper, "_monitor", None)
                if perf_monitor is None:
                    perf_monitor = PerformanceMonitor()
                    wrapper._monitor = perf_monitor

                perf_monitor.record_timing(func.__name__, duration)

                return result

            except Exception as e:
                duration = time.time() - start_time

                # Record failed timing
                perf_monitor = monitor or getattr(wrapper, "_monitor", None)
                if perf_monitor:
                    perf_monitor.record_timing(
                        f"{func.__name__}_failed", duration, {"error": str(e)}
                    )

                raise

        return wrapper

    return decorator


# Global instances
cache_manager = None
http_pool = None
performance_monitor = None
async_processor = None


def initialize_performance_optimizations(config: Optional[Dict[str, Any]] = None):
    """Initialize all performance optimization components."""
    global cache_manager, http_pool, performance_monitor, async_processor

    config = config or {}

    # Initialize cache manager
    cache_manager = CacheManager(config)

    # Initialize HTTP connection pool
    http_pool = HTTPConnectionPool(config)

    # Initialize performance monitor
    performance_monitor = PerformanceMonitor()

    # Initialize async processor
    async_processor = AsyncProcessor(max_workers=config.get("ASYNC_MAX_WORKERS", 5))

    return {
        "cache_manager": cache_manager,
        "http_pool": http_pool,
        "performance_monitor": performance_monitor,
        "async_processor": async_processor,
    }


def get_performance_stats() -> Dict[str, Any]:
    """Get comprehensive performance statistics."""
    stats = {}

    if cache_manager:
        stats["cache"] = cache_manager.get_stats()

    if performance_monitor:
        stats["performance"] = performance_monitor.get_stats()

    if async_processor:
        stats["async_processing"] = async_processor.get_stats()

    return stats


if __name__ == "__main__":
    # Example usage
    components = initialize_performance_optimizations(
        {
            "REDIS_URL": "redis://localhost:6379/0",
            "HTTP_POOL_CONNECTIONS": 10,
            "HTTP_POOL_MAXSIZE": 20,
            "ASYNC_MAX_WORKERS": 5,
        }
    )

    # Test caching
    @cached(ttl=60, key_prefix="test")
    def expensive_operation(x, y):
        time.sleep(0.1)  # Simulate expensive operation
        return x + y

    # Test timing
    @timed()
    def timed_operation():
        time.sleep(0.05)
        return "completed"

    # Run tests
    print("Testing caching...")
    result1 = expensive_operation(1, 2)  # Should be slow
    result2 = expensive_operation(1, 2)  # Should be fast (cached)

    print("Testing timing...")
    timed_operation()

    # Test async processing
    print("Testing async processing...")
    task_id = async_processor.submit_task(expensive_operation, 5, 10)
    print(f"Submitted task: {task_id}")

    # Wait for completion
    time.sleep(0.2)
    result = async_processor.get_task_result(task_id)
    print(f"Async result: {result}")

    # Get performance stats
    stats = get_performance_stats()
    print("\nPerformance Statistics:")
    for component, component_stats in stats.items():
        print(f"{component}: {component_stats}")

    # Cleanup
    if http_pool:
        http_pool.close()
    if async_processor:
        async_processor.shutdown()
