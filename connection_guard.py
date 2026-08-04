"""
Connection Guard
Continuous mid-scan monitoring.
Detects blocks, rotates connections automatically.
Runs alongside scan agents.
"""

import os
import time
import threading
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, 'monitor_logs.txt')


def write_log(message, level='INFO'):
    """Write to monitor log file."""
    timestamp = datetime.now().strftime('%H:%M:%S')
    prefix = {
        'INFO': '[INFO]',
        'WARN': '[WARN]',
        'ERROR': '[ERROR]',
        'SUCCESS': '[OK]',
        'CRITICAL': '[CRITICAL]',
        'SCAN': '[SCAN]',
        'AGENT': '[AGENT]',
        'CONNECT': '[CONN]',
        'SECURITY': '[SEC]',
        'GUARD': '[GUARD]',
        'BLOCK': '[BLOCK]',
        'ROTATE': '[ROTATE]',
    }.get(level, '[INFO]')

    log_line = f"{timestamp} {prefix} {message}\n"
    try:
        with open(
            LOG_FILE, 'a', encoding='utf-8'
        ) as f:
            f.write(log_line)
    except Exception:
        pass


class ConnectionGuard:
    """
    Monitors all HTTP requests in real-time.
    Detects blocks and auto-rotates connection.

    Usage:
        guard = ConnectionGuard(smart_conn)
        session = guard.get_session()
        # Use session for all requests
        # Guard monitors automatically
    """

    def __init__(self, smart_connection=None):
        self.smart_conn = smart_connection
        self.session = None

        # Counters
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.blocked_requests = 0
        self.timeout_requests = 0
        self.rotations = 0

        # Thresholds
        self.block_threshold = 3
        self.timeout_threshold = 5
        self.consecutive_fails = 0
        self.consecutive_timeouts = 0

        # State
        self.is_blocked = False
        self.current_method = 'direct'
        self.risk_level = 'LOW'
        self.last_status = 200
        self.last_check_time = time.time()

        # Block indicators
        self.block_status_codes = [
            403, 429, 503, 520, 521, 522, 523
        ]
        self.block_body_keywords = [
            'access denied',
            'blocked',
            'rate limit',
            'too many requests',
            'captcha',
            'cloudflare',
            'please wait',
            'security check',
            'bot detection',
            'automated',
            'suspicious activity',
            'ip has been blocked',
            'temporarily banned',
        ]

        # Lock for thread safety
        self._lock = threading.Lock()

        # Background health checker
        self._running = True
        self._health_thread = threading.Thread(
            target=self._health_check_loop,
            daemon=True
        )

    def init_session(self, session=None):
        """Initialize with existing session."""
        if session:
            self.session = session
        elif self.smart_conn:
            self.session = self.smart_conn.session
            self.current_method = (
                self.smart_conn.selected_method
            )
        else:
            import requests
            self.session = requests.Session()
            self.session.headers.update({
                'User-Agent': (
                    'Mozilla/5.0 '
                    '(Windows NT 10.0; Win64; x64)'
                )
            })
            self.current_method = 'direct'

        write_log(
            f'Guard initialized. '
            f'Method: {self.current_method}',
            'GUARD'
        )
        return self.session

    def start(self):
        """Start background health monitoring."""
        self._health_thread.start()
        write_log(
            'Connection guard active',
            'GUARD'
        )

    def stop(self):
        """Stop guard."""
        self._running = False

    def get_session(self):
        """Get the guarded session."""
        if not self.session:
            self.init_session()
        return GuardedSession(self)

    def _health_check_loop(self):
        """
        Background thread.
        Periodically checks connection health.
        """
        while self._running:
            time.sleep(30)
            try:
                self._periodic_health_check()
            except Exception:
                pass

    def _periodic_health_check(self):
        """Check if connection is still healthy."""
        if not self.session:
            return

        with self._lock:
            elapsed = (
                time.time() - self.last_check_time
            )

            # If no requests in 60s, skip check
            if elapsed < 60:
                return

            # Calculate failure rate
            if self.total_requests > 10:
                fail_rate = (
                    self.failed_requests
                    / self.total_requests
                    * 100
                )
                if fail_rate > 30:
                    write_log(
                        f'High failure rate: '
                        f'{fail_rate:.0f}% '
                        f'({self.failed_requests}/'
                        f'{self.total_requests})',
                        'WARN'
                    )

            # Log periodic status
            write_log(
                f'Guard status: '
                f'Reqs={self.total_requests} '
                f'OK={self.successful_requests} '
                f'Fail={self.failed_requests} '
                f'Block={self.blocked_requests} '
                f'Rotations={self.rotations}',
                'GUARD'
            )

    def check_response(self, response, url=''):
        """
        Check if response indicates blocking.
        Called after EVERY request.
        Returns: True if OK, False if blocked.
        """
        with self._lock:
            self.total_requests += 1
            self.last_check_time = time.time()
            self.last_status = response.status_code

            # Check status code
            if response.status_code in (
                self.block_status_codes
            ):
                self._handle_block(
                    'status_code',
                    response.status_code,
                    url
                )
                return False

            # Check response body for block keywords
            try:
                body_lower = (
                    response.text[:2000].lower()
                )
                for keyword in (
                    self.block_body_keywords
                ):
                    if keyword in body_lower:
                        self._handle_block(
                            'body_keyword',
                            keyword,
                            url
                        )
                        return False
            except Exception:
                pass

            # Success
            self.successful_requests += 1
            self.consecutive_fails = 0
            self.consecutive_timeouts = 0
            self.is_blocked = False
            return True

    def check_timeout(self, url=''):
        """Called when request times out."""
        with self._lock:
            self.total_requests += 1
            self.timeout_requests += 1
            self.consecutive_timeouts += 1

            write_log(
                f'Timeout #{self.consecutive_timeouts}'
                f' on {url[:50]}',
                'WARN'
            )

            if (
                self.consecutive_timeouts
                >= self.timeout_threshold
            ):
                write_log(
                    f'Timeout threshold reached '
                    f'({self.timeout_threshold}). '
                    f'Rotating...',
                    'BLOCK'
                )
                self._rotate_connection(
                    'consecutive_timeouts'
                )

    def check_error(self, error, url=''):
        """Called when request raises exception."""
        with self._lock:
            self.total_requests += 1
            self.failed_requests += 1
            self.consecutive_fails += 1

            error_str = str(error).lower()

            # Connection reset = likely blocked
            reset_indicators = [
                'connection reset',
                'connection refused',
                'connection aborted',
                'remote end closed',
                'broken pipe',
                'forcibly closed',
            ]

            is_reset = any(
                ind in error_str
                for ind in reset_indicators
            )

            if is_reset:
                write_log(
                    f'Connection reset detected: '
                    f'{str(error)[:80]}',
                    'BLOCK'
                )
                self._handle_block(
                    'connection_reset',
                    str(error)[:80],
                    url
                )
            elif (
                self.consecutive_fails
                >= self.block_threshold
            ):
                write_log(
                    f'Consecutive failures: '
                    f'{self.consecutive_fails}. '
                    f'Rotating...',
                    'BLOCK'
                )
                self._rotate_connection(
                    'consecutive_failures'
                )

    def _handle_block(
        self, block_type, detail, url=''
    ):
        """Handle detected block."""
        self.blocked_requests += 1
        self.consecutive_fails += 1
        self.is_blocked = True

        write_log(
            f'BLOCK DETECTED! '
            f'Type: {block_type} '
            f'Detail: {detail} '
            f'URL: {url[:50]}',
            'BLOCK'
        )

        if (
            self.consecutive_fails
            >= self.block_threshold
        ):
            write_log(
                f'Block threshold reached '
                f'({self.block_threshold}). '
                f'Auto-rotating...',
                'BLOCK'
            )
            self._rotate_connection(block_type)

    def _rotate_connection(self, reason):
        """Rotate to different connection method."""
        self.rotations += 1
        old_method = self.current_method

        write_log(
            f'Rotation #{self.rotations} '
            f'triggered by: {reason}',
            'ROTATE'
        )

        if self.smart_conn:
            new_session = self.smart_conn.rotate()
            if new_session:
                self.session = new_session
                self.current_method = (
                    self.smart_conn.selected_method
                )
                write_log(
                    f'Rotated: {old_method} → '
                    f'{self.current_method}',
                    'ROTATE'
                )
            else:
                write_log(
                    'Rotation failed - no '
                    'alternative available',
                    'ERROR'
                )

                # Add delay before retry
                delay = min(
                    30, 5 * self.rotations
                )
                write_log(
                    f'Waiting {delay}s before '
                    f'retrying...',
                    'GUARD'
                )
                time.sleep(delay)
        else:
            write_log(
                'No SmartConnection - cannot rotate',
                'WARN'
            )
            # Add delay
            delay = min(
                30, 5 * self.consecutive_fails
            )
            write_log(
                f'Waiting {delay}s before retry...',
                'GUARD'
            )
            time.sleep(delay)

        # Reset counters after rotation
        self.consecutive_fails = 0
        self.consecutive_timeouts = 0
        self.is_blocked = False

    def get_stats(self):
        """Get current guard statistics."""
        return {
            'total_requests': self.total_requests,
            'successful': self.successful_requests,
            'failed': self.failed_requests,
            'blocked': self.blocked_requests,
            'timeouts': self.timeout_requests,
            'rotations': self.rotations,
            'current_method': self.current_method,
            'is_blocked': self.is_blocked,
            'consecutive_fails': (
                self.consecutive_fails
            ),
        }


class GuardedSession:
    """
    Wraps requests.Session.
    Intercepts every request for guard checking.
    Drop-in replacement for requests.Session.
    """

    def __init__(self, guard):
        self.guard = guard
        self.session = guard.session
        self.headers = self.session.headers
        self.cookies = self.session.cookies
        self.proxies = (
            getattr(self.session, 'proxies', {})
        )

    def get(self, url, **kwargs):
        """Guarded GET request."""
        return self._request('GET', url, **kwargs)

    def post(self, url, **kwargs):
        """Guarded POST request."""
        return self._request('POST', url, **kwargs)

    def put(self, url, **kwargs):
        """Guarded PUT request."""
        return self._request('PUT', url, **kwargs)

    def delete(self, url, **kwargs):
        """Guarded DELETE request."""
        return self._request(
            'DELETE', url, **kwargs
        )

    def head(self, url, **kwargs):
        """Guarded HEAD request."""
        return self._request('HEAD', url, **kwargs)

    def options(self, url, **kwargs):
        """Guarded OPTIONS request."""
        return self._request(
            'OPTIONS', url, **kwargs
        )

    def patch(self, url, **kwargs):
        """Guarded PATCH request."""
        return self._request(
            'PATCH', url, **kwargs
        )

    def request(self, method, url, **kwargs):
        """Guarded generic request."""
        return self._request(method, url, **kwargs)

    def _request(self, method, url, **kwargs):
        """
        Execute request with guard monitoring.
        Auto-retry on block detection.
        """
        max_retries = 3
        retry_count = 0

        while retry_count < max_retries:
            try:
                # Refresh session reference
                # (may have changed after rotation)
                self.session = self.guard.session

                response = self.session.request(
                    method, url, **kwargs
                )

                # Check response with guard
                is_ok = self.guard.check_response(
                    response, url
                )

                if is_ok:
                    return response

                # Blocked - guard will rotate
                retry_count += 1
                if retry_count < max_retries:
                    write_log(
                        f'Retrying ({retry_count}/'
                        f'{max_retries}): '
                        f'{url[:50]}',
                        'GUARD'
                    )
                    time.sleep(2 * retry_count)
                else:
                    # Return last response even
                    # if blocked (let agent handle)
                    write_log(
                        f'Max retries reached for: '
                        f'{url[:50]}',
                        'WARN'
                    )
                    return response

            except Exception as e:
                error_str = str(e).lower()

                if 'timeout' in error_str:
                    self.guard.check_timeout(url)
                else:
                    self.guard.check_error(e, url)

                retry_count += 1
                if retry_count < max_retries:
                    write_log(
                        f'Error retry ({retry_count}/'
                        f'{max_retries}): '
                        f'{str(e)[:60]}',
                        'GUARD'
                    )
                    # Refresh session after rotation
                    self.session = self.guard.session
                    time.sleep(2 * retry_count)
                else:
                    raise

    def close(self):
        """Close session."""
        if self.session:
            self.session.close()
