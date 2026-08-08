import time
import threading
import requests
from datetime import datetime

WAF_SIGNATURES = [
    'cloudflare', 'attention required', 'security check',
    'access denied', 'forbidden', 'blocked by',
    'firewall', 'sucuri', 'incapsula', 'akamai',
    'ddos protection', 'ray id', 'this website is using a security',
    'you have been blocked', 'security incident'
]

BLOCK_STATUSES = [403, 406, 429, 503]

class GuardedSession:
    def __init__(self, inner_session, guard, log_writer=None):
        self._inner = inner_session
        self.guard = guard
        self.log_writer = log_writer
        self.headers = inner_session.headers
        self.proxies = getattr(inner_session, 'proxies', {})

    def _w(self, msg, lvl='INFO'):
        if self.log_writer:
            try: self.log_writer(msg, lvl)
            except: pass

    def request(self, method, url, **kwargs):
        # Auto set timeout
        kwargs.setdefault('timeout', 15)
        # Count
        self.guard._inc('total_requests')

        try:
            resp = self._inner.request(method, url, **kwargs)
            # Check WAF block
            if self.guard._is_blocked_response(resp):
                self.guard._inc('blocked')
                self.guard.consecutive_blocks += 1
                self.guard.consecutive_timeouts = 0
                body_low = resp.text[:2000].lower() if hasattr(resp,'text') else ''
                self._w(f'FIREWALL BLOCK [{resp.status_code}] URL:{url[:70]}', 'BLOCK')
                self._w(f'Response hint: {body_low[:100]}', 'BLOCK')
                self.guard._check_and_rotate()
                return resp
            else:
                # Success
                if 200 <= resp.status_code < 400:
                    self.guard._inc('successful')
                    self.guard.consecutive_blocks = 0
                    self.guard.consecutive_timeouts = 0
                else:
                    self.guard._inc('failed')
                return resp

        except (requests.exceptions.Timeout,
                requests.exceptions.ConnectTimeout,
                requests.exceptions.ReadTimeout) as e:
            self.guard._inc('timeouts')
            self.guard.consecutive_timeouts += 1
            self.guard.consecutive_blocks = 0
            self._w(f'Timeout [{method}] {url[:70]} - {e}', 'WARN')
            self.guard._check_and_rotate()
            raise

        except requests.exceptions.ConnectionError as e:
            self.guard._inc('timeouts')
            self.guard.consecutive_timeouts += 1
            self._w(f'Connection error {url[:70]} - {e}', 'WARN')
            self.guard._check_and_rotate()
            raise

        except Exception as e:
            self.guard._inc('failed')
            self._w(f'Request failed {e}', 'ERROR')
            raise

    def get(self, url, **kwargs): return self.request('GET', url, **kwargs)
    def post(self, url, **kwargs): return self.request('POST', url, **kwargs)
    def put(self, url, **kwargs): return self.request('PUT', url, **kwargs)
    def delete(self, url, **kwargs): return self.request('DELETE', url, **kwargs)
    def head(self, url, **kwargs): return self.request('HEAD', url, **kwargs)
    def patch(self, url, **kwargs): return self.request('PATCH', url, **kwargs)
    def options(self, url, **kwargs): return self.request('OPTIONS', url, **kwargs)

class ConnectionGuard:
    def __init__(self, smart_connection=None, log_writer=None):
        self.smart_conn = smart_connection
        self.log_writer = log_writer
        self._session = None
        self.guarded_session = None
        self.risk_level = 'LOW'
        self.block_threshold = 5
        self.timeout_threshold = 7
        self.running = False
        self.monitor_thread = None

        self._lock = threading.Lock()
        self.total_requests = 0
        self.successful = 0
        self.failed = 0
        self.blocked = 0
        self.timeouts = 0
        self.rotations = 0
        self.consecutive_blocks = 0
        self.consecutive_timeouts = 0

    def _w(self, msg, lvl='GUARD'):
        if self.log_writer:
            try: self.log_writer(msg, lvl)
            except: pass

    def _inc(self, key):
        with self._lock:
            if key == 'total_requests': self.total_requests+=1
            elif key == 'successful': self.successful+=1
            elif key == 'failed': self.failed+=1
            elif key == 'blocked': self.blocked+=1
            elif key == 'timeouts': self.timeouts+=1

    def init_session(self, raw_session):
        self._session = raw_session
        self.guarded_session = GuardedSession(raw_session, self, self.log_writer)
        self._w(f'Guard initialized. Method: {getattr(self.smart_conn,"selected_method","direct")}', 'GUARD')

    def get_session(self):
        if not self.guarded_session:
            # If no init, create direct
            s = requests.Session()
            self._session = s
            self.guarded_session = GuardedSession(s, self, self.log_writer)
        return self.guarded_session

    def _is_blocked_response(self, resp):
        if resp.status_code in BLOCK_STATUSES:
            # Additional check for 403/503 to avoid false positives
            if resp.status_code == 403:
                return True
            if resp.status_code == 429:
                return True
            # For 406, 503 check body contains WAF signature
            body = resp.text.lower() if hasattr(resp,'text') else ''
            if any(sig in body for sig in WAF_SIGNATURES):
                return True
            if resp.status_code in [406, 503]:
                return True
        else:
            # Even 200 can be WAF challenge page
            body = resp.text.lower() if hasattr(resp,'text') else ''
            if any(sig in body for sig in WAF_SIGNATURES):
                # Check if body is small (challenge page)
                if len(body) < 5000 and 'cloudflare' in body:
                    return True
        return False

    def _check_and_rotate(self):
        # Check if need to rotate
        should_rotate = False
        reason = ''
        if self.consecutive_blocks >= self.block_threshold:
            should_rotate = True
            reason = f'Block threshold reached ({self.consecutive_blocks}/{self.block_threshold})'
        elif self.consecutive_timeouts >= self.timeout_threshold:
            should_rotate = True
            reason = f'Timeout threshold ({self.consecutive_timeouts}/{self.timeout_threshold})'

        if should_rotate:
            self._w(f'BLOCK DETECTED: {reason} - Auto rotating...', 'BLOCK')
            self.rotate()

    def rotate(self):
        with self._lock:
            self.rotations += 1
            self.consecutive_blocks = 0
            self.consecutive_timeouts = 0

        self._w(f'Rotating connection... #{self.rotations}', 'ROTATE')

        try:
            if self.smart_conn and hasattr(self.smart_conn, 'rotate'):
                new_sess = self.smart_conn.rotate()
                if new_sess:
                    self._session = new_sess
                    self.guarded_session = GuardedSession(new_sess, self, self.log_writer)
                    self._w(f'Rotated to {self.smart_conn.selected_method.upper()}', 'ROTATE')
                    return True
        except Exception as e:
            self._w(f'Rotate failed: {e}', 'ERROR')

        # Fallback: new direct session with new UA
        from smart_connection import random_headers
        s = requests.Session()
        s.headers.update(random_headers())
        self._session = s
        self.guarded_session = GuardedSession(s, self, self.log_writer)
        self._w('Fallback to new DIRECT session with new fingerprint', 'ROTATE')
        return True

    def get_stats(self):
        with self._lock:
            return {
                'total_requests': self.total_requests,
                'successful': self.successful,
                'failed': self.failed,
                'blocked': self.blocked,
                'timeouts': self.timeouts,
                'rotations': self.rotations
            }

    def start(self):
        self.running = True
        def _monitor():
            while self.running:
                time.sleep(60)  # Log every 60 sec, not 30
                if not self.running:
                    break
                stats = self.get_stats()
                if stats['total_requests'] > 0:  # Only log if requests happened
                    self._w(f"Guard status: Reqs={stats['total_requests']} OK={stats['successful']} Fail={stats['failed']} Block={stats['blocked']} Rotations={stats['rotations']}", 'GUARD')

        self.monitor_thread = threading.Thread(target=_monitor, daemon=True)
        self.monitor_thread.start()
        self._w('Connection guard active (background monitor ON)', 'GUARD')

    def stop(self):
        self.running = False
