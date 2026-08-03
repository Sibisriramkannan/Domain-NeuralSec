import io
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

init(autoreset=True)


class FileUploadAgent:
    def __init__(self, target_url, session=None):
        self.target = target_url
        self.session = session or requests.Session()
        self.session.headers.update({
            'User-Agent': (
                'SecurityAudit/1.0 '
                '(Authorized Assessment)'
            )
        })
        self.findings = []

    def discover_upload_endpoints(self):
        print(
            f"  {Fore.CYAN}[*] Discovering upload "
            f"endpoints...{Style.RESET_ALL}"
        )
        upload_paths = [
            '/upload', '/file-upload',
            '/api/upload', '/api/file',
            '/upload/image', '/upload/file',
            '/profile/upload', '/avatar',
            '/media/upload', '/document/upload',
            '/attachment', '/files/upload',
            '/api/v1/upload', '/api/v2/upload',
            '/import', '/api/import',
        ]

        found = []
        for path in upload_paths:
            url = urljoin(self.target, path)
            try:
                r = self.session.get(
                    url, timeout=8,
                    allow_redirects=False
                )
                if r.status_code in [
                    200, 401, 403, 405
                ]:
                    found.append({
                        'url': url,
                        'status': r.status_code,
                        'method_not_allowed': (
                            r.status_code == 405
                        )
                    })
                    print(
                        f"  {Fore.GREEN}[+] Found: "
                        f"{url} [{r.status_code}]"
                        f"{Style.RESET_ALL}"
                    )
            except Exception:
                pass

        # Check page source for upload forms
        try:
            r = self.session.get(
                self.target, timeout=10
            )
            soup = BeautifulSoup(
                r.text, 'html.parser'
            )
            forms = soup.find_all('form')
            for form in forms:
                inputs = form.find_all('input')
                for inp in inputs:
                    if inp.get('type') == 'file':
                        action = form.get(
                            'action', self.target
                        )
                        if not action.startswith('http'):
                            action = urljoin(
                                self.target, action
                            )
                        found.append({
                            'url': action,
                            'status': 200,
                            'from_form': True,
                            'accept': inp.get(
                                'accept', 'any'
                            )
                        })
        except Exception:
            pass

        return found

    def test_dangerous_extensions(self, endpoints):
        print(
            f"  {Fore.CYAN}[*] Testing dangerous "
            f"file extensions...{Style.RESET_ALL}"
        )
        dangerous_extensions = [
            ('.php', 'application/octet-stream'),
            ('.php5', 'application/octet-stream'),
            ('.phtml', 'application/octet-stream'),
            ('.asp', 'application/octet-stream'),
            ('.aspx', 'application/octet-stream'),
            ('.jsp', 'application/octet-stream'),
            ('.sh', 'application/octet-stream'),
        ]

        safe_content = b'<?php echo "test"; ?>'

        for endpoint in endpoints[:3]:
            url = endpoint['url']
            for ext, content_type in (
                dangerous_extensions[:4]
            ):
                filename = f"test_audit{ext}"
                try:
                    files = {
                        'file': (
                            filename,
                            io.BytesIO(safe_content),
                            content_type
                        )
                    }
                    r = self.session.post(
                        url, files=files, timeout=10
                    )
                    if r.status_code in [200, 201]:
                        resp_lower = r.text.lower()
                        if any(
                            k in resp_lower for k in [
                                'success', 'uploaded',
                                'saved', 'created',
                                filename.lower()
                            ]
                        ):
                            self.findings.append({
                                'type': (
                                    'Dangerous File '
                                    'Upload Accepted'
                                ),
                                'category': (
                                    'file_upload'
                                ),
                                'risk': 'CRITICAL',
                                'url': url,
                                'extension': ext,
                                'description': (
                                    f'Server accepted '
                                    f'{ext} file upload. '
                                    f'RCE possible.'
                                ),
                                'business_impact': (
                                    'Attacker uploads webshell '
                                    'and achieves remote code '
                                    'execution on server'
                                ),
                                'fix': (
                                    '1. Whitelist allowed '
                                    'extensions only\n'
                                    '2. Validate MIME type '
                                    'server-side\n'
                                    '3. Rename uploaded files\n'
                                    '4. Store outside webroot\n'
                                    '5. Scan uploads for malware'
                                ),
                                'cvss_score': 9.8,
                                'cwe': 'CWE-434'
                            })
                            print(
                                f"  {Fore.RED}"
                                f"[!!!] DANGEROUS UPLOAD: "
                                f"{ext} accepted"
                                f"{Style.RESET_ALL}"
                            )
                            break
                except Exception:
                    pass

        return self.findings

    def test_content_type_bypass(self, endpoints):
        print(
            f"  {Fore.CYAN}[*] Testing content-type "
            f"bypass...{Style.RESET_ALL}"
        )
        php_content = b'<?php phpinfo(); ?>'

        for endpoint in endpoints[:3]:
            url = endpoint['url']
            try:
                # Try with image content-type
                files = {
                    'file': (
                        'image.jpg',
                        io.BytesIO(php_content),
                        'image/jpeg'
                    )
                }
                r = self.session.post(
                    url, files=files, timeout=10
                )
                if r.status_code in [200, 201]:
                    resp_lower = r.text.lower()
                    if any(
                        k in resp_lower for k in [
                            'success', 'uploaded',
                            'saved', 'image.jpg'
                        ]
                    ):
                        self.findings.append({
                            'type': (
                                'Content-Type Bypass '
                                'in File Upload'
                            ),
                            'category': 'file_upload',
                            'risk': 'HIGH',
                            'url': url,
                            'description': (
                                'PHP content uploaded '
                                'with image/jpeg MIME. '
                                'Content-type not validated.'
                            ),
                            'business_impact': (
                                'Webshell upload possible '
                                'by faking content type'
                            ),
                            'fix': (
                                '1. Validate file magic bytes\n'
                                '2. Use server-side MIME check\n'
                                '3. Do not trust client headers'
                            ),
                            'cvss_score': 8.8,
                            'cwe': 'CWE-434'
                        })
                        print(
                            f"  {Fore.RED}"
                            f"[!!!] CONTENT-TYPE BYPASS"
                            f"{Style.RESET_ALL}"
                        )
            except Exception:
                pass

        return self.findings

    def run_full_scan(self):
        print(
            f"\n{Fore.YELLOW}[FILE UPLOAD AGENT] "
            f"Starting...{Style.RESET_ALL}"
        )
        endpoints = self.discover_upload_endpoints()
        print(
            f"  {Fore.CYAN}[*] Found "
            f"{len(endpoints)} upload endpoints"
            f"{Style.RESET_ALL}"
        )
        if endpoints:
            self.test_dangerous_extensions(endpoints)
            self.test_content_type_bypass(endpoints)
        print(
            f"{Fore.GREEN}[FILE UPLOAD AGENT] "
            f"Complete - {len(self.findings)} findings"
            f"{Style.RESET_ALL}"
        )
        return self.findings
