"""
AI Report Generator
Generates professional security reports using Groq AI
"""

"""
AI Report Generator
Generates professional security reports using Groq AI
"""

import re
import json
from datetime import datetime

from groq import Groq


class ReportGenerator:
    def __init__(self, api_key):
        if not api_key:
            raise ValueError(
                "GROQ_API_KEY is missing"
            )

        self.client = Groq(api_key=api_key)
        self.model = "llama-3.3-70b-versatile"

        print(
            f"  [✓] Groq AI ready ({self.model})"
        )

    def generate_full_report(
        self, target, scan_results, scan_duration=0
    ):
        """Generate comprehensive security report"""

        stats = self._calculate_stats(scan_results)
        now_full = datetime.now().strftime(
            "%Y-%m-%d %H:%M"
        )

        compressed = self._compress_scan_data(
            target,
            scan_results,
            stats,
            scan_duration
        )

        system_prompt = (
            "You are a professional cybersecurity report "
            "writer with expertise in web security, "
            "network security, and risk assessment. "
            "Write clear, actionable reports in Markdown."
        )

        prompt = (
            f"Write a professional security assessment "
            f"report for: **{target}**\n"
            f"Date: {now_full}\n\n"
            f"{compressed}\n\n"
            "Write the report with these sections:\n"
            "# Security Assessment Report\n"
            "## Executive Summary\n"
            "## Overall Risk Rating\n"
            "## Critical Findings\n"
            "## High Risk Findings\n"
            "## Medium Risk Findings\n"
            "## Positive Security Findings\n"
            "## Remediation Roadmap\n"
            "## Technical Appendix\n\n"
            "Be specific, professional, and actionable."
        )

        try:
            print(
                "  [*] Sending data to Groq AI..."
            )

            response = (
                self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {
                            "role": "system",
                            "content": system_prompt
                        },
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    max_tokens=6000,
                    temperature=0.3
                )
            )

            markdown_report = (
                response.choices[0]
                .message.content
            )

            print(
                "  [✓] Groq AI response received!"
            )

            return {
                "markdown": markdown_report,
                "stats": stats,
                "generated_at": str(datetime.now()),
                "model": self.model
            }

        except Exception as e:
            print(
                f"  [!] Groq API error: {e}"
            )

            print(
                "  [*] Generating fallback report..."
            )

            fallback = (
                self._generate_fallback_report(
                    target,
                    scan_results,
                    scan_duration,
                    stats
                )
            )

            return {
                "markdown": fallback,
                "stats": stats,
                "generated_at": str(datetime.now()),
                "model": "fallback"
            }

    def _compress_scan_data(
        self,
        target: str,
        scan_results: dict,
        stats: dict,
        scan_duration: int
    ) -> str:
        """
        Compress scan data into key facts only
        Avoids 413 token limit error
        """
        lines = []

        lines.append("=== SCAN SUMMARY ===")
        lines.append(f"Target: {target}")
        lines.append(f"Duration: {scan_duration}s")
        lines.append(
            f"Risk: Critical={stats['critical']} "
            f"High={stats['high']} "
            f"Medium={stats['medium']} "
            f"Low={stats['low']}"
        )
        lines.append("")

        # Recon - key facts only
        recon = scan_results.get('reconnaissance', {})
        lines.append("=== RECON ===")

        tech = recon.get('tech_stack', {})
        server = tech.get(
            'header_indicators', {}
        ).get('Server', 'Unknown')
        lines.append(f"Server: {server}")

        subs = recon.get('subdomains', {})
        lines.append(
            f"Subdomains: {subs.get('found_count', 0)}"
        )

        robots = recon.get(
            'robots_sitemap', {}
        ).get('robots_txt', {})
        if robots.get('sensitive_paths_found'):
            paths = robots['sensitive_paths_found'][:5]
            lines.append(
                f"Robots sensitive paths: "
                f"{', '.join(paths)}"
            )

        exposed = recon.get('exposed_paths', {})
        exp_list = exposed.get('exposed_paths', [])
        if exp_list:
            for p in exp_list[:5]:
                lines.append(
                    f"Exposed: {p['path']} "
                    f"({p['risk']}) - "
                    f"{p.get('note', '')}"
                )

        whois = recon.get('whois', {})
        lines.append(
            f"Org: "
            f"{whois.get('organization', 'Unknown')}"
        )
        lines.append(
            f"Registrar: "
            f"{whois.get('registrar', 'Unknown')}"
        )
        lines.append(
            f"Created: "
            f"{str(whois.get('creation_date',''))[:10]}"
        )
        lines.append("")

        # Headers - key facts only
        headers = scan_results.get(
            'security_headers', {}
        )
        lines.append("=== SECURITY HEADERS ===")

        score = headers.get('score', {})
        lines.append(
            f"Score: {score.get('value', 0)}/100 "
            f"Grade: {score.get('grade', 'F')}"
        )

        security_headers = headers.get(
            'security_headers', {}
        )
        for h_name, h_data in security_headers.items():
            present = h_data.get('present', False)
            risk = h_data.get('risk_if_missing', 'LOW')
            status = (
                "OK" if present
                else f"MISSING({risk})"
            )
            lines.append(f"{h_name}: {status}")

        missing = headers.get('missing_critical', [])
        if missing:
            lines.append(
                f"Critical missing: "
                f"{', '.join(missing)}"
            )

        disc = headers.get('information_disclosure', {})
        for k, v in disc.items():
            lines.append(
                f"Info disclosure: "
                f"{k}={v.get('value', '')}"
            )
        lines.append("")

        # SSL - key facts only
        ssl = scan_results.get('ssl_tls', {})
        lines.append("=== SSL/TLS ===")

        cert = ssl.get('certificate', {})
        lines.append(
            f"Issuer: "
            f"{cert.get('issuer',{}).get('commonName','N/A')}"
        )
        lines.append(
            f"Valid until: "
            f"{str(cert.get('valid_until', ''))[:10]}"
        )
        lines.append(
            f"Days left: "
            f"{cert.get('days_until_expiry', 'N/A')}"
        )
        lines.append(
            f"Expired: {cert.get('is_expired', False)}"
        )

        tls = ssl.get('tls', {})
        lines.append(
            f"TLS: {tls.get('version', 'Unknown')}"
        )
        lines.append(
            f"Cipher: "
            f"{tls.get('cipher_suite', 'Unknown')} "
            f"({tls.get('cipher_bits', 'N/A')} bits)"
        )

        ssl_issues = ssl.get('issues', [])
        if ssl_issues:
            for issue in ssl_issues:
                lines.append(
                    f"SSL Issue: "
                    f"{issue.get('description', '')}"
                )
        else:
            lines.append("SSL Issues: None")

        lines.append(
            f"SSL Status: "
            f"{ssl.get('overall_status', 'Unknown')}"
        )
        lines.append("")

        # Email - key facts only
        email = scan_results.get('email_security', {})
        lines.append("=== EMAIL SECURITY ===")

        spf = email.get('spf', {})
        lines.append(
            f"SPF: "
            f"{'Configured' if spf.get('exists') else 'MISSING'}"
        )

        dmarc = email.get('dmarc', {})
        lines.append(
            f"DMARC: "
            f"{'Configured' if dmarc.get('exists') else 'MISSING'}"
            f" Risk={dmarc.get('risk', 'HIGH')}"
        )

        dkim = email.get('dkim', {})
        lines.append(
            f"DKIM: "
            f"{'Found' if dkim.get('exists') else 'NOT FOUND'}"
        )

        mx = email.get('mx_records', {})
        lines.append(
            f"MX Records: "
            f"{'Found' if mx.get('exists') else 'NOT FOUND'}"
        )

        score_data = email.get(
            'email_security_score', {}
        )
        lines.append(
            f"Email Score: "
            f"{score_data.get('score', 0)}/100 "
            f"Grade={score_data.get('grade', 'F')}"
        )

        return "\n".join(lines)

    def _calculate_stats(self, results):
        """Calculate summary statistics from results"""
        stats = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }

        # Count from exposed paths
        exposed = results.get(
            'reconnaissance', {}
        ).get('exposed_paths', {})
        for path in exposed.get('exposed_paths', []):
            risk = path.get('risk', 'INFO').upper()
            if risk == 'CRITICAL':
                stats['critical'] += 1
            elif risk == 'HIGH':
                stats['high'] += 1
            elif risk == 'MEDIUM':
                stats['medium'] += 1
            elif risk == 'LOW':
                stats['low'] += 1

        # Count from SSL
        ssl_issues = results.get(
            'ssl_tls', {}
        ).get('issues', [])
        for issue in ssl_issues:
            sev = issue.get('severity', 'LOW').upper()
            if sev == 'CRITICAL':
                stats['critical'] += 1
            elif sev == 'HIGH':
                stats['high'] += 1
            elif sev == 'MEDIUM':
                stats['medium'] += 1

        # Count from headers
        header_data = results.get('security_headers', {})
        missing_critical = header_data.get(
            'missing_critical', []
        )
        stats['high'] += len(missing_critical)

        # Count from email
        email_data = results.get('email_security', {})
        if not email_data.get('spf', {}).get(
            'exists', True
        ):
            stats['high'] += 1
        if not email_data.get('dmarc', {}).get(
            'exists', True
        ):
            stats['high'] += 1
        if not email_data.get('dkim', {}).get(
            'exists', True
        ):
            stats['medium'] += 1

        return stats

    def _generate_fallback_report(
        self,
        target: str,
        scan_results: dict,
        scan_duration: int,
        stats: dict
    ) -> str:
        """
        Human-readable report when Groq API unavailable
        No raw JSON - fully formatted professional report
        """
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        now_date = datetime.now().strftime('%Y-%m-%d')

        # Extract all data
        recon = scan_results.get('reconnaissance', {})
        headers = scan_results.get('security_headers', {})
        ssl = scan_results.get('ssl_tls', {})
        email = scan_results.get('email_security', {})

        # Risk Rating
        if stats['critical'] > 0:
            risk_rating = "CRITICAL"
            risk_score = 20
            grade = "F"
        elif stats['high'] > 3:
            risk_rating = "HIGH"
            risk_score = 35
            grade = "F"
        elif stats['high'] > 0:
            risk_rating = "MEDIUM-HIGH"
            risk_score = 50
            grade = "D"
        elif stats['medium'] > 2:
            risk_rating = "MEDIUM"
            risk_score = 65
            grade = "C"
        elif stats['medium'] > 0:
            risk_rating = "LOW-MEDIUM"
            risk_score = 75
            grade = "B"
        else:
            risk_rating = "LOW"
            risk_score = 90
            grade = "A"

        # Recon Data
        tech = recon.get('tech_stack', {})
        server = tech.get(
            'header_indicators', {}
        ).get('Server', 'Unknown')
        frameworks = tech.get('detected_frameworks', [])
        response_code = tech.get('response_code', 'N/A')

        subs = recon.get('subdomains', {})
        sub_count = subs.get('found_count', 0)
        sub_list = subs.get('found', [])
        high_risk_subs = subs.get('high_risk_found', [])

        robots_data = recon.get('robots_sitemap', {})
        robots = robots_data.get('robots_txt', {})
        robots_exists = robots.get('exists', False)
        sensitive_paths = robots.get(
            'sensitive_paths_found', []
        )
        robots_risk = robots.get('risk', 'LOW')

        exposed = recon.get('exposed_paths', {})
        exposed_count = exposed.get('exposed_count', 0)
        exposed_list = exposed.get('exposed_paths', [])
        checked_count = exposed.get('checked_count', 0)

        whois = recon.get('whois', {})
        registrar = whois.get('registrar', 'Unknown')
        creation = str(
            whois.get('creation_date', 'Unknown')
        )[:10]
        expiry = str(
            whois.get('expiration_date', 'Unknown')
        )[:10]
        org = whois.get('organization', 'Unknown')
        country = whois.get('country', 'Unknown')

        # Header Data
        score_data = headers.get('score', {})
        header_score = score_data.get('value', 0)
        header_grade = score_data.get('grade', 'F')
        header_interp = score_data.get(
            'interpretation', 'Unknown'
        )
        headers_present = score_data.get(
            'headers_present', 0
        )
        headers_total = score_data.get(
            'headers_total', 0
        )
        security_headers = headers.get(
            'security_headers', {}
        )
        missing_critical = headers.get(
            'missing_critical', []
        )
        info_disclosure = headers.get(
            'information_disclosure', {}
        )
        cors = headers.get('cors', {})

        # SSL Data
        https_enabled = ssl.get('https_enabled', False)
        cert = ssl.get('certificate', {})
        cert_subject = cert.get('subject', {})
        cert_issuer = cert.get('issuer', {})
        issuer_name = cert_issuer.get(
            'commonName', 'Unknown'
        )
        issuer_org = cert_issuer.get(
            'organizationName', 'Unknown'
        )
        common_name = cert_subject.get(
            'commonName', 'Unknown'
        )
        cert_org = cert_subject.get(
            'organizationName', 'Unknown'
        )
        valid_from = str(
            cert.get('valid_from', 'Unknown')
        )[:10]
        valid_until = str(
            cert.get('valid_until', 'Unknown')
        )[:10]
        days_left = cert.get('days_until_expiry', 'N/A')
        is_expired = cert.get('is_expired', False)
        san_domains = cert.get('san_domains', [])
        san_count = cert.get('san_count', 0)

        tls_data = ssl.get('tls', {})
        tls_version = tls_data.get('version', 'Unknown')
        cipher = tls_data.get('cipher_suite', 'Unknown')
        cipher_bits = tls_data.get('cipher_bits', 'N/A')
        tls_secure = tls_data.get(
            'protocol_secure', False
        )
        ssl_issues = ssl.get('issues', [])
        ssl_status = ssl.get('overall_status', 'Unknown')

        # Email Data
        spf = email.get('spf', {})
        spf_ok = spf.get('exists', False)

        dmarc = email.get('dmarc', {})
        dmarc_ok = dmarc.get('exists', False)
        dmarc_risk = dmarc.get('risk', 'HIGH')
        dmarc_desc = dmarc.get('description', '')
        dmarc_impact = dmarc.get('business_impact', '')
        dmarc_fix = dmarc.get('fix', '')

        dkim = email.get('dkim', {})
        dkim_ok = dkim.get('exists', False)
        dkim_selectors = dkim.get('checked_selectors', 0)

        mx = email.get('mx_records', {})
        mx_ok = mx.get('exists', False)

        email_score_data = email.get(
            'email_security_score', {}
        )
        email_score = email_score_data.get('score', 0)
        email_grade = email_score_data.get('grade', 'F')

        # Build Header Table
        header_rows = []
        for h_name, h_data in security_headers.items():
            present = h_data.get('present', False)
            status = "Present" if present else "MISSING"
            risk = h_data.get('risk_if_missing', 'LOW')
            header_rows.append(
                f"| {h_name} | {status} | {risk} |"
            )
        header_table = "\n".join(header_rows)

        # Build Exposed Paths
        exposed_lines = []
        for p in exposed_list:
            exposed_lines.append(
                f"- **{p['path']}** | "
                f"Status: {p.get('status_code', 'N/A')}"
                f" | Risk: **{p['risk']}** | "
                f"{p.get('description', '')} | "
                f"{p.get('note', '')}"
            )
        exposed_text = (
            "\n".join(exposed_lines)
            if exposed_lines
            else "No exposed paths detected"
        )

        # Build Sensitive Robots Paths
        robots_lines = []
        for rp in sensitive_paths:
            robots_lines.append(f"  - `{rp}`")
        robots_text = (
            "\n".join(robots_lines)
            if robots_lines
            else "  - None found"
        )

        # Build Missing Headers Detail
        missing_detail_lines = []
        for h in missing_critical:
            h_data = security_headers.get(h, {})
            desc = h_data.get('description', '')
            attack = h_data.get('attack', '')
            fix = h_data.get('fix', '')
            missing_detail_lines.append(
                f"### Missing: {h}\n"
                f"- **Risk Level:** HIGH\n"
                f"- **Description:** {desc}\n"
                f"- **Attack Vector:** {attack}\n"
                f"- **Fix:** `{fix}`\n"
            )
        missing_detail = "\n".join(missing_detail_lines)

        # Build SAN Domains
        san_lines = []
        for san in san_domains[:5]:
            san_lines.append(f"  - {san}")
        san_text = (
            "\n".join(san_lines)
            if san_lines
            else "  - None listed"
        )

        # Build Recommendations
        immediate = []
        short_term = []
        medium_term = []
        ongoing = []

        if not dmarc_ok:
            immediate.append(
                "**Configure DMARC Record** - "
                "Prevents email spoofing. "
                f"Fix: `_dmarc.{target} TXT "
                "v=DMARC1; p=reject; "
                f"rua=mailto:dmarc@{target}`"
            )
        if not spf_ok:
            immediate.append(
                "**Configure SPF Record** - "
                "Prevents unauthorized email sending. "
                f"Fix: Add SPF TXT record to DNS"
            )
        for h in missing_critical:
            h_data = security_headers.get(h, {})
            fix = h_data.get('fix', '')
            immediate.append(
                f"**Add {h} Header** - "
                f"Fix: `{fix}`"
            )

        if not dkim_ok:
            short_term.append(
                "**Configure DKIM** - "
                "Set up email signing with provider"
            )
        if info_disclosure:
            for h_name in info_disclosure:
                short_term.append(
                    f"**Remove {h_name} Header** - "
                    "Prevents technology fingerprinting"
                )
        if exposed_count > 0:
            short_term.append(
                f"**Review {exposed_count} "
                f"Exposed Path(s)** - "
                "Restrict sensitive endpoints"
            )
        if sensitive_paths:
            short_term.append(
                "**Review Robots.txt** - "
                "Sensitive paths visible to attackers"
            )

        medium_term.append(
            "**Conduct Active Security Assessment** - "
            "Commission a full penetration test"
        )
        medium_term.append(
            "**Implement Security Monitoring** - "
            "Set up alerts for security events"
        )
        medium_term.append(
            "**Review DNS Configuration** - "
            "Audit all DNS records"
        )

        ongoing.append(
            f"Monitor SSL certificate expiry "
            f"({days_left} days remaining)"
        )
        ongoing.append(
            "Audit security headers after any "
            "server or CDN changes"
        )
        ongoing.append(
            "Subscribe to security advisories "
            "for technologies in use"
        )
        ongoing.append(
            "Perform quarterly passive scans "
            "to track improvements"
        )

        def fmt_list(items):
            if not items:
                return "No actions required"
            return "\n".join(
                f"{i+1}. {r}"
                for i, r in enumerate(items)
            )

        imm_text = fmt_list(immediate)
        short_text = fmt_list(short_term)
        med_text = fmt_list(medium_term)
        ong_text = fmt_list(ongoing)

        # Build Positive Findings
        positives = []
        if https_enabled:
            positives.append("HTTPS enabled and enforced")
        if not is_expired:
            positives.append(
                f"SSL certificate valid "
                f"({days_left} days remaining)"
            )
        if tls_secure:
            positives.append(
                f"Strong TLS version ({tls_version})"
            )
        try:
            if cipher_bits and int(
                str(cipher_bits)
            ) >= 256:
                positives.append(
                    f"Strong cipher: {cipher} "
                    f"({cipher_bits}-bit)"
                )
        except (ValueError, TypeError):
            pass
        if not cors.get('misconfigured', False):
            positives.append("CORS properly configured")
        if not ssl_issues:
            positives.append(
                "No SSL/TLS vulnerabilities detected"
            )
        for h_name, h_data in security_headers.items():
            if h_data.get('present', False):
                positives.append(
                    f"{h_name} header configured"
                )

        positive_text = (
            "\n".join(f"- {p}" for p in positives)
            if positives
            else "- No positive findings recorded"
        )

        # Assemble Full Report
        report = (
            "# Security Assessment Report\n\n"
            "---\n\n"
            "| Field           | Details |\n"
            "|-----------------|---------|\n"
            f"| **Target**      | {target} |\n"
            f"| **Date**        | {now} |\n"
            f"| **Duration**    | {scan_duration}s |\n"
            "| **Scan Type**   | Passive External |\n"
            "| **Prepared by** | Security Assessment Agent |\n\n"
            "---\n\n"

            "## Executive Summary\n\n"
            f"A passive security assessment of **{target}**"
            f" was conducted on **{now_date}**. "
            "This assessment examined publicly available "
            "information including security headers, "
            "SSL/TLS, DNS records, and email security "
            "without any active or intrusive testing.\n\n"
            f"The domain belongs to **{org}** ({country}),"
            f" registered through **{registrar}** "
            f"since **{creation}**. "
            f"The web server is **{server}**.\n\n"
            f"Overall security posture is rated "
            f"**{risk_rating}** - Score: "
            f"**{risk_score}/100** (Grade: **{grade}**)."
            f" There are **{stats['high']} high risk** "
            f"and **{stats['medium']} medium risk** "
            "findings requiring attention.\n\n"
            "| Severity | Count |\n"
            "|----------|-------|\n"
            f"| Critical | {stats['critical']} |\n"
            f"| High     | {stats['high']} |\n"
            f"| Medium   | {stats['medium']} |\n"
            f"| Low      | {stats['low']} |\n\n"
            "---\n\n"

            "## Reconnaissance Findings\n\n"
            "### Domain Information\n\n"
            "| Field        | Value |\n"
            "|--------------|-------|\n"
            f"| Organization | {org} |\n"
            f"| Country      | {country} |\n"
            f"| Registrar    | {registrar} |\n"
            f"| Created      | {creation} |\n"
            f"| Expires      | {expiry} |\n\n"
            "### Technology Stack\n\n"
            f"- **Web Server:** {server}\n"
            f"- **Response Code:** {response_code}\n"
            "- **Frameworks:** "
            + (
                ", ".join(frameworks)
                if frameworks else "None detected"
            )
            + "\n\n"
            "### Subdomains\n\n"
            f"- **Total Found:** {sub_count}\n"
            + (
                "\n".join(f"  - {s}" for s in sub_list)
                if sub_list
                else "  - No subdomains discovered"
            )
            + "\n\n"
            "### Robots.txt\n\n"
            f"- **Exists:** "
            f"{'Yes' if robots_exists else 'No'}\n"
            f"- **Risk Level:** {robots_risk}\n"
            "- **Sensitive Paths Disclosed:**\n"
            + robots_text + "\n\n"
            "### Exposed Paths\n\n"
            f"- **Paths Checked:** {checked_count}\n"
            f"- **Paths Exposed:** {exposed_count}\n\n"
            + exposed_text + "\n\n"
            "---\n\n"

            "## Security Headers Analysis\n\n"
            f"**Score:** {header_score}/100 "
            f"(Grade: **{header_grade}** - "
            f"{header_interp})\n\n"
            f"**Headers Present:** "
            f"{headers_present}/{headers_total}\n\n"
            "| Header | Status | Risk If Missing |\n"
            "|--------|--------|-----------------|\n"
            + header_table + "\n\n"
            + (
                "### Critical Missing Headers\n\n"
                + missing_detail + "\n"
                if missing_detail else ""
            )
            + (
                "### Information Disclosure\n\n"
                + "\n".join(
                    f"- **{k}:** `{v.get('value','')}` - "
                    f"{v.get('description','')} | "
                    f"**Fix:** {v.get('fix','')}"
                    for k, v in info_disclosure.items()
                ) + "\n\n"
                if info_disclosure else ""
            )
            + "---\n\n"

            "## SSL/TLS Assessment\n\n"
            f"**Overall Status:** {ssl_status}\n\n"
            "### Certificate Details\n\n"
            "| Field             | Value |\n"
            "|-------------------|-------|\n"
            f"| Common Name       | {common_name} |\n"
            f"| Organization      | {cert_org} |\n"
            f"| Issuer            | {issuer_name} |\n"
            f"| Issuer Org        | {issuer_org} |\n"
            f"| Valid From        | {valid_from} |\n"
            f"| Valid Until       | {valid_until} |\n"
            f"| Days Until Expiry | {days_left} |\n"
            f"| Status            | "
            f"{'EXPIRED' if is_expired else 'Valid'} |\n"
            f"| SAN Count         | {san_count} |\n\n"
            "**SAN Domains:**\n"
            + san_text + "\n\n"
            "### TLS Configuration\n\n"
            "| Field           | Value |\n"
            "|-----------------|-------|\n"
            f"| TLS Version     | {tls_version} |\n"
            f"| Cipher Suite    | {cipher} |\n"
            f"| Cipher Bits     | {cipher_bits} |\n"
            f"| Protocol Secure | "
            f"{'Yes' if tls_secure else 'No'} |\n\n"
            + (
                "### SSL Issues\n\n"
                + "\n".join(
                    f"- **{i.get('severity','N/A')}:** "
                    f"{i.get('description','')}"
                    for i in ssl_issues
                ) + "\n\n"
                if ssl_issues
                else "**No SSL Issues Found**\n\n"
            )
            + "---\n\n"

            "## Email Security Analysis\n\n"
            f"**Email Security Score:** "
            f"{email_score}/100 "
            f"(Grade: **{email_grade}**)\n\n"
            "| Protocol   | Status | Risk |\n"
            "|------------|--------|------|\n"
            f"| SPF        | "
            f"{'Configured' if spf_ok else 'MISSING'}"
            f" | {'Low' if spf_ok else 'HIGH'} |\n"
            f"| DMARC      | "
            f"{'Configured' if dmarc_ok else 'MISSING'}"
            f" | {dmarc_risk} |\n"
            f"| DKIM       | "
            f"{'Detected' if dkim_ok else 'Not Found'}"
            f" | {'Low' if dkim_ok else 'MEDIUM'} |\n"
            f"| MX Records | "
            f"{'Found' if mx_ok else 'Not Found'}"
            f" | {'Low' if mx_ok else 'MEDIUM'} |\n\n"
            + (
                f"**Risk:** {dmarc_desc}\n\n"
                f"**Business Impact:** {dmarc_impact}\n\n"
                f"**Fix:** `{dmarc_fix}`\n\n"
                if not dmarc_ok and dmarc_desc else ""
            )
            + (
                f"Without proper email security, "
                f"attackers can impersonate "
                f"**@{target}** to conduct phishing "
                "attacks against your customers.\n\n"
                if not (spf_ok and dmarc_ok) else ""
            )
            + "---\n\n"

            "## Positive Security Findings\n\n"
            + positive_text + "\n\n"
            "---\n\n"

            "## Remediation Roadmap\n\n"
            "### Immediate Actions (This Week)\n\n"
            + imm_text + "\n\n"
            "### Short Term (This Month)\n\n"
            + short_text + "\n\n"
            "### Medium Term (Next Quarter)\n\n"
            + med_text + "\n\n"
            "### Ongoing\n\n"
            + ong_text + "\n\n"
            "---\n\n"

            "## Technical Appendix\n\n"
            "### Scan Coverage\n\n"
            "| Area                  | Status |\n"
            "|-----------------------|--------|\n"
            "| Technology Stack      | Checked |\n"
            "| Subdomain Enumeration | Checked |\n"
            "| Robots.txt & Sitemap  | Checked |\n"
            f"| Exposed Paths ({checked_count}) | Checked |\n"
            "| WHOIS Information     | Checked |\n"
            "| Security Headers      | Checked |\n"
            "| SSL/TLS Configuration | Checked |\n"
            "| SPF Record            | Checked |\n"
            "| DMARC Record          | Checked |\n"
            f"| DKIM ({dkim_selectors} selectors) | Checked |\n"
            "| MX Records            | Checked |\n\n"
            "### Scan Limitations\n\n"
            "This was a **passive scan** - "
            "public information only.\n\n"
            "NOT tested:\n\n"
            "- Authentication/authorization flaws\n"
            "- SQL injection & input validation\n"
            "- Business logic vulnerabilities\n"
            "- Internal network security\n"
            "- Application-layer vulnerabilities\n\n"
            "**Recommendation:** Commission an active "
            "penetration test for full coverage.\n\n"
            "---\n\n"
            f"*Generated: {now}*\n"
            "*Passive Security Assessment Agent*\n"
        )

        return report

    def generate_pdf(self, markdown_content, output_path):
        """Generate PDF from markdown using reportlab"""
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import (
                getSampleStyleSheet, ParagraphStyle
            )
            from reportlab.lib.units import inch
            from reportlab.lib import colors
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph,
                Spacer, HRFlowable
            )

            doc = SimpleDocTemplate(
                output_path,
                pagesize=A4,
                rightMargin=0.75 * inch,
                leftMargin=0.75 * inch,
                topMargin=0.75 * inch,
                bottomMargin=0.75 * inch
            )

            styles = getSampleStyleSheet()

            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Title'],
                fontSize=24,
                textColor=colors.HexColor('#1a1a2e'),
                spaceAfter=20,
                alignment=1
            )
            h1_style = ParagraphStyle(
                'CustomH1',
                parent=styles['Heading1'],
                fontSize=16,
                textColor=colors.HexColor('#16213e'),
                spaceBefore=16,
                spaceAfter=8
            )
            h2_style = ParagraphStyle(
                'CustomH2',
                parent=styles['Heading2'],
                fontSize=13,
                textColor=colors.HexColor('#0f3460'),
                spaceBefore=12,
                spaceAfter=6
            )
            h3_style = ParagraphStyle(
                'CustomH3',
                parent=styles['Heading3'],
                fontSize=11,
                textColor=colors.HexColor('#e94560'),
                spaceBefore=8,
                spaceAfter=4
            )
            body_style = ParagraphStyle(
                'CustomBody',
                parent=styles['Normal'],
                fontSize=10,
                leading=14,
                spaceAfter=4
            )
            bullet_style = ParagraphStyle(
                'CustomBullet',
                parent=styles['Normal'],
                fontSize=10,
                leading=14,
                spaceAfter=3,
                leftIndent=20
            )

            story = []

            for line in markdown_content.split('\n'):
                stripped = line.strip()

                if not stripped:
                    story.append(Spacer(1, 0.1 * inch))
                    continue

                if stripped.startswith('# '):
                    story.append(
                        Paragraph(
                            stripped[2:], title_style
                        )
                    )
                    story.append(
                        HRFlowable(
                            width="100%",
                            thickness=3,
                            color=colors.HexColor(
                                '#1a1a2e'
                            )
                        )
                    )

                elif stripped.startswith('## '):
                    story.append(Spacer(1, 0.1 * inch))
                    story.append(
                        Paragraph(
                            stripped[3:], h1_style
                        )
                    )
                    story.append(
                        HRFlowable(
                            width="100%",
                            thickness=1,
                            color=colors.HexColor(
                                '#16213e'
                            )
                        )
                    )

                elif stripped.startswith('### '):
                    story.append(
                        Paragraph(
                            stripped[4:], h2_style
                        )
                    )

                elif stripped.startswith('#### '):
                    story.append(
                        Paragraph(
                            stripped[5:], h3_style
                        )
                    )

                elif stripped.startswith('---'):
                    story.append(Spacer(1, 0.05 * inch))
                    story.append(
                        HRFlowable(
                            width="100%",
                            thickness=1,
                            color=colors.grey
                        )
                    )
                    story.append(Spacer(1, 0.05 * inch))

                elif stripped.startswith('|'):
                    # Skip separator rows
                    clean = stripped.replace(
                        '|', ''
                    ).replace('-', '').strip()
                    if not clean:
                        continue
                    cells = [
                        c.strip()
                        for c in stripped.split('|')
                        if c.strip()
                    ]
                    row_text = "  |  ".join(cells)
                    row_text = re.sub(
                        r'\*\*(.*?)\*\*',
                        r'<b>\1</b>',
                        row_text
                    )
                    try:
                        story.append(
                            Paragraph(
                                row_text, body_style
                            )
                        )
                    except Exception:
                        pass

                elif stripped.startswith('- '):
                    text = stripped[2:]
                    text = re.sub(
                        r'\*\*(.*?)\*\*',
                        r'<b>\1</b>',
                        text
                    )
                    text = re.sub(
                        r'`(.*?)`',
                        r'<font name="Courier">\1</font>',
                        text
                    )
                    try:
                        story.append(
                            Paragraph(
                                f"• {text}",
                                bullet_style
                            )
                        )
                    except Exception:
                        story.append(
                            Paragraph(
                                f"• {text.encode('ascii','ignore').decode()}",
                                bullet_style
                            )
                        )

                elif (
                    len(stripped) > 2
                    and stripped[0].isdigit()
                    and stripped[1] == '.'
                ):
                    text = stripped[2:].strip()
                    text = re.sub(
                        r'\*\*(.*?)\*\*',
                        r'<b>\1</b>',
                        text
                    )
                    text = re.sub(
                        r'`(.*?)`',
                        r'<font name="Courier">\1</font>',
                        text
                    )
                    try:
                        story.append(
                            Paragraph(
                                f"{stripped[0]}. {text}",
                                bullet_style
                            )
                        )
                    except Exception:
                        pass

                elif stripped.startswith('```'):
                    continue

                else:
                    text = stripped
                    text = re.sub(
                        r'\*\*(.*?)\*\*',
                        r'<b>\1</b>',
                        text
                    )
                    text = re.sub(
                        r'\*(.*?)\*',
                        r'<i>\1</i>',
                        text
                    )
                    text = re.sub(
                        r'`(.*?)`',
                        r'<font name="Courier">\1</font>',
                        text
                    )
                    try:
                        story.append(
                            Paragraph(text, body_style)
                        )
                    except Exception:
                        story.append(
                            Paragraph(
                                text.encode(
                                    'ascii', 'ignore'
                                ).decode(),
                                body_style
                            )
                        )

            doc.build(story)
            print(f"  [✓] PDF saved: {output_path}")
            return output_path

        except ImportError:
            print(
                "  [!] reportlab not installed - "
                "saving as HTML"
            )
            return self._save_as_html(
                markdown_content, output_path
            )

    def _save_as_html(
        self,
        markdown_content: str,
        output_path: str
    ) -> str:
        """Fallback - save as HTML if PDF fails"""
        html_path = output_path.replace('.pdf', '.html')

        html_lines = []
        for line in markdown_content.split('\n'):
            stripped = line.strip()

            if not stripped:
                html_lines.append("<br>")
                continue

            if stripped.startswith('# '):
                html_lines.append(
                    f"<h1>{stripped[2:]}</h1>"
                )
            elif stripped.startswith('## '):
                html_lines.append(
                    f"<h2>{stripped[3:]}</h2>"
                )
            elif stripped.startswith('### '):
                html_lines.append(
                    f"<h3>{stripped[4:]}</h3>"
                )
            elif stripped.startswith('#### '):
                html_lines.append(
                    f"<h4>{stripped[5:]}</h4>"
                )
            elif stripped.startswith('---'):
                html_lines.append("<hr>")
            elif stripped.startswith('|'):
                clean = stripped.replace(
                    '|', ''
                ).replace('-', '').strip()
                if not clean:
                    continue
                cells = [
                    c.strip()
                    for c in stripped.split('|')
                    if c.strip()
                ]
                cells_html = "".join(
                    f"<td>{c}</td>" for c in cells
                )
                html_lines.append(
                    f"<tr>{cells_html}</tr>"
                )
            elif stripped.startswith('- '):
                text = re.sub(
                    r'\*\*(.*?)\*\*',
                    r'<b>\1</b>',
                    stripped[2:]
                )
                text = re.sub(
                    r'`(.*?)`',
                    r'<code>\1</code>',
                    text
                )
                html_lines.append(f"<li>{text}</li>")
            elif stripped.startswith('```'):
                continue
            else:
                text = re.sub(
                    r'\*\*(.*?)\*\*',
                    r'<b>\1</b>',
                    stripped
                )
                text = re.sub(
                    r'`(.*?)`',
                    r'<code>\1</code>',
                    text
                )
                html_lines.append(f"<p>{text}</p>")

        html_body = "\n".join(html_lines)

        css = (
            "body{font-family:Arial,sans-serif;"
            "margin:0;color:#333;line-height:1.6;}"
            ".container{max-width:960px;"
            "margin:0 auto;padding:40px;}"
            "h1{color:#1a1a2e;"
            "border-bottom:3px solid #e94560;"
            "padding-bottom:10px;}"
            "h2{color:#16213e;"
            "border-bottom:1px solid #ddd;"
            "padding-bottom:6px;margin-top:30px;}"
            "h3{color:#0f3460;}"
            "h4{color:#e94560;}"
            "table{border-collapse:collapse;"
            "width:100%;margin:15px 0;}"
            "td,th{border:1px solid #ddd;"
            "padding:8px 12px;text-align:left;}"
            "tr:nth-child(even){background:#f9f9f9;}"
            "li{margin:6px 0;}"
            "hr{border:1px solid #eee;margin:20px 0;}"
            "b{color:#16213e;}"
            "code{background:#f4f4f4;padding:2px 6px;"
            "border-radius:3px;"
            "font-family:monospace;font-size:12px;}"
        )

        html_content = (
            "<!DOCTYPE html>\n<html>\n<head>\n"
            "<meta charset='utf-8'>\n"
            "<title>Security Report</title>\n"
            "<style>\n" + css + "\n</style>\n"
            "</head>\n<body>\n"
            "<div class='container'>\n"
            + html_body
            + "\n</div>\n</body>\n</html>"
        )

        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        print(f"  [!] Saved as HTML: {html_path}")
        return html_path
