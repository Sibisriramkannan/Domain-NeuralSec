import json
from datetime import datetime

from groq import Groq


class AdvancedReportGenerator:
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
        stats = self._calculate_stats(scan_results)

        try:
            compressed = self._compress_scan_data(
                target,
                scan_results,
                stats,
                scan_duration
            )

            prompt = (
                "You are a senior penetration tester. "
                "Write a professional advanced security "
                "assessment report.\n\n"
                f"{compressed}\n\n"
                "Write report with these sections:\n"
                "# Advanced Security Assessment Report\n"
                "## Executive Summary\n"
                "## Scope and Methodology\n"
                "## Risk Summary Table\n"
                "## Critical Findings\n"
                "## High Risk Findings\n"
                "## Medium Risk Findings\n"
                "## Positive Findings\n"
                "## Remediation Roadmap\n"
                "## Technical Appendix\n\n"
                "Professional, specific, actionable. "
                "Include CVSS and CWE for each finding."
            )

            response = (
                self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {
                            "role": "system",
                            "content": (
                                "Expert penetration tester "
                                "writing professional reports."
                            )
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

            return {
                "markdown": (
                    response.choices[0]
                    .message.content
                ),
                "stats": stats,
                "generated_at": str(datetime.now()),
                "model": self.model
            }

        except Exception as e:
            print(
                f"  [!] AI failed: {e}"
            )
            print(
                "  [*] Using fallback report..."
            )

            return self._generate_fallback_report(
                target,
                scan_results,
                scan_duration,
                stats
            )

    def _compress_scan_data(
        self, target, scan_results, stats, duration
    ):
        lines = []
        lines.append("=== ADVANCED SCAN SUMMARY ===")
        lines.append(f"Target: {target}")
        lines.append(
            f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        )
        lines.append(f"Duration: {duration}s")
        lines.append(
            f"Critical: {stats['critical']}, "
            f"High: {stats['high']}, "
            f"Medium: {stats['medium']}, "
            f"Low: {stats['low']}"
        )
        lines.append("")

        agent_keys = [
            ('authentication', 'AUTHENTICATION'),
            ('command_injection', 'COMMAND INJECTION'),
            ('file_upload', 'FILE UPLOAD'),
            ('ssrf', 'SSRF'),
            ('xxe', 'XXE'),
            ('nosql_injection', 'NOSQL INJECTION'),
            ('ssti', 'SSTI'),
            ('csrf', 'CSRF'),
            ('websocket', 'WEBSOCKET'),
            ('http_host_header', 'HTTP HOST HEADER'),
            ('web_cache', 'WEB CACHE'),
            ('oauth', 'OAUTH'),
            ('prototype_pollution', 'PROTOTYPE POLLUTION'),
            ('access_control', 'ACCESS CONTROL'),
        ]

        for key, label in agent_keys:
            findings = scan_results.get(key, [])
            if not isinstance(findings, list):
                continue
            lines.append(f"=== {label} ===")
            if not findings:
                lines.append("No findings.")
            else:
                for f in findings[:4]:
                    risk = f.get('risk', 'UNKNOWN')
                    ftype = f.get('type', '')
                    desc = f.get('description', '')
                    impact = f.get('business_impact', '')
                    fix = f.get('fix', '')
                    cvss = f.get('cvss_score', '')
                    cwe = f.get('cwe', '')
                    lines.append(f"[{risk}] {ftype}")
                    if desc:
                        lines.append(
                            f"  Desc: {desc[:180]}"
                        )
                    if impact:
                        lines.append(
                            f"  Impact: {impact[:120]}"
                        )
                    if fix:
                        lines.append(
                            f"  Fix: {str(fix)[:180]}"
                        )
                    if cvss:
                        lines.append(f"  CVSS: {cvss}")
                    if cwe:
                        lines.append(f"  CWE: {cwe}")
                    lines.append("")
            lines.append("")

        return '\n'.join(lines)

    def _calculate_stats(self, results):
        stats = {
            'critical': 0, 'high': 0,
            'medium': 0, 'low': 0
        }
        for findings in results.values():
            if not isinstance(findings, list):
                continue
            for f in findings:
                risk = f.get('risk', '').upper()
                if risk == 'CRITICAL':
                    stats['critical'] += 1
                elif risk == 'HIGH':
                    stats['high'] += 1
                elif risk == 'MEDIUM':
                    stats['medium'] += 1
                elif risk in ['LOW', 'INFO']:
                    stats['low'] += 1
        return stats

    def _generate_fallback_report(
        self, target, scan_results,
        scan_duration, stats
    ):
        now = datetime.now().strftime(
            '%Y-%m-%d %H:%M:%S'
        )
        total = sum(stats.values())

        risk_rating = (
            'CRITICAL' if stats['critical'] > 0
            else 'HIGH' if stats['high'] > 0
            else 'MEDIUM' if stats['medium'] > 0
            else 'LOW'
        )

        lines = []
        lines.append(
            "# Advanced Security Assessment Report"
        )
        lines.append("")
        lines.append("| Field | Details |")
        lines.append("| --- | --- |")
        lines.append(f"| Target | {target} |")
        lines.append(f"| Date | {now} |")
        lines.append(f"| Duration | {scan_duration}s |")
        lines.append(
            "| Type | Advanced Active Assessment |"
        )
        lines.append(
            "| Classification | CONFIDENTIAL |"
        )
        lines.append("")
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(
            f"Advanced assessment of **{target}** "
            f"found **{total} findings**. "
            f"Overall risk: **{risk_rating}**."
        )
        lines.append("")
        lines.append(
            f"- Critical: {stats['critical']}"
        )
        lines.append(f"- High: {stats['high']}")
        lines.append(f"- Medium: {stats['medium']}")
        lines.append(f"- Low: {stats['low']}")
        lines.append("")

        agent_keys = [
            ('authentication', 'Authentication'),
            ('command_injection', 'Command Injection'),
            ('file_upload', 'File Upload'),
            ('ssrf', 'SSRF'),
            ('xxe', 'XXE Injection'),
            ('nosql_injection', 'NoSQL Injection'),
            ('ssti', 'SSTI'),
            ('csrf', 'CSRF'),
            ('websocket', 'WebSocket Security'),
            ('http_host_header', 'HTTP Host Header'),
            ('web_cache', 'Web Cache'),
            ('oauth', 'OAuth Security'),
            ('prototype_pollution', 'Prototype Pollution'),
            ('access_control', 'Access Control'),
        ]

        lines.append("## Detailed Findings")
        lines.append("")

        for key, label in agent_keys:
            findings = scan_results.get(key, [])
            if not isinstance(findings, list):
                continue
            lines.append(f"### {label}")
            lines.append("")
            if not findings:
                lines.append(f"- No {label} issues.")
                lines.append("")
                continue

            for f in findings:
                risk = f.get('risk', 'UNKNOWN')
                ftype = f.get('type', 'Unknown')
                desc = f.get('description', 'N/A')
                impact = f.get('business_impact', 'N/A')
                fix = f.get('fix', 'N/A')
                cvss = f.get('cvss_score', 'N/A')
                cwe = f.get('cwe', 'N/A')
                url = f.get('url', '')

                lines.append(
                    f"#### [{risk}] {ftype}"
                )
                lines.append("")
                lines.append("| Field | Details |")
                lines.append("| --- | --- |")
                lines.append(f"| Severity | {risk} |")
                if cvss != 'N/A':
                    lines.append(
                        f"| CVSS | {cvss} |"
                    )
                if cwe != 'N/A':
                    lines.append(
                        f"| CWE | {cwe} |"
                    )
                if url:
                    lines.append(
                        f"| URL | {url[:80]} |"
                    )
                lines.append("")
                lines.append(
                    f"**Description:** {desc}"
                )
                lines.append("")
                lines.append(
                    f"**Business Impact:** {impact}"
                )
                lines.append("")
                lines.append("**Fix:**")
                if isinstance(fix, str):
                    for step in fix.split('\n'):
                        if step.strip():
                            lines.append(
                                f"- {step.strip()}"
                            )
                else:
                    lines.append(f"- {fix}")
                lines.append("")

        lines.append("## Remediation Roadmap")
        lines.append("")
        lines.append("### Immediate (24-48 Hours)")
        critical = [
            f.get('type', '') for v in scan_results.values()
            if isinstance(v, list)
            for f in v if f.get('risk') == 'CRITICAL'
        ]
        if critical:
            for c in critical:
                lines.append(f"- Fix: {c}")
        else:
            lines.append("- No critical items")
        lines.append("")
        lines.append("### This Week")
        high = [
            f.get('type', '') for v in scan_results.values()
            if isinstance(v, list)
            for f in v if f.get('risk') == 'HIGH'
        ]
        if high:
            for h in high:
                lines.append(f"- Address: {h}")
        else:
            lines.append("- No high priority items")
        lines.append("")
        lines.append("### This Month")
        lines.append("- Address medium risk findings")
        lines.append("- Security code review")
        lines.append("")
        lines.append("### Ongoing")
        lines.append(
            "- Monthly advanced assessments"
        )
        lines.append("- OWASP Top 10 training")
        lines.append("- Dependency updates")
        lines.append("")
        lines.append("## Technical Appendix")
        lines.append("")
        lines.append("### Agents Run (14 Total)")
        lines.append("")
        lines.append("| Agent | Coverage |")
        lines.append("| --- | --- |")
        lines.append(
            "| Auth | Default creds, lockout, MFA |"
        )
        lines.append(
            "| Command Injection | Error + time-based |"
        )
        lines.append(
            "| File Upload | Extension + MIME bypass |"
        )
        lines.append(
            "| SSRF | Internal + cloud metadata |"
        )
        lines.append(
            "| XXE | XML parser exploitation |"
        )
        lines.append(
            "| NoSQL | JSON + param injection |"
        )
        lines.append(
            "| SSTI | Math expression evaluation |"
        )
        lines.append(
            "| CSRF | Token + SameSite check |"
        )
        lines.append(
            "| WebSocket | Encryption + endpoints |"
        )
        lines.append(
            "| HTTP Host | Injection + reset poison |"
        )
        lines.append(
            "| Web Cache | Headers + deception |"
        )
        lines.append(
            "| OAuth | State + redirect_uri |"
        )
        lines.append(
            "| Prototype Pollution | Client + server |"
        )
        lines.append(
            "| Access Control | Admin + method + header |"
        )
        lines.append("")
        lines.append("### Limitations")
        lines.append(
            "- Business logic: Manual review needed"
        )
        lines.append(
            "- Race conditions: Not covered"
        )
        lines.append(
            "- Deserialization: App-specific"
        )
        lines.append(
            "- HTTP smuggling: Expert required"
        )
        lines.append("")
        lines.append(
            "*CONFIDENTIAL - Authorized personnel only*"
        )

        return {
            'markdown': '\n'.join(lines),
            'stats': stats,
            'generated_at': str(datetime.now()),
            'model': 'fallback'
        }

    def generate_pdf(
        self, markdown_content, output_path
    ):
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
            import re

            doc = SimpleDocTemplate(
                output_path, pagesize=A4,
                rightMargin=0.75 * inch,
                leftMargin=0.75 * inch,
                topMargin=0.75 * inch,
                bottomMargin=0.75 * inch
            )
            styles = getSampleStyleSheet()

            s_title = ParagraphStyle(
                'T', parent=styles['Title'],
                fontSize=24,
                textColor=colors.HexColor('#1a1a2e'),
                alignment=1, spaceAfter=16
            )
            s_h1 = ParagraphStyle(
                'H1', parent=styles['Heading1'],
                fontSize=16,
                textColor=colors.HexColor('#16213e'),
                spaceBefore=14, spaceAfter=8
            )
            s_h2 = ParagraphStyle(
                'H2', parent=styles['Heading2'],
                fontSize=13,
                textColor=colors.HexColor('#0f3460'),
                spaceBefore=10, spaceAfter=6
            )
            s_h3 = ParagraphStyle(
                'H3', parent=styles['Heading3'],
                fontSize=11,
                textColor=colors.HexColor('#e94560'),
                spaceBefore=8, spaceAfter=4
            )
            s_body = ParagraphStyle(
                'B', parent=styles['Normal'],
                fontSize=10, leading=14, spaceAfter=4
            )
            s_bullet = ParagraphStyle(
                'BL', parent=styles['Normal'],
                fontSize=10, leading=14,
                leftIndent=20, spaceAfter=2
            )

            story = []

            def process(text):
                text = text.replace('&', '&amp;')
                text = text.replace('<', '&lt;')
                text = text.replace('>', '&gt;')
                text = re.sub(
                    r'\*\*(.+?)\*\*',
                    r'<b>\1</b>', text
                )
                text = re.sub(
                    r'\*(.+?)\*',
                    r'<i>\1</i>', text
                )
                text = re.sub(
                    r'`(.+?)`',
                    r'<font name="Courier">\1</font>',
                    text
                )
                return text

            for line in markdown_content.split('\n'):
                s = line.strip()
                if not s:
                    story.append(
                        Spacer(1, 0.08 * inch)
                    )
                elif s.startswith('# '):
                    story.append(
                        Paragraph(s[2:], s_title)
                    )
                    story.append(
                        HRFlowable(
                            width='100%', thickness=2,
                            color=colors.HexColor('#1a1a2e')
                        )
                    )
                elif s.startswith('## '):
                    story.append(
                        Paragraph(s[3:], s_h1)
                    )
                elif s.startswith('### '):
                    story.append(
                        Paragraph(s[4:], s_h2)
                    )
                elif s.startswith('#### '):
                    story.append(
                        Paragraph(s[5:], s_h3)
                    )
                elif s.startswith('---'):
                    story.append(
                        HRFlowable(
                            width='100%', thickness=1,
                            color=colors.grey
                        )
                    )
                elif s.startswith(('- ', '* ')):
                    story.append(
                        Paragraph(
                            f"• {process(s[2:])}",
                            s_bullet
                        )
                    )
                elif s.startswith('|'):
                    if '---' in s:
                        continue
                    story.append(
                        Paragraph(
                            process(s), s_body
                        )
                    )
                elif s.startswith('>'):
                    story.append(
                        Paragraph(
                            process(s[1:].strip()),
                            s_body
                        )
                    )
                else:
                    try:
                        story.append(
                            Paragraph(
                                process(s), s_body
                            )
                        )
                    except Exception:
                        pass

            doc.build(story)
            return output_path

        except ImportError:
            return self._save_as_html(
                markdown_content, output_path
            )
        except Exception as e:
            print(f"  [!] PDF error: {e}")
            return self._save_as_html(
                markdown_content, output_path
            )

    def _save_as_html(
        self, markdown_content, output_path
    ):
        import re
        html_path = output_path.replace(
            '.pdf', '.html'
        )
        css = (
            "<style>body{font-family:Arial;"
            "max-width:900px;margin:40px auto;"
            "padding:0 20px;color:#333;line-height:1.6;}"
            "h1{color:#1a1a2e;border-bottom:"
            "3px solid #1a1a2e;padding-bottom:10px;}"
            "h2{color:#16213e;margin-top:30px;}"
            "h3{color:#0f3460;}h4{color:#e94560;}"
            "table{border-collapse:collapse;width:100%;}"
            "td,th{border:1px solid #ddd;padding:8px;}"
            "code{background:#f0f0f0;padding:2px 6px;}"
            "</style>"
        )
        html = ["<html><head>", css, "</head><body>"]
        for line in markdown_content.split('\n'):
            s = line.strip()
            if not s:
                html.append('<br>')
            elif s.startswith('# '):
                html.append(f"<h1>{s[2:]}</h1>")
            elif s.startswith('## '):
                html.append(f"<h2>{s[3:]}</h2>")
            elif s.startswith('### '):
                html.append(f"<h3>{s[4:]}</h3>")
            elif s.startswith('#### '):
                html.append(f"<h4>{s[5:]}</h4>")
            elif s.startswith('---'):
                html.append('<hr>')
            elif s.startswith(('- ', '* ')):
                html.append(f"<li>{s[2:]}</li>")
            elif s.startswith('|'):
                html.append(
                    f"<tr><td>{s}</td></tr>"
                )
            else:
                s = re.sub(
                    r'\*\*(.+?)\*\*',
                    r'<b>\1</b>', s
                )
                html.append(f"<p>{s}</p>")
        html.append("</body></html>")
        with open(
            html_path, 'w', encoding='utf-8'
        ) as f:
            f.write('\n'.join(html))
        print(f"  [!] HTML saved: {html_path}")
        return html_path
