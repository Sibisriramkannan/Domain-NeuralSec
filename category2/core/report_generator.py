import json
import os
from datetime import datetime

from groq import Groq


class ActiveReportGenerator:
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
                "Write a professional security assessment "
                "report based on this scan data.\n\n"
                f"{compressed}\n\n"
                "Write the report with these sections:\n"
                "# Active Security Assessment Report\n"
                "## Executive Summary\n"
                "## Scope and Methodology\n"
                "## Risk Summary\n"
                "## Critical Findings\n"
                "## High Risk Findings\n"
                "## Medium Risk Findings\n"
                "## Positive Findings\n"
                "## Remediation Roadmap\n"
                "## Technical Appendix\n\n"
                "Be professional, specific, and actionable. "
                "Include CVSS scores and CWE IDs."
            )

            response = (
                self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {
                            "role": "system",
                            "content": (
                                "You are an expert "
                                "penetration tester writing "
                                "professional reports."
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

            markdown = (
                response.choices[0]
                .message.content
            )

            return {
                "markdown": markdown,
                "stats": stats,
                "generated_at": str(datetime.now()),
                "model": self.model
            }

        except Exception as e:
            print(
                f"  [!] AI report failed: {e}"
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
        lines.append("=== SCAN SUMMARY ===")
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
            ('sql_injection', 'SQL INJECTION'),
            ('xss', 'CROSS-SITE SCRIPTING'),
            ('path_traversal', 'PATH TRAVERSAL'),
            ('cors', 'CORS'),
            ('graphql', 'GRAPHQL'),
            ('jwt', 'JWT'),
            ('api', 'API SECURITY'),
        ]

        for key, label in agent_keys:
            findings = scan_results.get(key, [])
            if not isinstance(findings, list):
                continue
            lines.append(f"=== {label} ===")
            if not findings:
                lines.append("No findings detected.")
            else:
                for f in findings[:5]:
                    risk = f.get('risk', 'UNKNOWN')
                    ftype = f.get('type', 'Unknown')
                    desc = f.get('description', '')
                    impact = f.get(
                        'business_impact', ''
                    )
                    fix = f.get('fix', '')
                    cvss = f.get('cvss_score', '')
                    cwe = f.get('cwe', '')
                    lines.append(
                        f"[{risk}] {ftype}"
                    )
                    if desc:
                        lines.append(
                            f"  Description: {desc[:200]}"
                        )
                    if impact:
                        lines.append(
                            f"  Impact: {impact[:150]}"
                        )
                    if fix:
                        lines.append(
                            f"  Fix: {str(fix)[:200]}"
                        )
                    if cvss:
                        lines.append(
                            f"  CVSS: {cvss}"
                        )
                    if cwe:
                        lines.append(
                            f"  CWE: {cwe}"
                        )
                    lines.append("")
            lines.append("")

        return '\n'.join(lines)

    def _calculate_stats(self, results):
        stats = {
            'critical': 0, 'high': 0,
            'medium': 0, 'low': 0
        }

        for key, findings in results.items():
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
        total = (
            stats['critical'] + stats['high']
            + stats['medium'] + stats['low']
        )

        if stats['critical'] > 0:
            risk_rating = 'CRITICAL'
        elif stats['high'] > 0:
            risk_rating = 'HIGH'
        elif stats['medium'] > 0:
            risk_rating = 'MEDIUM'
        else:
            risk_rating = 'LOW'

        lines = []

        # Header
        lines.append(
            "# Active Security Assessment Report"
        )
        lines.append("")
        lines.append(
            "| Field | Details |"
        )
        lines.append("| --- | --- |")
        lines.append(f"| Target | {target} |")
        lines.append(f"| Date | {now} |")
        lines.append(
            f"| Duration | {scan_duration}s |"
        )
        lines.append(
            "| Type | Semi-Active Security Assessment |"
        )
        lines.append(
            "| Classification | CONFIDENTIAL |"
        )
        lines.append("")

        # Executive Summary
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(
            f"This assessment identified **{total} "
            f"total findings** against {target}. "
            f"The overall risk rating is **{risk_rating}**."
        )
        lines.append("")
        lines.append(
            f"- Critical Findings: {stats['critical']}"
        )
        lines.append(
            f"- High Risk Findings: {stats['high']}"
        )
        lines.append(
            f"- Medium Risk Findings: {stats['medium']}"
        )
        lines.append(
            f"- Low Risk Findings: {stats['low']}"
        )
        lines.append("")

        if stats['critical'] > 0:
            lines.append(
                "> CRITICAL vulnerabilities require "
                "immediate remediation within 24-48 hours."
            )
        elif stats['high'] > 0:
            lines.append(
                "> HIGH risk findings should be "
                "addressed within 1 week."
            )
        else:
            lines.append(
                "> No critical issues detected. "
                "Address medium findings this month."
            )
        lines.append("")

        # Findings by Agent
        agent_keys = [
            ('sql_injection', 'SQL Injection'),
            ('xss', 'Cross-Site Scripting (XSS)'),
            ('path_traversal', 'Path Traversal'),
            ('cors', 'CORS Misconfiguration'),
            ('graphql', 'GraphQL Security'),
            ('jwt', 'JWT Vulnerabilities'),
            ('api', 'API Security'),
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
                lines.append(
                    f"- No {label} issues detected."
                )
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
                param = f.get('parameter', '')

                risk_icon = (
                    'CRITICAL'
                    if risk == 'CRITICAL'
                    else 'HIGH'
                    if risk == 'HIGH'
                    else 'MEDIUM'
                    if risk == 'MEDIUM'
                    else 'LOW'
                )

                lines.append(
                    f"#### [{risk_icon}] {ftype}"
                )
                lines.append("")
                lines.append(
                    "| Field | Details |"
                )
                lines.append("| --- | --- |")
                lines.append(
                    f"| Severity | {risk} |"
                )
                if cvss != 'N/A':
                    lines.append(
                        f"| CVSS Score | {cvss} |"
                    )
                if cwe != 'N/A':
                    lines.append(
                        f"| CWE | {cwe} |"
                    )
                if url:
                    lines.append(
                        f"| URL | {url[:80]} |"
                    )
                if param:
                    lines.append(
                        f"| Parameter | {param} |"
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
                lines.append("**Remediation:**")
                if isinstance(fix, str):
                    for step in fix.split('\n'):
                        if step.strip():
                            lines.append(
                                f"- {step.strip()}"
                            )
                else:
                    lines.append(f"- {fix}")
                lines.append("")

        # Positive Findings
        lines.append("## Positive Security Findings")
        lines.append("")
        positives = []
        if not scan_results.get('sql_injection'):
            positives.append(
                "No SQL injection vulnerabilities detected"
            )
        if not scan_results.get('path_traversal'):
            positives.append(
                "No path traversal vulnerabilities detected"
            )
        if not scan_results.get('cors'):
            positives.append(
                "CORS configuration appears correct"
            )
        if positives:
            for p in positives:
                lines.append(f"- {p}")
        else:
            lines.append(
                "- Site has active defenses "
                "but requires improvements"
            )
        lines.append("")

        # Remediation Roadmap
        lines.append("## Remediation Roadmap")
        lines.append("")

        critical_items = []
        high_items = []
        medium_items = []

        for key, findings in scan_results.items():
            if not isinstance(findings, list):
                continue
            for f in findings:
                risk = f.get('risk', '')
                ftype = f.get('type', '')
                if risk == 'CRITICAL':
                    critical_items.append(ftype)
                elif risk == 'HIGH':
                    high_items.append(ftype)
                elif risk == 'MEDIUM':
                    medium_items.append(ftype)

        lines.append(
            "### Immediate (24-48 Hours)"
        )
        if critical_items:
            for item in critical_items:
                lines.append(f"- Fix: {item}")
        else:
            lines.append(
                "- No critical items requiring "
                "immediate action"
            )
        lines.append("")

        lines.append("### Short Term (This Week)")
        if high_items:
            for item in high_items:
                lines.append(f"- Address: {item}")
        else:
            lines.append(
                "- No high priority items "
                "this week"
            )
        lines.append("")

        lines.append("### Medium Term (This Month)")
        if medium_items:
            for item in medium_items:
                lines.append(f"- Review: {item}")
        else:
            lines.append(
                "- Review medium risk items"
            )
        lines.append("")

        lines.append("### Ongoing")
        lines.append(
            "- Schedule monthly security assessments"
        )
        lines.append(
            "- Implement security code review process"
        )
        lines.append(
            "- Keep all dependencies updated"
        )
        lines.append(
            "- Train development team on OWASP Top 10"
        )
        lines.append("")

        # Technical Appendix
        lines.append("## Technical Appendix")
        lines.append("")
        lines.append("### Scan Coverage")
        lines.append("")
        lines.append(
            "| Agent | Tests Performed |"
        )
        lines.append("| --- | --- |")
        lines.append(
            "| SQLi | Error-based, Time-based blind |"
        )
        lines.append(
            "| XSS | Reflected, DOM indicators |"
        )
        lines.append(
            "| Path Traversal | LFI, file inclusion |"
        )
        lines.append(
            "| CORS | Origin reflection, wildcard |"
        )
        lines.append(
            "| GraphQL | Introspection, batching |"
        )
        lines.append(
            "| JWT | Algorithm, weak secrets, expiry |"
        )
        lines.append(
            "| API | BOLA, HTTP methods, rate limits |"
        )
        lines.append("")

        lines.append("### Important Limitations")
        lines.append("")
        lines.append(
            "This tool detects INDICATORS, "
            "not confirmed exploits."
        )
        lines.append(
            "Manual expert review is required for:"
        )
        lines.append(
            "- Business logic vulnerabilities"
        )
        lines.append(
            "- Complex authentication bypasses"
        )
        lines.append("- Race conditions")
        lines.append(
            "- Advanced chained attack scenarios"
        )
        lines.append(
            "- Server-side deserialization"
        )
        lines.append(
            "- Stored XSS (requires login)"
        )
        lines.append("")
        lines.append(
            "*This report is CONFIDENTIAL and intended "
            "only for authorized personnel.*"
        )

        markdown = '\n'.join(lines)

        return {
            'markdown': markdown,
            'stats': stats,
            'generated_at': str(datetime.now()),
            'model': 'fallback'
        }

    def generate_pdf(self, markdown_content, output_path):
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

            style_title = ParagraphStyle(
                'CustomTitle',
                parent=styles['Title'],
                fontSize=24,
                textColor=colors.HexColor('#1a1a2e'),
                alignment=1,
                spaceAfter=16
            )
            style_h1 = ParagraphStyle(
                'CustomH1',
                parent=styles['Heading1'],
                fontSize=16,
                textColor=colors.HexColor('#16213e'),
                spaceBefore=14,
                spaceAfter=8
            )
            style_h2 = ParagraphStyle(
                'CustomH2',
                parent=styles['Heading2'],
                fontSize=13,
                textColor=colors.HexColor('#0f3460'),
                spaceBefore=10,
                spaceAfter=6
            )
            style_h3 = ParagraphStyle(
                'CustomH3',
                parent=styles['Heading3'],
                fontSize=11,
                textColor=colors.HexColor('#e94560'),
                spaceBefore=8,
                spaceAfter=4
            )
            style_body = ParagraphStyle(
                'CustomBody',
                parent=styles['Normal'],
                fontSize=10,
                leading=14,
                spaceAfter=4
            )
            style_bullet = ParagraphStyle(
                'CustomBullet',
                parent=styles['Normal'],
                fontSize=10,
                leading=14,
                leftIndent=20,
                spaceAfter=2
            )

            story = []

            for line in markdown_content.split('\n'):
                stripped = line.strip()

                if not stripped:
                    story.append(
                        Spacer(1, 0.08 * inch)
                    )
                    continue

                if stripped.startswith('# '):
                    text = stripped[2:].strip()
                    story.append(
                        Paragraph(text, style_title)
                    )
                    story.append(
                        HRFlowable(
                            width='100%',
                            thickness=2,
                            color=colors.HexColor(
                                '#1a1a2e'
                            )
                        )
                    )

                elif stripped.startswith('## '):
                    text = stripped[3:].strip()
                    story.append(
                        Paragraph(text, style_h1)
                    )

                elif stripped.startswith('### '):
                    text = stripped[4:].strip()
                    story.append(
                        Paragraph(text, style_h2)
                    )

                elif stripped.startswith('#### '):
                    text = stripped[5:].strip()
                    story.append(
                        Paragraph(text, style_h3)
                    )

                elif stripped.startswith('---'):
                    story.append(
                        HRFlowable(
                            width='100%',
                            thickness=1,
                            color=colors.grey
                        )
                    )

                elif (
                    stripped.startswith('- ')
                    or stripped.startswith('* ')
                ):
                    text = stripped[2:].strip()
                    text = self._process_inline(text)
                    story.append(
                        Paragraph(
                            f"• {text}", style_bullet
                        )
                    )

                elif stripped[0].isdigit() and (
                    stripped[1:3] in ['. ', ') ']
                    or (
                        len(stripped) > 2
                        and stripped[1].isdigit()
                        and stripped[2:4] in ['. ', ') ']
                    )
                ):
                    text = self._process_inline(stripped)
                    story.append(
                        Paragraph(text, style_bullet)
                    )

                elif stripped.startswith('|'):
                    text = stripped.replace(
                        '|', ' | '
                    ).strip()
                    if '---' in text:
                        continue
                    text = self._process_inline(text)
                    story.append(
                        Paragraph(text, style_body)
                    )

                elif stripped.startswith('>'):
                    text = stripped[1:].strip()
                    text = self._process_inline(text)
                    note_style = ParagraphStyle(
                        'Note',
                        parent=style_body,
                        leftIndent=20,
                        textColor=colors.HexColor(
                            '#555555'
                        ),
                        backColor=colors.HexColor(
                            '#f5f5f5'
                        )
                    )
                    story.append(
                        Paragraph(text, note_style)
                    )

                else:
                    text = self._process_inline(stripped)
                    story.append(
                        Paragraph(text, style_body)
                    )

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

    def _process_inline(self, text):
        import re
        text = text.replace('&', '&amp;')
        text = text.replace('<', '&lt;')
        text = text.replace('>', '&gt;')
        text = re.sub(
            r'\*\*(.+?)\*\*',
            r'<b>\1</b>',
            text
        )
        text = re.sub(
            r'\*(.+?)\*',
            r'<i>\1</i>',
            text
        )
        text = re.sub(
            r'`(.+?)`',
            r'<font name="Courier">\1</font>',
            text
        )
        return text

    def _save_as_html(
        self, markdown_content, output_path
    ):
        html_path = output_path.replace(
            '.pdf', '.html'
        )
        css = (
            "<style>"
            "body{font-family:Arial,sans-serif;"
            "max-width:900px;margin:40px auto;"
            "padding:0 20px;color:#333;"
            "line-height:1.6;}"
            "h1{color:#1a1a2e;border-bottom:"
            "3px solid #1a1a2e;padding-bottom:10px;}"
            "h2{color:#16213e;margin-top:30px;}"
            "h3{color:#0f3460;}"
            "h4{color:#e94560;}"
            "table{border-collapse:collapse;"
            "width:100%;margin:10px 0;}"
            "td,th{border:1px solid #ddd;"
            "padding:8px;text-align:left;}"
            "tr:nth-child(even){background:#f9f9f9;}"
            "blockquote{background:#f5f5f5;"
            "border-left:4px solid #0f3460;"
            "padding:10px 20px;margin:10px 0;}"
            "code{background:#f0f0f0;"
            "padding:2px 6px;border-radius:3px;"
            "font-family:Courier,monospace;}"
            "hr{border:1px solid #ddd;margin:20px 0;}"
            "</style>"
        )

        html_lines = [
            "<html><head>",
            "<meta charset='utf-8'>",
            f"<title>Security Report - {output_path}</title>",
            css,
            "</head><body>"
        ]

        import re
        for line in markdown_content.split('\n'):
            s = line.strip()
            if not s:
                html_lines.append('<br>')
            elif s.startswith('# '):
                html_lines.append(
                    f"<h1>{s[2:]}</h1>"
                )
            elif s.startswith('## '):
                html_lines.append(
                    f"<h2>{s[3:]}</h2>"
                )
            elif s.startswith('### '):
                html_lines.append(
                    f"<h3>{s[4:]}</h3>"
                )
            elif s.startswith('#### '):
                html_lines.append(
                    f"<h4>{s[5:]}</h4>"
                )
            elif s.startswith('---'):
                html_lines.append('<hr>')
            elif s.startswith('- ') or s.startswith('* '):
                html_lines.append(
                    f"<li>{s[2:]}</li>"
                )
            elif s.startswith('|'):
                html_lines.append(
                    f"<tr><td>{s}</td></tr>"
                )
            elif s.startswith('>'):
                html_lines.append(
                    f"<blockquote>{s[1:]}</blockquote>"
                )
            else:
                s = re.sub(
                    r'\*\*(.+?)\*\*',
                    r'<b>\1</b>', s
                )
                s = re.sub(
                    r'\*(.+?)\*',
                    r'<i>\1</i>', s
                )
                s = re.sub(
                    r'`(.+?)`',
                    r'<code>\1</code>', s
                )
                html_lines.append(f"<p>{s}</p>")

        html_lines.append("</body></html>")

        with open(
            html_path, 'w', encoding='utf-8'
        ) as f:
            f.write('\n'.join(html_lines))

        print(
            f"  [!] PDF failed - HTML saved: {html_path}"
        )
        return html_path
