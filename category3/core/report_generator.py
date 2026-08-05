"""
Advanced Report Generator - FAST REBUILD
Low overhead, faster stats, simpler prompts, faster PDF fallback.
"""
import json, re
from datetime import datetime
from groq import Groq


class AdvancedReportGenerator:
    def __init__(self, api_key):
        if not api_key:
            raise ValueError("GROQ_API_KEY is missing")
        self.client = Groq(api_key=api_key)
        self.model = "llama-3.3-70b-versatile"
        print(f"  [✓] Groq AI ready ({self.model})")

    def generate_full_report(self, target, scan_results, scan_duration=0):
        stats = self._calculate_stats(scan_results)
        compressed = self._compress_fast(target, scan_results, stats, scan_duration)
        prompt = (
            "You are a senior penetration tester. Write a professional advanced security assessment report.\n\n"
            f"{compressed}\n\n"
            "Sections required: Executive Summary, Scope/Methodology, Risk Summary Table, Critical Findings, High Findings, Medium Findings, Positive Findings, Remediation Roadmap, Technical Appendix. Include CVSS and CWE for each finding. Professional, concise, actionable."
        )
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role":"system","content":"Expert penetration tester writing professional security reports."},
                          {"role":"user","content":prompt}],
                max_tokens=5000, temperature=0.3
            )
            return {"markdown": response.choices[0].message.content,
                    "stats": stats,
                    "generated_at": str(datetime.now()),
                    "model": self.model}
        except Exception as e:
            print(f"  [!] AI failed: {e}")
            return self._generate_fallback_report(target, scan_results, scan_duration, stats)

    def _compress_fast(self, target, scan_results, stats, duration):
        lines = [f"=== ADVANCED SCAN SUMMARY ===\nTarget: {target}\nDuration: {duration}s\nRisk: Critical={stats['critical']}, High={stats['high']}, Medium={stats['medium']}, Low={stats['low']}\n"]
        agent_keys = [
            ('authentication','AUTHENTICATION'),('command_injection','COMMAND INJECTION'),
            ('file_upload','FILE UPLOAD'),('ssrf','SSRF'),('xxe','XXE'),
            ('nosql_injection','NOSQL'),('ssti','SSTI'),('csrf','CSRF'),
            ('websocket','WEBSOCKET'),('http_host_header','HOST HEADER'),
            ('web_cache','CACHE'),('oauth','OAUTH'),('prototype_pollution','PROTOTYPE POLLUTION'),
            ('access_control','ACCESS CONTROL')
        ]
        for key, label in agent_keys:
            findings = scan_results.get(key, [])
            if not isinstance(findings, list):
                continue
            lines.append(f"=== {label} ===")
            if not findings:
                lines.append("No findings.")
            else:
                for f in findings[:3]:
                    risk = f.get('risk', 'UNK')
                    ftype = f.get('type', '')
                    desc = f.get('description', '')[:150]
                    impact = f.get('business_impact', '')[:100]
                    fix = f.get('fix', '')[:150]
                    lines.append(f"[{risk}] {ftype}\n  Desc: {desc}\n  Impact: {impact}\n  Fix: {str(fix)[:150]}\n  CVSS: {f.get('cvss_score','N/A')} CWE: {f.get('cwe','N/A')}")
            lines.append('')
        return '\n'.join(lines)

    def _calculate_stats(self, results):
        stats = {'critical':0,'high':0,'medium':0,'low':0}
        for findings in results.values():
            if not isinstance(findings, list):
                continue
            for f in findings:
                r = f.get('risk','').upper()
                if r == 'CRITICAL': stats['critical'] += 1
                elif r == 'HIGH': stats['high'] += 1
                elif r == 'MEDIUM': stats['medium'] += 1
                elif r in ['LOW','INFO']: stats['low'] += 1
        return stats

    def _generate_fallback_report(self, target, scan_results, scan_duration, stats):
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        total = sum(stats.values())
        risk_rating = 'CRITICAL' if stats['critical']>0 else 'HIGH' if stats['high']>0 else 'MEDIUM' if stats['medium']>0 else 'LOW'
        lines = [f"# Advanced Security Assessment Report\n| Field | Details |\n| --- | --- |\n| Target | {target} |\n| Date | {now} |\n| Duration | {scan_duration}s |\n| Risk Rating | {risk_rating} |\n\n## Executive Summary\nTotal findings: {total} (Critical: {stats['critical']}, High: {stats['high']}, Medium: {stats['medium']}, Low: {stats['low']})."]
        agent_map = [
            ('authentication','Authentication'),('command_injection','Command Injection'),
            ('file_upload','File Upload'),('ssrf','SSRF'),('xxe','XXE'),
            ('nosql_injection','NoSQL'),('ssti','SSTI'),('csrf','CSRF'),
            ('websocket','WebSocket'),('http_host_header','Host Header'),
            ('web_cache','Cache'),('oauth','OAuth'),('prototype_pollution','Prototype Pollution'),
            ('access_control','Access Control')
        ]
        lines.append("\n## Detailed Findings\n")
        for key, label in agent_map:
            findings = scan_results.get(key, [])
            if not isinstance(findings, list):
                continue
            lines.append(f"### {label}\n")
            if not findings:
                lines.append(f"- No {label} findings.\n")
            else:
                for f in findings:
                    r = f.get('risk','UNKNOWN')
                    ftype = f.get('type','Unknown')
                    desc = f.get('description','')
                    fix = f.get('fix','')
                    lines.append(f"#### [{r}] {ftype}\n**Description:** {desc}\n**Fix:** {str(fix)[:200]}\nCVSS: {f.get('cvss_score','N/A')} | CWE: {f.get('cwe','N/A')}\n")
        lines.append("\n## Remediation Roadmap\n### Immediate\n- Address critical findings\n### This Week\n- Address high findings\n### This Month\n- Address medium findings, code review, dependency updates\n\n*CONFIDENTIAL - Authorized personnel only*")
        return {"markdown":"\n".join(lines),"stats":stats,"generated_at":str(datetime.now()),"model":"fallback"}

    def generate_pdf(self, markdown_content, output_path):
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.lib import colors
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, HRFlowable
            doc = SimpleDocTemplate(output_path, pagesize=A4, rightMargin=0.75*inch, leftMargin=0.75*inch, topMargin=0.75*inch, bottomMargin=0.75*inch)
            styles = getSampleStyleSheet()
            s_title = ParagraphStyle('T', parent=styles['Title'], fontSize=20, textColor=colors.HexColor('#1a1a2e'), alignment=1, spaceAfter=12)
            s_h1 = ParagraphStyle('H1', parent=styles['Heading1'], fontSize=14, textColor=colors.HexColor('#16213e'), spaceBefore=10, spaceAfter=6)
            s_body = ParagraphStyle('B', parent=styles['Normal'], fontSize=9, leading=12, spaceAfter=3)
            story = []
            for line in markdown_content.split('\n'):
                s = line.strip()
                if s.startswith('# '): story.append(Paragraph(s[2:], s_title)); story.append(HRFlowable(width='100%', thickness=2, color=colors.HexColor('#1a1a2e')))
                elif s.startswith('## '): story.append(Paragraph(s[3:], s_h1))
                elif s.startswith('- '): story.append(Paragraph(f"• {re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', s[2:])}", s_body))
                elif s.startswith('|') and '---' not in s: story.append(Paragraph(s, s_body))
                elif s: story.append(Paragraph(re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', s), s_body))
            doc.build(story)
            return output_path
        except Exception as e:
            print(f"  [!] PDF error: {e} — saving HTML fallback")
            return self._save_as_html(markdown_content, output_path)

    def _save_as_html(self, markdown_content, output_path):
        import re
        html_path = output_path.replace('.pdf', '.html')
        css = "<style>body{font-family:Arial,sans-serif;max-width:900px;margin:40px auto;padding:0 20px;color:#333;line-height:1.6;}h1{color:#1a1a2e;border-bottom:3px solid #1a1a2e;padding-bottom:10px;}h2{color:#16213e;margin-top:24px;}table{border-collapse:collapse;width:100%;}th,td{border:1px solid #ccc;padding:6px;}code{background:#f0f0f0;padding:2px 4px;}</style>"
        html = ["<html><head>", css, "</head><body>"]
        for line in markdown_content.split('\n'):
            s = line.strip()
            if not s: html.append('<br>')
            elif s.startswith('# '): html.append(f"<h1>{s[2:]}</h1>")
            elif s.startswith('## '): html.append(f"<h2>{s[3:]}</h2>")
            elif s.startswith('### '): html.append(f"<h3>{s[4:]}</h3>")
            elif s.startswith('- '): html.append(f"<li>{re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', s[2:])}</li>")
            elif s.startswith('|') and '---' not in s: html.append(f"<p>{s}</p>")
            else: html.append(f"<p>{re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', s)}</p>")
        html.append("</body></html>")
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(''.join(html))
        print(f"  [!] HTML saved: {html_path}")
        return html_path
