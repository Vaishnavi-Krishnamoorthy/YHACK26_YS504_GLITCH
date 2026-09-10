"""
Module: Executive Offline HTML Assurance Report Generator
Compiles pipeline audit findings from all 5 engines into a styled,
printable HTML report (reports/assurance_report.html) with 100% offline CSS.
"""

import os
import json
from datetime import datetime, timezone


def generate_html_report(assessment_data, output_path=None):
    """
    Generates a self-contained, air-gap compliant HTML report.
    Zero external CDNs or network requests.
    """
    timestamp = assessment_data.get("timestamp", datetime.now(timezone.utc).isoformat())
    score = assessment_data.get("composite_risk_score", 0)
    rec = assessment_data.get("recommendation", "REVIEW")
    flags = assessment_data.get("flags_raised", [])
    breakdown = assessment_data.get("module_breakdown", {})
    limitations = assessment_data.get("limitations", [
        "Evaluated in air-gapped mode using local symmetric HMAC signatures.",
        "Signal-frequency analysis is tailored for periodic and high-frequency adversarial triggers."
    ])

    # Color definitions
    if rec == "ACCEPT":
        theme_color = "#10b981"
        badge_bg = "#ecfdf5"
        badge_border = "#059669"
        badge_text = "#065f46"
        status_label = "CLEARED FOR DEPLOYMENT"
    elif rec == "REVIEW":
        theme_color = "#f59e0b"
        badge_bg = "#fffbeb"
        badge_border = "#d97706"
        badge_text = "#92400e"
        status_label = "MANUAL INSPECTION REQUIRED"
    else:
        theme_color = "#ef4444"
        badge_bg = "#fef2f2"
        badge_border = "#dc2626"
        badge_text = "#991b1b"
        status_label = "CRITICAL: PIPELINE QUARANTINED"

    flags_html = ""
    if flags:
        flags_html = "<ul class='flag-list'>" + "".join(f"<li><span class='bullet'>!</span> {f}</li>" for f in flags) + "</ul>"
    else:
        flags_html = "<p class='clean-msg'>All behavioral, architectural, and cryptographic integrity checks passed with zero flags.</p>"

    breakdown_rows = "".join(
        f"<tr><td><strong>{mod.replace('_', ' ').title()}</strong></td>"
        f"<td><span class='badge-pill {'pill-fail' if 'FAIL' in str(res) or 'DETECTED' in str(res) else 'pill-pass'}'>{res}</span></td></tr>"
        for mod, res in breakdown.items()
    )

    limitations_html = "".join(f"<li>{lim}</li>" for lim in limitations)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AEGIS-CV Assurance Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #f8fafc; color: #1e293b; padding: 32px; line-height: 1.5; }}
  .container {{ max-width: 900px; margin: 0 auto; background: #ffffff; border-radius: 12px; border: 1px solid #e2e8f0; box-shadow: 0 4px 12px rgba(0,0,0,0.05); overflow: hidden; }}
  .header {{ background: #0f172a; color: #ffffff; padding: 24px 32px; display: flex; justify-content: space-between; align-items: center; border-bottom: 4px solid {theme_color}; }}
  .logo {{ font-size: 24px; font-weight: 800; letter-spacing: -0.5px; }}
  .logo span {{ color: #ef4444; }}
  .sub-header {{ font-size: 13px; color: #94a3b8; margin-top: 4px; }}
  .seal {{ text-align: right; font-size: 11px; color: #cbd5e1; }}
  .seal-badge {{ display: inline-block; background: rgba(255,255,255,0.1); border: 1px solid rgba(255,255,255,0.2); border-radius: 6px; padding: 4px 10px; font-weight: 600; margin-bottom: 4px; }}
  .content {{ padding: 32px; }}
  
  /* Triage Box */
  .triage-card {{ background: {badge_bg}; border: 2px solid {badge_border}; border-radius: 10px; padding: 20px 24px; margin-bottom: 28px; display: flex; justify-content: space-between; align-items: center; }}
  .triage-title {{ font-size: 13px; font-weight: 700; text-transform: uppercase; color: {badge_text}; letter-spacing: 0.5px; }}
  .triage-verdict {{ font-size: 32px; font-weight: 900; color: {badge_text}; margin: 4px 0; }}
  .triage-desc {{ font-size: 13px; color: {badge_text}; opacity: 0.9; }}
  .score-gauge {{ text-align: center; min-width: 120px; }}
  .score-val {{ font-size: 40px; font-weight: 900; color: {theme_color}; line-height: 1; }}
  .score-lbl {{ font-size: 11px; color: #64748b; font-weight: 600; text-transform: uppercase; }}

  /* Sections */
  h3 {{ font-size: 16px; font-weight: 700; color: #0f172a; margin-bottom: 12px; border-bottom: 2px solid #f1f5f9; padding-bottom: 6px; }}
  .section {{ margin-bottom: 24px; }}
  
  /* Tables */
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 8px; }}
  th {{ background: #f8fafc; text-align: left; padding: 10px 14px; font-weight: 600; color: #475569; border-bottom: 2px solid #e2e8f0; }}
  td {{ padding: 10px 14px; border-bottom: 1px solid #f1f5f9; color: #334155; }}
  
  /* Pills & Badges */
  .badge-pill {{ display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 700; text-transform: uppercase; }}
  .pill-pass {{ background: #dcfce7; color: #166534; }}
  .pill-fail {{ background: #fee2e2; color: #991b1b; }}

  .flag-list {{ list-style: none; }}
  .flag-list li {{ background: #fff1f2; border-left: 4px solid #f43f5e; padding: 8px 12px; font-size: 13px; margin-bottom: 6px; border-radius: 0 6px 6px 0; color: #9f1239; }}
  .bullet {{ font-weight: 800; margin-right: 6px; }}
  .clean-msg {{ background: #f0fdf4; border-left: 4px solid #22c55e; padding: 10px 14px; font-size: 13px; color: #15803d; border-radius: 0 6px 6px 0; }}

  /* Limitations & Footer */
  .limitations {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px 18px; font-size: 12px; color: #64748b; }}
  .limitations ul {{ padding-left: 18px; margin-top: 6px; }}
  .footer {{ background: #f8fafc; border-top: 1px solid #e2e8f0; padding: 16px 32px; font-size: 11px; color: #94a3b8; display: flex; justify-content: space-between; }}
  
  @media print {{
    body {{ background: #ffffff; padding: 0; }}
    .container {{ border: none; box-shadow: none; max-width: 100%; }}
  }}
</style>
</head>
<body>

<div class="container">
  <div class="header">
    <div>
      <div class="logo">AEGIS<span>-CV</span></div>
      <div class="sub-header">Offline Computer Vision Assurance &amp; Cryptographic Provenance Suite</div>
    </div>
    <div class="seal">
      <div class="seal-badge">AIR-GAP CERTIFIED</div>
      <div>YHACK'26 | Challenge 22</div>
      <div>Team: GLITCH (YS504)</div>
    </div>
  </div>

  <div class="content">
    <!-- Triage Banner -->
    <div class="triage-card">
      <div>
        <div class="triage-title">Audit Recommendation</div>
        <div class="triage-verdict">{rec}</div>
        <div class="triage-desc">{status_label}</div>
      </div>
      <div class="score-gauge">
        <div class="score-val">{score}</div>
        <div class="score-lbl">Risk Score (0–100)</div>
      </div>
    </div>

    <!-- Active Flags -->
    <div class="section">
      <h3>1. Security &amp; Behavioral Findings</h3>
      {flags_html}
    </div>

    <!-- Module Coverage Table -->
    <div class="section">
      <h3>2. Cross-Layer Module Coverage</h3>
      <table>
        <thead>
          <tr>
            <th>Assurance Engine</th>
            <th>Verification Status</th>
          </tr>
        </thead>
        <tbody>
          {breakdown_rows}
        </tbody>
      </table>
    </div>

    <!-- Operational Limitations -->
    <div class="section">
      <h3>3. Coverage &amp; Operational Limitations</h3>
      <div class="limitations">
        <strong>Air-Gapped Execution Boundaries:</strong>
        <ul>
          {limitations_html}
        </ul>
      </div>
    </div>
  </div>

  <div class="footer">
    <div>Generated: {timestamp}</div>
    <div>Verifiable completely offline using SHA-256 Merkle Roots &amp; HMAC Receipts</div>
  </div>
</div>

</body>
</html>
"""

    if output_path:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

    return html_content
