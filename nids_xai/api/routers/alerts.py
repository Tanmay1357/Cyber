import io
from datetime import datetime
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse
from api.services.alert_store import alert_store

router = APIRouter()


@router.get("/api/alerts")
def get_alerts(
    limit: int = Query(default=100, ge=1, le=500),
    type: str = Query(default="all", pattern="^(all|attack|benign)$"),
):
    return alert_store.get(limit=limit, filter_type=type)


@router.post("/api/alerts/clear")
def clear_alerts():
    """Empty the in-memory alert buffer. Does not stop monitoring."""
    removed = alert_store.clear()
    return {"cleared": True, "removed": removed}


@router.get("/api/alerts/{alert_id}/report.pdf")
def alert_report_pdf(alert_id: str):
    """Generate a one-page PDF report for the given alert (prediction + SHAP)."""
    alert = alert_store.get_by_id(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found.")

    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
        )
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="reportlab not installed. Run: pip install reportlab",
        )

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=18*mm, rightMargin=18*mm, topMargin=15*mm, bottomMargin=15*mm,
        title=f"NIDS-XAI Alert {alert_id[:8]}",
    )
    styles = getSampleStyleSheet()
    h_style = ParagraphStyle("H", parent=styles["Heading1"], fontSize=18,
        textColor=colors.HexColor("#1d4ed8"), spaceAfter=4)
    sub_style = ParagraphStyle("Sub", parent=styles["Normal"], fontSize=9,
        textColor=colors.HexColor("#64748b"), spaceAfter=12)
    section_style = ParagraphStyle("Sec", parent=styles["Heading3"], fontSize=11,
        textColor=colors.HexColor("#1e293b"), spaceBefore=10, spaceAfter=4)

    is_attack   = bool(alert.get("is_attack"))
    prediction  = alert.get("prediction", "Attack" if is_attack else "Benign")
    attack_prob = float(alert.get("attack_prob", 1.0 if is_attack else 0.0))
    src_ip      = alert.get("src_ip") or alert.get("source_ip") or "—"
    dst_ip      = alert.get("dst_ip") or alert.get("destination_ip") or "—"
    src_port    = alert.get("src_port") or alert.get("source_port") or "—"
    dst_port    = alert.get("dst_port") or alert.get("destination_port") or "—"
    protocol    = alert.get("protocol") or "—"
    timestamp   = alert.get("timestamp") or alert.get("time") or datetime.now().isoformat()
    decision_conf = attack_prob if is_attack else 1.0 - attack_prob
    true_type   = alert.get("true_type")

    # Pull the same rich explanation the dashboard panel shows (full feature list
    # + plain-English narrative), falling back to stored factors if unavailable.
    rich = None
    try:
        from api.services.explainer_service import explainer_service
        from api.services.model_service import model_service
        if model_service.is_loaded:
            rich = explainer_service.explain(alert, model_service)
    except Exception:
        rich = None

    elements = []
    elements.append(Paragraph("NIDS-XAI Alert Report", h_style))
    elements.append(Paragraph(
        f"Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} · Alert ID {alert_id}",
        sub_style,
    ))

    # Verdict banner
    banner_color = colors.HexColor("#fee2e2") if is_attack else colors.HexColor("#dcfce7")
    text_color   = colors.HexColor("#991b1b") if is_attack else colors.HexColor("#14532d")
    banner = Table(
        [[
            Paragraph(f"<b>{prediction}</b>", ParagraphStyle("B", parent=styles["Normal"],
                fontSize=22, textColor=text_color, fontName="Helvetica-Bold")),
            Paragraph(f"<b>{decision_conf*100:.2f}%</b><br/>"
                      f"<font size='8' color='#475569'>confidence in this verdict</font>",
                ParagraphStyle("BV", parent=styles["Normal"], fontSize=14, textColor=text_color,
                    alignment=2, fontName="Helvetica-Bold")),
        ]],
        colWidths=[100*mm, 70*mm],
    )
    banner.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1, -1), banner_color),
        ("LINEBELOW",      (0, 0), (-1, 0),  1, text_color),
        ("VALIGN",         (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING",    (0, 0), (-1, -1), 12),
        ("RIGHTPADDING",   (0, 0), (-1, -1), 12),
        ("TOPPADDING",     (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 12),
    ]))
    elements.append(banner)
    if true_type:
        elements.append(Spacer(1, 4))
        elements.append(Paragraph(
            f"<font size='9' color='#475569'>True label for this flow (from the dataset): "
            f"<b>{true_type}</b></font>",
            styles["Normal"]))
    elements.append(Spacer(1, 8))

    # Connection details
    elements.append(Paragraph("Connection", section_style))
    conn_data = [
        ["Source",      f"{src_ip} : {src_port}"],
        ["Destination", f"{dst_ip} : {dst_port}"],
        ["Protocol",    str(protocol)],
        ["Timestamp",   str(timestamp)],
    ]
    conn = Table(conn_data, colWidths=[40*mm, 130*mm])
    conn.setStyle(TableStyle([
        ("FONTNAME",      (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 9),
        ("TEXTCOLOR",     (0, 0), (0, -1), colors.HexColor("#475569")),
        ("TEXTCOLOR",     (1, 0), (1, -1), colors.HexColor("#1e293b")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("LINEBELOW",     (0, 0), (-1, -2), 0.4, colors.HexColor("#e2e8f0")),
    ]))
    elements.append(conn)

    # SHAP contributions — prefer the full (trimmed) list from the rich explanation,
    # falling back to the 3 factors stored on the alert.
    feats = (rich or {}).get("features")
    if not feats:
        feats = [
            {"feature": f.get("feature"), "shap_value": float(f.get("value", 0)),
             "direction": "positive" if f.get("direction") == "attack" else "negative"}
            for f in (alert.get("shap_top3") or [])
        ]
    elements.append(Paragraph("Why the model reached this verdict (SHAP)", section_style))
    if feats:
        shap_rows = [["#", "Feature", "Direction", "Contribution"]]
        for i, f in enumerate(feats[:12], 1):
            direction_lbl = "→ Attack" if f.get("direction") == "positive" else "→ Benign"
            shap_rows.append([str(i), str(f.get("feature", "?")), direction_lbl,
                              f"{float(f.get('shap_value', 0)):+.4f}"])
        shap_tbl = Table(shap_rows, colWidths=[10*mm, 80*mm, 40*mm, 40*mm])
        shap_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#1d4ed8")),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 9),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("LINEBELOW",     (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
            ("ALIGN",         (3, 0), (3, -1), "RIGHT"),
        ]))
        elements.append(shap_tbl)
    else:
        elements.append(Paragraph("<i>No SHAP factors stored for this alert.</i>", styles["Normal"]))

    # Attack type (secondary classifier) and why
    if is_attack and (rich or {}).get("predicted_type"):
        pt = rich["predicted_type"]; ptc = rich.get("predicted_type_conf")
        elements.append(Paragraph("Attack type", section_style))
        line = f"Predicted attack type: <b>{pt}</b>"
        if ptc is not None:
            line += f"  ({ptc * 100:.0f}% confidence)"
        elements.append(Paragraph(line, styles["BodyText"]))
        try:
            import numpy as np
            from api.services.type_classifier_service import type_classifier_service
            from api.services.model_service import model_service as _ms
            feats = alert.get("features")
            if feats:
                te = type_classifier_service.explain_type(
                    np.array(feats, dtype=np.float32).reshape(1, -1),
                    _ms.dataset or "2017", _ms.feature_names, want_lime=False)
                if te and te.get("shap"):
                    top = [f["feature"] for f in te["shap"] if f["direction"] == "positive"][:4]
                    if top:
                        elements.append(Paragraph(
                            "Most characteristic features: " + ", ".join(top) + ".", styles["Normal"]))
        except Exception:
            pass

    # Plain-English explanation (same narrative as the app)
    summary = (rich or {}).get("summary")
    if summary:
        elements.append(Paragraph("Plain-English explanation", section_style))
        elements.append(Paragraph(summary.replace("\n", "<br/>"), styles["BodyText"]))

    # Recommended action
    elements.append(Paragraph("Recommended action", section_style))
    if is_attack:
        rec = (
            "<b>Investigate immediately.</b> Review the source IP for abuse history, correlate "
            "with other logs (firewall, WAF, host syslog) over the timestamp window, and consider "
            "rate-limiting or blocking the source if patterns repeat. Capture full packets if available."
        )
    else:
        rec = (
            "Logged as benign by the model. No action required, but the connection is recorded "
            "for audit. Manual review may be appropriate if business context contradicts the verdict."
        )
    elements.append(Paragraph(rec, styles["BodyText"]))

    # Footer
    elements.append(Spacer(1, 14))
    elements.append(Paragraph(
        "<font size='7' color='#94a3b8'>Generated by NIDS-XAI · "
        "Random Forest classifier with SHAP &amp; LIME explanations · "
        "This report reflects model output only and is not a substitute for human SOC analysis.</font>",
        styles["Normal"],
    ))

    doc.build(elements)
    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="alert-{alert_id[:8]}.pdf"',
        },
    )
