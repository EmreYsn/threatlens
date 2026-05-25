import io
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)

def _register_fonts():
    """Türkçe karakter destekli font kaydet"""
    import os
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    font_options = [
        # Windows - Segoe UI (en iyi Türkçe destek)
        ('C:/Windows/Fonts/segoeui.ttf', 'C:/Windows/Fonts/segoeuib.ttf'),
        # Windows - Arial
        ('C:/Windows/Fonts/arial.ttf', 'C:/Windows/Fonts/arialbd.ttf'),
        # Linux
        ('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf', '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf'),
    ]

    for regular_path, bold_path in font_options:
        if os.path.exists(regular_path):
            try:
                pdfmetrics.registerFont(TTFont('TRFont', regular_path))
                if os.path.exists(bold_path):
                    pdfmetrics.registerFont(TTFont('TRFont-Bold', bold_path))
                else:
                    pdfmetrics.registerFont(TTFont('TRFont-Bold', regular_path))
                
                # Default font olarak ayarla
                from reportlab.lib.fonts import addMapping
                addMapping('TRFont', 0, 0, 'TRFont')
                addMapping('TRFont', 1, 0, 'TRFont-Bold')
                
                return 'TRFont', 'TRFont-Bold'
            except Exception:
                continue

    return 'Helvetica', 'Helvetica-Bold'

def generate_ioc_report(ioc, breakdown=None):
    """IOC için PDF rapor oluştur"""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
    )

    font_regular, font_bold = _register_fonts()
    styles = getSampleStyleSheet()

    # Custom stiller
    styles.add(ParagraphStyle(
        'ThreatTitle',
        parent=styles['Title'],
        fontName=font_bold,
        fontSize=22,
        textColor=colors.HexColor('#00b894'),
        spaceAfter=5,
    ))
    styles.add(ParagraphStyle(
        'SectionTitle',
        parent=styles['Heading2'],
        fontName=font_bold,
        fontSize=14,
        textColor=colors.HexColor('#0984e3'),
        spaceBefore=15,
        spaceAfter=8,
    ))
    styles.add(ParagraphStyle(
        'InfoText',
        parent=styles['Normal'],
        fontName=font_regular,
        fontSize=10,
        spaceAfter=3,
    ))
    styles.add(ParagraphStyle(
        'SmallGray',
        parent=styles['Normal'],
        fontName=font_regular,
        fontSize=8,
        textColor=colors.gray,
    ))

    def tr(text):
        """Türkçe karakter düzeltme for plain table cells"""
        if not isinstance(text, str):
            text = str(text)
        replacements = {
            'ı': 'ı', 'İ': 'İ', 'ş': 'ş', 'Ş': 'Ş',
            'ğ': 'ğ', 'Ğ': 'Ğ', 'ü': 'ü', 'Ü': 'Ü',
            'ö': 'ö', 'Ö': 'Ö', 'ç': 'ç', 'Ç': 'Ç',
        }
        return text

    elements = []

    # ──────── BAŞLIK ────────
    elements.append(Paragraph('ThreatLens', styles['ThreatTitle']))
    elements.append(Paragraph('Siber Tehdit İstihbaratı Raporu', styles['SmallGray']))
    elements.append(Spacer(1, 5 * mm))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#00b894')))
    elements.append(Spacer(1, 5 * mm))

    # ──────── ÖZET BİLGİLER ────────
    severity_colors = {
        'safe': colors.HexColor('#00b894'),
        'suspicious': colors.HexColor('#fdcb6e'),
        'malicious': colors.HexColor('#e74c3c'),
    }
    severity_labels = {
        'safe': 'GÜVENLİ',
        'suspicious': 'ŞÜPHELİ',
        'malicious': 'TEHLİKELİ',
    }
    sev_color = severity_colors.get(ioc.severity, colors.gray)
    sev_label = severity_labels.get(ioc.severity, ioc.severity)

    type_labels = {
        'ip': 'IP Adresi', 'domain': 'Domain',
        'url': 'URL', 'hash': 'Hash', 'email': 'Email',
    }

    summary_data = [
        ['IOC Değeri', ioc.value],
        ['IOC Tipi', type_labels.get(ioc.ioc_type, ioc.ioc_type)],
        ['Tehdit Skoru', f'{ioc.threat_score}/100'],
        ['Seviye', sev_label],
        ['İlk Sorgu', ioc.first_seen.strftime('%d/%m/%Y %H:%M') if ioc.first_seen else '-'],
        ['Sorgu Sayısı', str(ioc.query_count)],
    ]

    summary_table = Table(summary_data, colWidths=[45 * mm, 120 * mm])
    summary_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), font_bold),
        ('FONTNAME', (1, 0), (1, -1), font_regular),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('TEXTCOLOR', (1, 2), (1, 2), sev_color),  # skor rengi
        ('TEXTCOLOR', (1, 3), (1, 3), sev_color),  # seviye rengi
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('LINEBELOW', (0, 0), (-1, -2), 0.5, colors.HexColor('#e0e0e0')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 5 * mm))

    # ──────── AbuseIPDB ────────
    if ioc.abuseipdb_data:
        elements.append(Paragraph('AbuseIPDB', styles['SectionTitle']))
        data = ioc.abuseipdb_data
        abuse_rows = [
            ['Abuse Skoru', f'{data.get("abuse_confidence_score", "-")}/100'],
            ['Toplam Rapor', str(data.get('total_reports', '-'))],
            ['Raporlayan Kullanıcı', str(data.get('num_distinct_users', '-'))],
            ['ISP', str(data.get('isp', '-'))],
            ['Domain', str(data.get('domain', '-'))],
            ['Kullanım Tipi', str(data.get('usage_type', '-'))],
            ['Tor Exit Node', 'Evet' if data.get('is_tor') else 'Hayır'],
        ]
        t = Table(abuse_rows, colWidths=[45 * mm, 120 * mm])
        t.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), font_bold),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('LINEBELOW', (0, 0), (-1, -2), 0.5, colors.HexColor('#e0e0e0')),
        ]))
        elements.append(t)

    # ──────── VirusTotal ────────
    if ioc.virustotal_data:
        elements.append(Paragraph('VirusTotal', styles['SectionTitle']))
        data = ioc.virustotal_data
        vt_rows = [
            ['Kötü Tespit', str(data.get('malicious', 0))],
            ['Şüpheli', str(data.get('suspicious', 0))],
            ['Zararsız', str(data.get('harmless', 0))],
            ['Toplam Motor', str(data.get('total_vendors', 0))],
            ['Reputation', str(data.get('reputation', 0))],
        ]
        if data.get('meaningful_name'):
            vt_rows.append(['Dosya Adı', data['meaningful_name']])
        if data.get('type_description'):
            vt_rows.append(['Dosya Tipi', data['type_description']])

        t = Table(vt_rows, colWidths=[45 * mm, 120 * mm])
        t.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), font_bold),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('LINEBELOW', (0, 0), (-1, -2), 0.5, colors.HexColor('#e0e0e0')),
        ]))
        elements.append(t)

    # ──────── AlienVault OTX ────────
    if ioc.alienvault_data:
        elements.append(Paragraph('AlienVault OTX', styles['SectionTitle']))
        data = ioc.alienvault_data
        otx_rows = [
            ['Pulse Sayısı', str(data.get('pulse_count', 0))],
        ]
        if data.get('threat_score'):
            otx_rows.append(['Tehdit Skoru', str(data['threat_score'])])
        if data.get('activities'):
            otx_rows.append(['Aktiviteler', ', '.join(data['activities'][:5])])
        if data.get('pulse_names'):
            for i, name in enumerate(data['pulse_names'][:3]):
                otx_rows.append([f'Pulse #{i+1}', name[:80]])

        t = Table(otx_rows, colWidths=[45 * mm, 120 * mm])
        t.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), font_bold),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('LINEBELOW', (0, 0), (-1, -2), 0.5, colors.HexColor('#e0e0e0')),
        ]))
        elements.append(t)

    # ──────── ipinfo.io ────────
    if ioc.ipinfo_data:
        elements.append(Paragraph('ipinfo.io - Konum', styles['SectionTitle']))
        data = ioc.ipinfo_data
        geo_rows = [
            ['Şehir', str(data.get('city', '-'))],
            ['Bölge', str(data.get('region', '-'))],
            ['Ülke', str(data.get('country_name', '-'))],
            ['Organizasyon', str(data.get('org_name', '-'))],
            ['ASN', str(data.get('asn', '-'))],
            ['Hostname', str(data.get('hostname', '-'))],
            ['Zaman Dilimi', str(data.get('timezone', '-'))],
        ]
        t = Table(geo_rows, colWidths=[45 * mm, 120 * mm])
        t.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), font_bold),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('LINEBELOW', (0, 0), (-1, -2), 0.5, colors.HexColor('#e0e0e0')),
        ]))
        elements.append(t)

    # ──────── SKOR DETAYI ────────
    if breakdown:
        elements.append(Paragraph('Skor Detayı', styles['SectionTitle']))
        score_rows = [['Kaynak', 'Ağırlık', 'Skor', 'Detay']]
        for item in breakdown:
            score_rows.append([
                item['source'],
                f'%{item["weight"]}',
                f'{item["score"]}/100',
                item['details'][:60],
            ])

        # Tablo hücrelerini Paragraph'a çevir (Türkçe karakter desteği)
        styled_rows = []
        for i, row in enumerate(score_rows):
            if i == 0:
                # Header satırı bold
                styled_rows.append([
                    Paragraph(f'<b>{cell}</b>', ParagraphStyle('cell', fontName=font_bold, fontSize=8, textColor=colors.white))
                    for cell in row
                ])
            else:
                styled_rows.append([
                    Paragraph(str(cell), ParagraphStyle('cell', fontName=font_regular, fontSize=8))
                    for cell in row
                ])
        score_rows = styled_rows
        
        t = Table(score_rows, colWidths=[35 * mm, 20 * mm, 20 * mm, 90 * mm])
        t.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, 0), font_bold),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2d3436')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('LINEBELOW', (0, 0), (-1, -1), 0.5, colors.HexColor('#e0e0e0')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e0e0e0')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        elements.append(t)

    # ──────── NOTLAR ────────
    notes = ioc.notes.all()
    if notes:
        elements.append(Paragraph('Notlar', styles['SectionTitle']))
        for note in notes:
            elements.append(Paragraph(
                f'<b>{note.created_at.strftime("%d/%m/%Y %H:%M")}</b> — {note.content}',
                styles['InfoText']
            ))

    # ──────── FOOTER ────────
    elements.append(Spacer(1, 10 * mm))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.gray))
    elements.append(Paragraph(
        f'ThreatLens — Rapor tarihi: {datetime.now().strftime("%d/%m/%Y %H:%M")}',
        styles['SmallGray']
    ))

    doc.build(elements)
    buffer.seek(0)
    return buffer