from django import template

register = template.Library()

@register.filter
def score_class(value):
    """Skora göre CSS class döndür"""
    try:
        value = int(value)
    except (ValueError, TypeError):
        return ''
    if value <= 30:
        return 'score-safe'
    elif value <= 60:
        return 'score-suspicious'
    else:
        return 'score-critical'

@register.filter
def score_color(value):
    """Skora göre renk döndür"""
    try:
        value = int(value)
    except (ValueError, TypeError):
        return '#a0aec0'
    if value <= 30:
        return '#00b894'
    elif value <= 60:
        return '#fdcb6e'
    else:
        return '#e74c3c'

@register.filter
def severity_display(value):
    """Severity Türkçe karşılığı"""
    displays = {
        'safe': '🟢 Güvenli',
        'suspicious': '🟡 Şüpheli',
        'malicious': '🔴 Tehlikeli',
    }
    return displays.get(value, value)

@register.filter
def percentage_of(value, max_val):
    """Score ring SVG için dashoffset hesapla"""
    try:
        value = int(value)
        max_val = int(max_val)
    except (ValueError, TypeError):
        return 339.292
    if max_val == 0:
        return 339.292
    ratio = value / max_val
    return 339.292 * (1 - ratio)
