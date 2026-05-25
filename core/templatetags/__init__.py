from django import template
from django.utils.timesince import timesince

register = template.Library()

@register.filter
def score_class(score):
    """Return CSS class based on threat score"""
    if score <= 30:
        return 'score-safe'
    elif score <= 60:
        return 'score-suspicious'
    return 'score-malicious'

@register.filter
def severity_display(severity):
    mapping = {
        'safe': 'Güvenli',
        'suspicious': 'Şüpheli',
        'malicious': 'Tehlikeli',
    }
    return mapping.get(severity, severity)
