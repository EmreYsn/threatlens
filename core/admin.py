from django.contrib import admin
from django.utils.html import format_html
from .models import Tag, IOC, Note, QueryLog, APIKey


admin.site.site_header = 'ThreatLens Yönetim Paneli'
admin.site.site_title = 'ThreatLens Admin'
admin.site.index_title = 'Yönetim'


@admin.register(Tag)
class TagAdmin(admin.ModelAdmin):
    list_display = ['name', 'colored_badge', 'ioc_count']
    search_fields = ['name']

    def colored_badge(self, obj):
        return format_html(
            '<span style="background:{};color:white;padding:2px 8px;border-radius:4px;">{}</span>',
            obj.color, obj.name
        )
    colored_badge.short_description = 'Etiket'

    def ioc_count(self, obj):
        return obj.ioc_set.count()
    ioc_count.short_description = 'IOC Sayısı'


@admin.register(IOC)
class IOCAdmin(admin.ModelAdmin):
    list_display = ['value', 'ioc_type', 'score_badge', 'severity_badge', 'country_code', 'user', 'query_count', 'last_queried']
    list_filter = ['ioc_type', 'severity', 'country_code']
    search_fields = ['value', 'isp', 'country']
    readonly_fields = [
        'id', 'first_seen', 'last_queried',
        'abuseipdb_data', 'virustotal_data', 'ipinfo_data',
        'alienvault_data', 'shodan_data', 'whois_data',
    ]
    list_per_page = 25
    ordering = ['-last_queried']

    def score_badge(self, obj):
        if obj.threat_score <= 30:
            color = '#00b894'
        elif obj.threat_score <= 60:
            color = '#fdcb6e'
        else:
            color = '#e74c3c'
        return format_html(
            '<span style="color:{};font-weight:bold;">{}/100</span>',
            color, obj.threat_score
        )
    score_badge.short_description = 'Skor'
    score_badge.admin_order_field = 'threat_score'

    def severity_badge(self, obj):
        colors = {'safe': '#00b894', 'suspicious': '#fdcb6e', 'malicious': '#e74c3c'}
        labels = {'safe': 'Güvenli', 'suspicious': 'Şüpheli', 'malicious': 'Tehlikeli'}
        color = colors.get(obj.severity, '#999')
        label = labels.get(obj.severity, obj.severity)
        return format_html(
            '<span style="background:{};color:white;padding:2px 8px;border-radius:4px;font-size:11px;">{}</span>',
            color, label
        )
    severity_badge.short_description = 'Seviye'
    severity_badge.admin_order_field = 'severity'


@admin.register(Note)
class NoteAdmin(admin.ModelAdmin):
    list_display = ['ioc', 'short_content', 'created_at']
    list_filter = ['created_at']
    search_fields = ['content', 'ioc__value']

    def short_content(self, obj):
        return obj.content[:80] + '...' if len(obj.content) > 80 else obj.content
    short_content.short_description = 'İçerik'


@admin.register(QueryLog)
class QueryLogAdmin(admin.ModelAdmin):
    list_display = ['ioc', 'sources_display', 'response_time_ms', 'queried_at']
    list_filter = ['queried_at']
    search_fields = ['ioc__value']
    list_per_page = 30
    ordering = ['-queried_at']

    def sources_display(self, obj):
        if not obj.sources_queried:
            return '-'
        return ', '.join(obj.sources_queried)
    sources_display.short_description = 'Kaynaklar'


@admin.register(APIKey)
class APIKeyAdmin(admin.ModelAdmin):
    list_display = ['user', 'short_key', 'is_active', 'requests_today', 'created_at']
    list_filter = ['is_active']
    search_fields = ['user__username']

    def short_key(self, obj):
        return f'{obj.key[:12]}...'
    short_key.short_description = 'API Key'