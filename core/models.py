import uuid
from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User


class Tag(models.Model):
    """IOC etiketleri: botnet, phishing, ransomware, APT, C2 vb."""
    name = models.CharField(max_length=50, unique=True)
    color = models.CharField(max_length=7, default='#6366f1')  # hex renk
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name


class IOC(models.Model):
    """Indicator of Compromise - Tehdit Göstergesi"""

    IOC_TYPES = [
        ('ip', 'IP Adresi'),
        ('domain', 'Domain'),
        ('url', 'URL'),
        ('hash', 'Dosya Hash'),
        ('email', 'Email'),
    ]

    SEVERITY_CHOICES = [
        ('safe', 'Güvenli'),
        ('suspicious', 'Şüpheli'),
        ('malicious', 'Tehlikeli'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    value = models.CharField(max_length=2048, db_index=True)  # IP, domain, URL, hash, email
    ioc_type = models.CharField(max_length=10, choices=IOC_TYPES, db_index=True)
    threat_score = models.IntegerField(default=0)  # 0-100
    severity = models.CharField(max_length=12, choices=SEVERITY_CHOICES, default='safe')
    tags = models.ManyToManyField(Tag, blank=True, related_name='iocs')

    # Coğrafi bilgi (IP için)
    country = models.CharField(max_length=100, blank=True, default='')
    country_code = models.CharField(max_length=5, blank=True, default='')
    city = models.CharField(max_length=100, blank=True, default='')
    latitude = models.FloatField(null=True, blank=True)
    longitude = models.FloatField(null=True, blank=True)
    isp = models.CharField(max_length=255, blank=True, default='')
    asn = models.CharField(max_length=50, blank=True, default='')

    # API sonuçları (JSON olarak sakla)
    abuseipdb_data = models.JSONField(default=dict, blank=True)
    virustotal_data = models.JSONField(default=dict, blank=True)
    alienvault_data = models.JSONField(default=dict, blank=True)
    shodan_data = models.JSONField(default=dict, blank=True)
    greynoise_data = models.JSONField(default=dict, blank=True)
    ipinfo_data = models.JSONField(default=dict, blank=True)
    urlhaus_data = models.JSONField(default=dict, blank=True)
    whois_data = models.JSONField(default=dict, blank=True, null=True)

    first_seen = models.DateTimeField(auto_now_add=True)
    last_queried = models.DateTimeField(auto_now=True)
    query_count = models.IntegerField(default=1)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='iocs')

    class Meta:
        ordering = ['-last_queried']
        verbose_name = 'IOC'
        verbose_name_plural = 'IOCs'
        indexes = [
            models.Index(fields=['ioc_type', 'threat_score']),
        ]

    def __str__(self):
        return f"[{self.get_ioc_type_display()}] {self.value} (Skor: {self.threat_score})"

    @property
    def severity_color(self):
        if self.threat_score <= 30:
            return '#22c55e'  # yeşil
        elif self.threat_score <= 60:
            return '#eab308'  # sarı
        return '#ef4444'  # kırmızı

    def update_severity(self):
        if self.threat_score <= 30:
            self.severity = 'safe'
        elif self.threat_score <= 60:
            self.severity = 'suspicious'
        else:
            self.severity = 'malicious'


class Note(models.Model):
    """IOC için kullanıcı notları"""
    ioc = models.ForeignKey(IOC, on_delete=models.CASCADE, related_name='notes')
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Not: {self.content[:50]}..."


class QueryLog(models.Model):
    """Sorgu geçmişi"""
    ioc = models.ForeignKey(IOC, on_delete=models.CASCADE, related_name='query_logs')
    queried_at = models.DateTimeField(auto_now_add=True)
    sources_queried = models.JSONField(default=list)  # ['abuseipdb', 'virustotal', ...]
    response_time_ms = models.IntegerField(default=0)  # toplam yanıt süresi

    class Meta:
        ordering = ['-queried_at']

    def __str__(self):
        return f"{self.ioc.value} - {self.queried_at.strftime('%d/%m/%Y %H:%M')}"

import secrets


class APIKey(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='api_key')
    key = models.CharField(max_length=64, unique=True, default=secrets.token_hex)
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    requests_today = models.IntegerField(default=0)
    last_request_date = models.DateField(null=True, blank=True)

    class Meta:
        verbose_name = 'API Key'
        verbose_name_plural = 'API Keys'

    def __str__(self):
        return f'{self.user.username} - {self.key[:8]}...'

    def check_rate_limit(self, daily_limit=100):
        """Günlük rate limit kontrolü"""
        from django.utils import timezone
        today = timezone.now().date()
        if self.last_request_date != today:
            self.requests_today = 0
            self.last_request_date = today
        if self.requests_today >= daily_limit:
            return False
        self.requests_today += 1
        self.save(update_fields=['requests_today', 'last_request_date'])
        return True