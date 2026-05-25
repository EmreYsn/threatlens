from rest_framework import serializers
from .models import IOC, Note, QueryLog, Tag


class TagSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tag
        fields = ['id', 'name', 'color']


class NoteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Note
        fields = ['id', 'content', 'created_at']


class IOCListSerializer(serializers.ModelSerializer):
    """IOC listesi için kısa serializer"""
    ioc_type_display = serializers.CharField(source='get_ioc_type_display', read_only=True)
    severity_display = serializers.SerializerMethodField()
    tags = TagSerializer(many=True, read_only=True)

    class Meta:
        model = IOC
        fields = [
            'id', 'value', 'ioc_type', 'ioc_type_display',
            'threat_score', 'severity', 'severity_display',
            'country', 'country_code',
            'query_count', 'first_seen', 'last_queried',
            'tags',
        ]

    def get_severity_display(self, obj):
        labels = {'safe': 'Güvenli', 'suspicious': 'Şüpheli', 'malicious': 'Tehlikeli'}
        return labels.get(obj.severity, obj.severity)


class IOCDetailSerializer(serializers.ModelSerializer):
    """IOC detay için tam serializer"""
    ioc_type_display = serializers.CharField(source='get_ioc_type_display', read_only=True)
    severity_display = serializers.SerializerMethodField()
    tags = TagSerializer(many=True, read_only=True)
    notes = NoteSerializer(many=True, read_only=True)
    score_breakdown = serializers.SerializerMethodField()

    class Meta:
        model = IOC
        fields = [
            'id', 'value', 'ioc_type', 'ioc_type_display',
            'threat_score', 'severity', 'severity_display',
            'country', 'country_code', 'isp', 'asn',
            'query_count', 'first_seen', 'last_queried',
            'tags', 'notes',
            'abuseipdb_data', 'virustotal_data', 'ipinfo_data',
            'alienvault_data', 'shodan_data', 'whois_data',
            'score_breakdown',
        ]

    def get_severity_display(self, obj):
        labels = {'safe': 'Güvenli', 'suspicious': 'Şüpheli', 'malicious': 'Tehlikeli'}
        return labels.get(obj.severity, obj.severity)

    def get_score_breakdown(self, obj):
        from .services.scoring import calculate_threat_score
        api_results = {}
        if obj.abuseipdb_data:
            api_results['abuseipdb'] = {'success': True, 'data': obj.abuseipdb_data}
        if obj.virustotal_data:
            api_results['virustotal'] = {'success': True, 'data': obj.virustotal_data}
        if obj.ipinfo_data:
            api_results['ipinfo'] = {'success': True, 'data': obj.ipinfo_data}
        if obj.alienvault_data:
            api_results['alienvault'] = {'success': True, 'data': obj.alienvault_data}
        if obj.shodan_data:
            api_results['shodan'] = {'success': True, 'data': obj.shodan_data}
        if obj.whois_data:
            api_results['whois'] = {'success': True, 'data': obj.whois_data}

        _, breakdown = calculate_threat_score(obj.ioc_type, api_results)
        return breakdown


class QueryLogSerializer(serializers.ModelSerializer):
    ioc_value = serializers.CharField(source='ioc.value', read_only=True)
    ioc_type = serializers.CharField(source='ioc.ioc_type', read_only=True)
    threat_score = serializers.IntegerField(source='ioc.threat_score', read_only=True)

    class Meta:
        model = QueryLog
        fields = [
            'id', 'ioc_value', 'ioc_type', 'threat_score',
            'sources_queried', 'response_time_ms', 'queried_at',
        ]


class StatsSerializer(serializers.Serializer):
    total_iocs = serializers.IntegerField()
    total_queries = serializers.IntegerField()
    malicious_count = serializers.IntegerField()
    suspicious_count = serializers.IntegerField()
    safe_count = serializers.IntegerField()
    type_distribution = serializers.DictField()
    recent_queries = QueryLogSerializer(many=True)