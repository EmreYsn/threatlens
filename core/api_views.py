import time
from django.db.models import Count
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response

from .models import IOC, QueryLog, Tag, APIKey
from .serializers import (
    IOCListSerializer, IOCDetailSerializer,
    QueryLogSerializer, StatsSerializer
)
from .services.ioc_utils import detect_ioc_type, validate_ioc
from .services.scoring import calculate_threat_score, get_severity
from .services.abuseipdb import check_ip as abuseipdb_check
from .services.virustotal import (
    check_ip as vt_check_ip, check_domain as vt_check_domain,
    check_url as vt_check_url, check_hash as vt_check_hash
)
from .services.ipinfo import check_ip as ipinfo_check
from .services.alienvault import (
    check_ip as otx_check_ip, check_domain as otx_check_domain,
    check_hash as otx_check_hash
)
from .services.shodan_service import check_ip as shodan_check
from .services.whois_service import check_domain as whois_check


@api_view(['GET'])
@permission_classes([AllowAny])
def api_docs(request):
    """API dokümantasyonu"""
    docs = {
        'name': 'ThreatLens API',
        'version': '1.0',
        'description': 'Siber Tehdit İstihbaratı REST API',
        'authentication': 'Header: X-API-Key: <your-api-key>',
        'rate_limit': '100 istek/gün',
        'endpoints': {
            'GET /api/': 'Bu dokümantasyon',
            'GET /api/search/?q=<ioc>': 'IOC sorgula (IP, domain, URL, hash, email)',
            'GET /api/ioc/<uuid>/': 'IOC detay bilgileri',
            'GET /api/history/': 'Sorgu geçmişi',
            'GET /api/stats/': 'Genel istatistikler',
            'GET /api/my-key/': 'API key bilgileri',
        },
        'examples': {
            'search': '/api/search/?q=8.8.8.8',
            'detail': '/api/ioc/<uuid>/',
            'history': '/api/history/?page=1',
        }
    }
    return Response(docs)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def api_search(request):
    """IOC sorgulama endpoint'i"""
    query = request.GET.get('q', '').strip()
    if not query:
        return Response(
            {'error': 'q parametresi gerekli. Örnek: /api/search/?q=8.8.8.8'},
            status=status.HTTP_400_BAD_REQUEST
        )

    # IOC tipini algıla
    ioc_type = detect_ioc_type(query)
    if not ioc_type:
        return Response(
            {'error': f'"{query}" tanınamadı. Geçerli: IP, domain, URL, hash, email'},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Doğrula
    is_valid, error_msg = validate_ioc(query, ioc_type)
    if not is_valid:
        return Response({'error': error_msg}, status=status.HTTP_400_BAD_REQUEST)

    # DB'de ara veya oluştur
    ioc, created = IOC.objects.get_or_create(
        value=query,
        ioc_type=ioc_type,
        defaults={'user': request.user}
    )

    if not created:
        ioc.query_count += 1

    # API sorguları
    start_time = time.time()
    api_results = {}
    sources_queried = []

    if ioc_type == 'ip':
        result = abuseipdb_check(query)
        api_results['abuseipdb'] = result
        sources_queried.append('abuseipdb')
        if result.get('success'):
            data = result['data']
            ioc.abuseipdb_data = data
            ioc.country_code = data.get('country_code', '')
            ioc.country = data.get('country_name', '')
            ioc.isp = data.get('isp', '')

        result = vt_check_ip(query)
        api_results['virustotal'] = result
        sources_queried.append('virustotal')
        if result.get('success'):
            ioc.virustotal_data = result['data']

        result = otx_check_ip(query)
        api_results['alienvault'] = result
        sources_queried.append('alienvault')
        if result.get('success'):
            ioc.alienvault_data = result['data']

        result = shodan_check(query)
        api_results['shodan'] = result
        sources_queried.append('shodan')
        if result.get('success'):
            ioc.shodan_data = result['data']

        result = ipinfo_check(query)
        api_results['ipinfo'] = result
        sources_queried.append('ipinfo')
        if result.get('success'):
            ioc.ipinfo_data = result['data']

    elif ioc_type == 'domain':
        result = vt_check_domain(query)
        api_results['virustotal'] = result
        sources_queried.append('virustotal')
        if result.get('success'):
            ioc.virustotal_data = result['data']

        result = otx_check_domain(query)
        api_results['alienvault'] = result
        sources_queried.append('alienvault')
        if result.get('success'):
            ioc.alienvault_data = result['data']

        result = whois_check(query)
        api_results['whois'] = result
        sources_queried.append('whois')
        if result.get('success'):
            ioc.whois_data = result['data']

    elif ioc_type == 'url':
        result = vt_check_url(query)
        api_results['virustotal'] = result
        sources_queried.append('virustotal')
        if result.get('success'):
            ioc.virustotal_data = result['data']

    elif ioc_type == 'hash':
        result = vt_check_hash(query)
        api_results['virustotal'] = result
        sources_queried.append('virustotal')
        if result.get('success'):
            ioc.virustotal_data = result['data']

        result = otx_check_hash(query)
        api_results['alienvault'] = result
        sources_queried.append('alienvault')
        if result.get('success'):
            ioc.alienvault_data = result['data']

    # Skor hesapla
    score, breakdown = calculate_threat_score(ioc_type, api_results)
    ioc.threat_score = score
    ioc.severity = get_severity(score)
    ioc.save()

    elapsed_ms = int((time.time() - start_time) * 1000)
    QueryLog.objects.create(
        ioc=ioc,
        sources_queried=sources_queried,
        response_time_ms=elapsed_ms,
    )

    serializer = IOCDetailSerializer(ioc)
    return Response({
        'success': True,
        'response_time_ms': elapsed_ms,
        'sources': sources_queried,
        'data': serializer.data,
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def api_ioc_detail(request, ioc_id):
    """IOC detay endpoint'i"""
    try:
        ioc = IOC.objects.get(id=ioc_id)
    except IOC.DoesNotExist:
        return Response({'error': 'IOC bulunamadı'}, status=status.HTTP_404_NOT_FOUND)

    serializer = IOCDetailSerializer(ioc)
    return Response({'success': True, 'data': serializer.data})


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def api_history(request):
    """Sorgu geçmişi endpoint'i"""
    logs = QueryLog.objects.select_related('ioc').order_by('-queried_at')

    # Filtreler
    ioc_type = request.GET.get('type')
    if ioc_type:
        logs = logs.filter(ioc__ioc_type=ioc_type)

    serializer = QueryLogSerializer(logs[:50], many=True)
    return Response({'success': True, 'count': len(serializer.data), 'data': serializer.data})


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def api_stats(request):
    """İstatistik endpoint'i"""
    total_iocs = IOC.objects.count()
    total_queries = QueryLog.objects.count()

    stats = {
        'total_iocs': total_iocs,
        'total_queries': total_queries,
        'malicious_count': IOC.objects.filter(severity='malicious').count(),
        'suspicious_count': IOC.objects.filter(severity='suspicious').count(),
        'safe_count': IOC.objects.filter(severity='safe').count(),
        'type_distribution': {
            item['ioc_type']: item['count']
            for item in IOC.objects.values('ioc_type').annotate(count=Count('id'))
        },
    }

    recent = QueryLog.objects.select_related('ioc').order_by('-queried_at')[:10]
    stats['recent_queries'] = QueryLogSerializer(recent, many=True).data

    return Response({'success': True, 'data': stats})


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def api_my_key(request):
    """Kullanıcının API key bilgileri"""
    try:
        key = APIKey.objects.get(user=request.user)
        return Response({
            'success': True,
            'data': {
                'key': key.key,
                'is_active': key.is_active,
                'requests_today': key.requests_today,
                'daily_limit': 100,
                'created_at': key.created_at,
            }
        })
    except APIKey.DoesNotExist:
        # Otomatik oluştur
        key = APIKey.objects.create(user=request.user)
        return Response({
            'success': True,
            'data': {
                'key': key.key,
                'is_active': key.is_active,
                'requests_today': 0,
                'daily_limit': 100,
                'created_at': key.created_at,
            }
        })