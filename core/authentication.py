from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from .models import APIKey


class APIKeyAuthentication(BaseAuthentication):
    """X-API-Key header ile authentication"""

    def authenticate(self, request):
        api_key = request.META.get('HTTP_X_API_KEY')
        if not api_key:
            return None  # Diğer auth yöntemlerine geç

        try:
            key_obj = APIKey.objects.select_related('user').get(key=api_key, is_active=True)
        except APIKey.DoesNotExist:
            raise AuthenticationFailed('Geçersiz API key')

        if not key_obj.check_rate_limit():
            raise AuthenticationFailed('Günlük API limiti aşıldı (100 istek/gün)')

        return (key_obj.user, None)