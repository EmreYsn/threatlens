from django.urls import path
from . import views
from . import api_views

urlpatterns = [
    # Web sayfaları (mevcut olanlar)
    path('', views.index, name='index'),
    path('search/', views.search, name='search'),
    path('result/<uuid:ioc_id>/', views.result, name='result'),
    path('note/<uuid:ioc_id>/', views.add_note, name='add_note'),
    path('tag/<uuid:ioc_id>/<int:tag_id>/', views.toggle_tag, name='toggle_tag'),
    path('history/', views.history, name='history'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('export/<uuid:ioc_id>/pdf/', views.export_pdf, name='export_pdf'),
    path('bulk/', views.bulk_search, name='bulk_search'),
    path('compare/', views.compare, name='compare'),
    path('rescan/<uuid:ioc_id>/', views.rescan, name='rescan'),
    path('register/', views.register, name='register'),
    path('profile/', views.profile, name='profile'),

    # REST API
    path('api/', api_views.api_docs, name='api_docs'),
    path('api/search/', api_views.api_search, name='api_search'),
    path('api/ioc/<uuid:ioc_id>/', api_views.api_ioc_detail, name='api_ioc_detail'),
    path('api/history/', api_views.api_history, name='api_history'),
    path('api/stats/', api_views.api_stats, name='api_stats'),
    path('api/my-key/', api_views.api_my_key, name='api_my_key'),
    path('profile/api-key/', views.generate_api_key, name='generate_api_key'),
    path('docs/api/', views.api_docs_page, name='api_docs_page'),
    path('delete/<uuid:ioc_id>/', views.delete_ioc, name='delete_ioc'),
    path('export/csv/', views.export_csv, name='export_csv'),
]