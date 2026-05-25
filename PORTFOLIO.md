# ThreatLens — Portfolyo Özeti

## Proje Bilgileri
- **Proje Adı:** ThreatLens - Siber Tehdit İstihbaratı Platformu
- **Geliştirici:** Yasin Emre
- **Süre:** 4 Hafta (Mayıs 2026)
- **Teknolojiler:** Python, Django, Django REST Framework, JavaScript, Chart.js, Leaflet.js
- **GitHub:** https://github.com/EmreYsn/threatlens
- **Canlı Demo:** https://ysnemre.com/threatlens (opsiyonel)

---

## Problem
Siber güvenlik analistleri şüpheli IP, domain, URL, hash ve email adreslerini analiz ederken birden fazla OSINT platformunu tek tek kontrol etmek zorunda kalıyor. Bu süreç zaman alıcı ve hata yapma riski yüksek.

## Çözüm
ThreatLens, tek bir platformdan 6 farklı tehdit istihbaratı kaynağını otomatik sorgulayarak ağırlıklı tehdit skoru üreten bir web uygulamasıdır.

---

## Teknik Özellikler

### Backend
- Django 5.0 ile MVC mimarisi
- 6 harici API entegrasyonu (AbuseIPDB, VirusTotal, AlienVault OTX, Shodan, ipinfo.io, WHOIS)
- Ağırlıklı tehdit skoru algoritması (IOC tipine göre dinamik ağırlıklar)
- REST API + API Key authentication (Django REST Framework)
- Kullanıcı yönetimi (kayıt, giriş, profil)
- PDF rapor üretimi (ReportLab)
- CSV import/export

### Frontend
- Responsive tasarım (mobil uyumlu)
- Dark/Light tema desteği
- Chart.js ile interaktif grafikler (doughnut, line, stacked bar)
- Leaflet.js ile coğrafi haritalar
- Loading animasyonu ve toast bildirimler

### Veritabanı
- 5 model: IOC, Tag, Note, QueryLog, APIKey
- UUID primary key
- JSONField ile API yanıtlarını saklama
- Sorgu cache'leme (1 saat)

---

## Öğrenilen Beceriler
- Django web framework ile full-stack geliştirme
- RESTful API tasarımı ve implementasyonu
- Harici API entegrasyonu ve hata yönetimi
- OSINT metodolojisi ve tehdit istihbaratı
- Ağırlıklı skor algoritması tasarımı
- Responsive web tasarımı
- Git versiyon kontrolü
- Proje planlama ve zaman yönetimi (4 haftalık sprint)

---

## Sayılarla ThreatLens
- **6** OSINT kaynağı entegrasyonu
- **5** IOC tipi desteği (IP, Domain, URL, Hash, Email)
- **9** web sayfası + REST API
- **6** API endpoint
- **~3000** satır Python kodu
- **~1500** satır HTML/CSS/JS
- **4** hafta geliştirme süresi

---

## Ekran Görüntüleri

### Ana Sayfa
> Arama formu, istatistik kartları, entegre kaynaklar ve son sorgular

### Sonuç Sayfası
> Skor ring, bilgi kartları (6 kaynak), coğrafi harita, skor detayı

### Dashboard
> IOC tip dağılımı, severity dağılımı, 7/30 gün trend, dünya haritası

### Karşılaştırma
> İki IOC'yi yan yana skor ve detay karşılaştırması

### API Dokümantasyonu
> REST API endpoint'leri, authentication, örnek istekler

---

## Gelecek Planları
- Have I Been Pwned entegrasyonu (email veri ihlali kontrolü)
- Async API çağrıları (performans iyileştirme)
- Docker containerization
- PostgreSQL migration
- VPS deploy (ysnemre.com)