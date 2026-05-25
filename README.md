# 🔍 ThreatLens — Siber Tehdit İstihbaratı Platformu

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)
![Django](https://img.shields.io/badge/Django-5.0+-green?logo=django&logoColor=white)
![DRF](https://img.shields.io/badge/DRF-3.15+-red?logo=django&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow)

**IP, Domain, URL, Hash ve Email için çoklu kaynak tehdit istihbaratı analizi**

[Demo](#demo) · [Kurulum](#kurulum) · [API](#rest-api) · [Özellikler](#özellikler) · [Ekran Görüntüleri](#ekran-görüntüleri)

</div>

---

## 📋 Proje Hakkında

ThreatLens, siber güvenlik analistleri için geliştirilmiş bir **OSINT (Açık Kaynak İstihbarat)** platformudur. Girilen IOC (Indicator of Compromise) değerlerini 6 farklı tehdit istihbaratı kaynağından sorgulayarak **0-100 arası ağırlıklı tehdit skoru** üretir.

### Neden ThreatLens?

- **Çoklu Kaynak Doğrulaması:** Tek kaynağa güvenmek yerine 6 farklı kaynaktan veri toplayarak false positive oranını minimize eder
- **Ağırlıklı Skor Algoritması:** Her kaynak IOC tipine göre farklı ağırlıkta değerlendirilir
- **Tek Platform:** IP, domain, URL, hash ve email analizini tek yerden yapın
- **REST API:** Programatik erişim ile otomasyon ve entegrasyon desteği

---

## ✨ Özellikler

### Tehdit Analizi
- 🔎 5 IOC tipi: IP Adresi, Domain, URL, Hash (MD5/SHA1/SHA256), Email
- 📊 6 OSINT kaynağı entegrasyonu
- ⚖️ Ağırlıklı tehdit skoru algoritması (0-100)
- 🏷️ Etiketleme sistemi (Botnet, Phishing, Ransomware, APT, C2...)
- 📝 IOC bazlı not ekleme

### Entegre Kaynaklar
| Kaynak | Veri Tipi | IOC Desteği |
|--------|-----------|-------------|
| AbuseIPDB | Abuse raporları, güven skoru | IP |
| VirusTotal | 90+ AV motoru analizi | IP, Domain, URL, Hash |
| AlienVault OTX | Tehdit pulse'ları | IP, Domain, Hash |
| Shodan | Açık portlar, servisler, CVE | IP |
| ipinfo.io | Geolocation, ASN, hostname | IP |
| WHOIS | Domain kayıt bilgileri, yaş | Domain, URL |

### Dashboard & Raporlama
- 📈 Chart.js ile interaktif grafikler (tip dağılımı, severity, 30 gün trend)
- 🗺️ Leaflet.js ile coğrafi harita (IOC lokasyonları)
- 📄 PDF rapor çıktısı (ReportLab)
- 📋 CSV toplu sorgulama (50 IOC/dosya)
- 🔄 IOC karşılaştırma (yan yana analiz)

### Teknik
- 👤 Kullanıcı authentication (kayıt, giriş, profil)
- 🔑 REST API + API Key authentication
- 💾 Sorgu cache'leme (1 saat)
- 🌙 Dark/Light tema
- 📱 Responsive tasarım
- ⏳ Loading animasyonu

---

## 🛠️ Teknolojiler

**Backend:** Python 3.10+, Django 5.0, Django REST Framework

**Frontend:** HTML5, CSS3, JavaScript, Chart.js, Leaflet.js

**Veritabanı:** SQLite (geliştirme), PostgreSQL (production)

**API'ler:** AbuseIPDB, VirusTotal, AlienVault OTX, Shodan, ipinfo.io, WHOIS

---

## 🚀 Kurulum

### Gereksinimler
- Python 3.10+
- pip

### Adımlar

```bash
# 1. Projeyi klonla
git clone https://github.com/EmreYsn/threatlens.git
cd threatlens

# 2. Virtual environment oluştur
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# 3. Bağımlılıkları kur
pip install -r requirements.txt

# 4. Environment değişkenlerini ayarla
cp .env.example .env
# .env dosyasını düzenleyip API key'leri ekleyin

# 5. Veritabanını oluştur
python manage.py migrate

# 6. Superuser oluştur
python manage.py createsuperuser

# 7. Sunucuyu başlat
python manage.py runserver
```

Tarayıcıda `http://127.0.0.1:8000` adresine gidin.

### API Key'leri Alma (Ücretsiz)

| Kaynak | URL | Ücretsiz Limit |
|--------|-----|----------------|
| AbuseIPDB | [abuseipdb.com](https://abuseipdb.com) | 1.000 sorgu/gün |
| VirusTotal | [virustotal.com](https://virustotal.com) | 4 istek/dk, 500/gün |
| AlienVault OTX | [otx.alienvault.com](https://otx.alienvault.com) | Limitsiz |
| Shodan | [shodan.io](https://shodan.io) | 100 sorgu/ay |
| ipinfo.io | [ipinfo.io](https://ipinfo.io) | 50.000/ay |

---

## 🔌 REST API

ThreatLens, programatik erişim için REST API sunar.

### Authentication
```bash
curl -H "X-API-Key: YOUR_KEY" http://localhost:8000/api/search/?q=8.8.8.8
```

### Endpoints

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| GET | `/api/` | API dokümantasyonu |
| GET | `/api/search/?q={ioc}` | IOC sorgula |
| GET | `/api/ioc/{uuid}/` | IOC detay |
| GET | `/api/history/` | Sorgu geçmişi |
| GET | `/api/stats/` | İstatistikler |
| GET | `/api/my-key/` | API key bilgileri |

### Örnek Yanıt
```json
{
  "success": true,
  "response_time_ms": 3470,
  "sources": ["abuseipdb", "virustotal", "alienvault", "shodan", "ipinfo"],
  "data": {
    "value": "8.8.8.8",
    "threat_score": 0,
    "severity": "safe",
    "score_breakdown": [
      {"source": "AbuseIPDB", "score": 0, "weight": 35},
      {"source": "VirusTotal", "score": 0, "weight": 40}
    ]
  }
}
```

---

## 📁 Proje Yapısı

threatlens_project/
├── manage.py
├── requirements.txt
├── .env.example
├── .gitignore
├── README.md
├── threatlens/              # Django proje ayarları
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
├── core/                    # Ana uygulama
│   ├── models.py            # IOC, Tag, Note, QueryLog, APIKey
│   ├── views.py             # Web view'ları
│   ├── api_views.py         # REST API endpoint'leri
│   ├── serializers.py       # DRF serializer'lar
│   ├── authentication.py    # API Key auth
│   ├── forms.py             # Form tanımları
│   ├── admin.py             # Admin panel
│   ├── urls.py              # URL routing
│   ├── services/            # API servisleri
│   │   ├── abuseipdb.py
│   │   ├── virustotal.py
│   │   ├── alienvault.py
│   │   ├── shodan_service.py
│   │   ├── ipinfo.py
│   │   ├── whois_service.py
│   │   ├── scoring.py       # Tehdit skoru algoritması
│   │   ├── ioc_utils.py     # IOC algılama/doğrulama
│   │   ├── base.py          # Ortak API yardımcıları
│   │   └── pdf_report.py    # PDF rapor üretimi
│   ├── templates/core/      # Sayfa template'leri
│   │   ├── index.html
│   │   ├── result.html
│   │   ├── history.html
│   │   ├── dashboard.html
│   │   ├── compare.html
│   │   ├── bulk_search.html
│   │   ├── profile.html
│   │   └── api_docs.html
│   └── templatetags/
│       └── threat_tags.py   # Custom template filter'lar
├── templates/               # Global template'ler
│   ├── base.html
│   └── auth/
│       ├── login.html
│       └── register.html
└── static/
├── css/style.css
└── js/main.js

---

## 🧮 Skor Algoritması

ThreatLens, her IOC tipine göre farklı ağırlıklarla çoklu kaynak tehdit skoru hesaplar:

### IP Adresi
| Kaynak | Ağırlık | Değerlendirme Kriterleri |
|--------|---------|------------------------|
| AbuseIPDB | %35 | Abuse skoru, rapor sayısı, Tor node |
| VirusTotal | %40 | Detection ratio, reputation |
| AlienVault OTX | %15 | Pulse sayısı, aktiviteler |
| Shodan | %15 | Açık port sayısı, tehlikeli portlar, CVE |
| ipinfo.io | %10 | Bogon, VPN/proxy/Tor tespiti |

### Domain
| Kaynak | Ağırlık |
|--------|---------|
| VirusTotal | %50 |
| AlienVault OTX | %20 |
| WHOIS | %15 |

### Skor Aralıkları
- 🟢 **0-30:** Güvenli
- 🟡 **31-60:** Şüpheli
- 🔴 **61-100:** Tehlikeli

---

## 👨‍💻 Geliştirici

**Yasin Emre**
- Web: [ysnemre.com](https://ysnemre.com)
- GitHub: [github.com/EmreYsn](https://github.com/EmreYsn)

---

## 📄 Lisans

Bu proje MIT lisansı ile lisanslanmıştır.