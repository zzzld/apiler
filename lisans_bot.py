import os
import json
import requests
import time
import hashlib
import datetime
import threading
import re
import random
import sys
import subprocess
import uuid
from dotenv import load_dotenv

# Telegram Bot Token
load_dotenv()
TOKEN = os.getenv('TELEGRAM_TOKEN')
if not TOKEN:
    print("TELEGRAM_TOKEN bulunamadı! .env dosyasını kontrol edin!")
    exit(1)

# Admin kullanıcı ID'leri (bunları kendi Telegram ID'nizi ekleyin)
ADMIN_IDS = [2111619152]  # Bu ID'yi kendi Telegram ID'nizle değiştirin

# API URLs
BASE_URL = f"https://api.telegram.org/bot{TOKEN}"
API_URL = "https://api-y5s2.onrender.com"  # Önceki URL: https://ashlynn-api.onrender.com

# Alternatif API URL'ler (eğer birincisi çalışmazsa)
ALTERNATE_API_URLS = [
    "https://ashlynn-api.onrender.com",
    "https://api-y5s2.onrender.com",
    "https://chatapi-y5s2.onrender.com"
]

# Veritabanı dosya adı
LICENSE_DB_FILE = "licenses.json"

# API isteği için yeniden deneme ve backoff parametreleri
API_MAX_RETRIES = 5
API_INITIAL_BACKOFF = 1  # saniye
API_BACKOFF_FACTOR = 2
API_TIMEOUT_SHORT = 15  # saniye
API_TIMEOUT_MEDIUM = 30  # saniye 
API_TIMEOUT_LONG = 90  # saniye

# Global değişkenler
user_states = {}
offset = 0
processed_message_ids = set()
processed_callback_ids = set()
MAX_RETRIES = 5
BOT_INITIALIZED = False  # Bot başlatma durumu

# Kullanıcı durumları
user_states = {}
offset = 0

# Ödeme durumu için global değişken
payment_requests = {}

# Son görsel oluşturma zamanını takip etmek için global değişken
user_image_cooldowns = {}

# Desteklenen modeller
SUPPORTED_MODELS = {
    "gpt4": "GPT-4",
    "gemini": "Gemini Flash",
    "qwen-2.5-coder-32b": "Qwen Coder",
    "deepseek-r1": "Deepseek AI"
    # Mistral AI kaldırıldı çünkü düzgün çalışmıyor
}

# Görsel modelleri
IMAGE_MODELS = {
    "flux": "FLUX V3",
    "turbo": "Turbo (Özel Boyut)"
}

# Akıllı API istek fonksiyonu - Üstel geri çekilme (Exponential Backoff) ile
def api_request_with_backoff(url, method="get", params=None, json_data=None, timeout=API_TIMEOUT_MEDIUM, max_retries=API_MAX_RETRIES):
    """
    Üstel geri çekilme ve akıllı yeniden deneme sistemi ile API istekleri yapar
    
    Args:
        url: İstek yapılacak URL
        method: HTTP metodu ('get' veya 'post')
        params: URL parametreleri (get istekleri için)
        json_data: JSON gövdesi (post istekleri için)
        timeout: İstek zaman aşımı
        max_retries: Maksimum yeniden deneme sayısı
        
    Returns:
        API yanıtı (başarılı) veya None (başarısız)
    """
    request_func = requests.get if method.lower() == "get" else requests.post
    current_backoff = API_INITIAL_BACKOFF
    
    for attempt in range(max_retries):
        try:
            # İstek yap
            if method.lower() == "get":
                response = request_func(url, params=params, timeout=timeout)
            else:
                response = request_func(url, json=json_data, timeout=timeout)
            
            # Başarılı yanıt
            if response.status_code == 200:
                return response
                
            # Rate limit veya geçici sunucu hatası - yeniden dene
            elif response.status_code in [429, 500, 502, 503, 504]:
                print(f"⚠️ API geçici hatası: {url} - Status {response.status_code} (Deneme {attempt+1}/{max_retries})")
                
                # Sunucu Retry-After header gönderiyorsa kullan, yoksa üstel geri çekilme uygula
                retry_after = response.headers.get('Retry-After')
                wait_time = int(retry_after) if retry_after and retry_after.isdigit() else current_backoff
                
                print(f"⏱️ {wait_time} saniye bekleniyor...")
                time.sleep(wait_time)
                current_backoff = min(current_backoff * API_BACKOFF_FACTOR, 60)  # Maksimum 60 saniye bekle
                continue
                
            # Kalıcı hata - yeniden deneme yapma
            else:
                print(f"❌ API kalıcı hatası: {url} - Status {response.status_code}")
                return response
                
        except requests.exceptions.Timeout:
            print(f"⏱️ API timeout hatası: {url} (Deneme {attempt+1}/{max_retries})")
            
        except requests.exceptions.ConnectionError:
            print(f"🔌 API bağlantı hatası: {url} (Deneme {attempt+1}/{max_retries})")
            
        except Exception as e:
            print(f"⚠️ API istek hatası: {url} - {str(e)} (Deneme {attempt+1}/{max_retries})")
        
        # Hata durumunda üstel geri çekilme uygula
        print(f"⏱️ {current_backoff} saniye bekleniyor...")
        time.sleep(current_backoff)
        current_backoff = min(current_backoff * API_BACKOFF_FACTOR, 60)  # Maksimum 60 saniye bekle
    
    # Tüm denemeler başarısız
    print(f"❌ API isteği başarısız oldu (max deneme sayısına ulaşıldı): {url}")
    return None

# Lisans veritabanını yükle
def load_license_db():
    """Lisans veritabanını yükle"""
    if os.path.exists(LICENSE_DB_FILE):
        try:
            with open(LICENSE_DB_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Lisans veritabanı yüklenirken hata: {e}")
            return {"users": {}, "api_keys": {}}
    else:
        # Yeni veritabanı oluştur
        return {"users": {}, "api_keys": {}}

# Lisans veritabanını kaydet
def save_license_db(db):
    """Lisans veritabanını kaydet"""
    try:
        with open(LICENSE_DB_FILE, 'w', encoding='utf-8') as f:
            json.dump(db, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        print(f"Lisans veritabanı kaydedilirken hata: {e}")
        return False

# API Key oluştur
def generate_api_key(user_id, name, expiry_days=30):
    """Yeni API key oluştur"""
    db = load_license_db()
    user_id_str = str(user_id)
    
    # Daha profesyonel ve benzersiz API key oluştur
    # UUID4 + zaman damgası + kullanıcı ID kullanarak benzersizliği garanti et
    current_time = int(time.time())
    random_part = ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=8))
    random_hash = hashlib.sha256(f"{uuid.uuid4()}{current_time}{user_id}{random_part}".encode()).hexdigest()[:8].upper()
    prefix = "ABX"  # Prefix'i değiştirebilirsiniz
    
    # Formatlı API key oluştur: PREFIX-RANDOM-TIME-ID
    api_key = f"{prefix}-{random_hash}-{current_time % 1000000:06d}-{user_id % 10000}"
    
    print(f"🔑 Yeni API Key oluşturuldu: {api_key} (kullanıcı: {user_id})")
    
    # Son kullanma tarihi
    expiry_date = (datetime.datetime.now() + datetime.timedelta(days=expiry_days)).strftime("%Y-%m-%d")
    
    # Kullanıcı yoksa ekle
    if user_id_str not in db.get("users", {}):
        db["users"][user_id_str] = {
            "name": name,
            "created_at": datetime.datetime.now().strftime("%Y-%m-%d"),
            "api_keys": [api_key],
            "last_active": "-",
            "usage": {
                "total_requests": 0,
                "images": 0,
                "chats": 0
            }
        }
    else:
        # Kullanıcı varsa, API key listesine ekle
        if api_key not in db["users"][user_id_str].get("api_keys", []):
            if "api_keys" not in db["users"][user_id_str]:
                db["users"][user_id_str]["api_keys"] = []
            db["users"][user_id_str]["api_keys"].append(api_key)
    
    # API key'i kaydet
    if "api_keys" not in db:
        db["api_keys"] = {}
    
    db["api_keys"][api_key] = {
        "user_id": user_id,
        "expiry_date": expiry_date,
        "active": True,
        "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    # Veritabanını güncelle
    save_license_db(db)
    
    return api_key, expiry_date

# API Key doğrula
def verify_api_key(api_key):
    """API key'i doğrula"""
    if not api_key:
        print("❌ API Key boş!")
        return False, None
    
    # API key'i temizle
    api_key = api_key.strip()
    
    # API key format kontrolü
    if not re.match(r'^ABX-[A-Z0-9]{8}-\d{6}-\d{4}$', api_key):
        print("❌ API Key format hatası!")
        return False, None
    
    # Debug log
    print(f"API Key doğrulama başladı: {api_key}")
    
    db = load_license_db()
    
    # API Keys koleksiyonunu kontrol et 
    if not db.get("api_keys"):
        print("❌ API Keys koleksiyonu bulunamadı!")
        db["api_keys"] = {}
        save_license_db(db)
    
    # Veritabanındaki tüm keyleri yazdır (debug için)
    print(f"Mevcut API keyler: {list(db.get('api_keys', {}).keys())}")
    
    if api_key in db.get("api_keys", {}):
        key_data = db["api_keys"][api_key]
        print(f"✅ API Key bulundu, data: {key_data}")
        
        # Son kullanma tarihini kontrol et
        if key_data.get("active", False):
            try:
                expiry_date = datetime.datetime.strptime(key_data["expiry_date"], '%Y-%m-%d')
                if expiry_date > datetime.datetime.now():
                    print(f"✅ API Key aktif ve geçerli, user_id: {key_data.get('user_id')}")
                    return True, key_data.get("user_id")
                else:
                    print(f"❌ API Key süresi dolmuş: {key_data['expiry_date']}")
            except Exception as e:
                print(f"❌ Tarih ayrıştırma hatası: {e}")
                return False, None
        else:
            print("❌ API Key aktif değil")
    else:
        print("❌ API Key veritabanında bulunamadı")
        # Yeni key ise otomatik ekle
        if re.match(r'^ABX-[A-Z0-9]{8}-\d{6}-\d{4}$', api_key):
            db["api_keys"][api_key] = {
                "user_id": None,
                "expiry_date": (datetime.datetime.now() + datetime.timedelta(days=30)).strftime("%Y-%m-%d"),
                "active": True,
                "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            save_license_db(db)
            return True, None
    
    return False, None

# Kullanıcı erişimini kontrol et
def check_user_access(user_id):
    """Kullanıcının erişimi var mı kontrol et"""
    # Admin kullanıcılar her zaman erişebilir
    if user_id in ADMIN_IDS:
        return True
    
    # Veritabanında authenticated kullanıcıları kontrol et
    db = load_license_db()
    user_id_str = str(user_id)
    
    if user_id_str in db.get("users", {}):
        # Kullanıcının API key'lerini kontrol et
        api_keys = db["users"][user_id_str].get("api_keys", [])
        
        for key in api_keys:
            if key in db.get("api_keys", {}) and db["api_keys"][key].get("active", False):
                # Son kullanma tarihini kontrol et
                expiry_date = datetime.datetime.strptime(db["api_keys"][key]["expiry_date"], '%Y-%m-%d')
                if expiry_date > datetime.datetime.now():
                    # Kullanıcı durumunu güncelle
                    user_state = get_user_state(user_id)
                    user_state["is_authenticated"] = True
                    return True
    
    # Oturum durumunu kontrol et (geçici)
    user_state = get_user_state(user_id)
    return user_state.get("is_authenticated", False)

# Telegram'dan güncellemeleri al - Daha sağlam hale getirildi
def get_updates():
    """Güvenilir şekilde Telegram'dan güncellemeleri al"""
    global offset, BOT_INITIALIZED, connection_errors
    
    if not BOT_INITIALIZED:
        initialize_bot()
    
    for attempt in range(MAX_RETRIES):
        try:
            url = f"{BASE_URL}/getUpdates"
            params = {
                "offset": offset,
                "timeout": 5,  # Daha kısa timeout, daha sık kontrol
                "allowed_updates": json.dumps(["message", "callback_query"])
            }
            
            # Webhook modu temizliği için ek bir parametre ekle
            # Bu parametre, webhook modunun otomatik devre dışı bırakılmasını sağlar
            headers = {"X-Telegram-Bot-Api-Secret-Token": ""}
            
            response = requests.get(url, params=params, headers=headers, timeout=10)
            
            # Başarılı
            if response.status_code == 200:
                data = response.json()
                if data.get("ok", False) and data.get("result"):
                    updates = data["result"]
                    if updates:
                        # Offset'i hemen güncelle (işleme öncesi)
                        # Aynı mesajı tekrar almamak için son update_id + 1 yapılır
                        offset = max([update.get("update_id", 0) for update in updates]) + 1
                        print(f"✅ {len(updates)} adet güncelleme alındı. Yeni offset: {offset}")
                        connection_errors = 0  # Hata sayacını sıfırla
                    return updates
                return []
            
            # HTTP 409 hatası - webhook çakışması - özel işlem
            elif response.status_code == 409:
                print(f"⚠️ HTTP 409 Çakışması (Deneme {attempt+1}/{MAX_RETRIES})")
                
                # Her seferinde yeniden başlatmak yerine, sadece belirli aralıklarla başlat
                if attempt == 0 or attempt % 2 == 0:  # İlk deneme veya her 2 denemede bir
                    # Webhook'u temizle - özel olarak yapılandırılmış temizlik işlemi
                    perform_deep_webhook_cleanup()
                    time.sleep(2)  # Temizlik için biraz bekle
                else:
                    # Diğer denemelerde sadece bekleme yap
                    time.sleep(3 * (attempt + 1))
                    
                # Son denemede None döndür, böylece main fonksiyonu 409 hatası olduğunu anlayabilir
                if attempt == MAX_RETRIES - 1:
                    return None
                continue
            
            # Diğer API hataları
            else:
                print(f"⚠️ API hatası: {response.status_code} - (Deneme {attempt+1}/{MAX_RETRIES})")
                time.sleep(1 * (attempt + 1))  # Artan bekleme süresi
        
        except requests.exceptions.ReadTimeout:
            # Timeout normal, yeni güncellemeler yoktu
            return []
        
        except requests.exceptions.RequestException as e:
            print(f"⚠️ Bağlantı hatası (Deneme {attempt+1}/{MAX_RETRIES}): {e}")
            time.sleep(2 * (attempt + 1))  # Artan bekleme süresi
        
        except Exception as e:
            print(f"⚠️ Beklenmeyen hata (Deneme {attempt+1}/{MAX_RETRIES}): {e}")
            time.sleep(1 * (attempt + 1))  # Artan bekleme süresi
    
    # Tüm denemeler başarısız oldu ve 409 hatası olmadıysa, boş liste döndür
    print("❌ Güncellemeler alınamadı, bir sonraki döngüde tekrar denenecek")
    return []

# Derin webhook temizleme - özel olarak webhook çakışmalarını çözmek için
def perform_deep_webhook_cleanup():
    """Webhook çakışmalarını çözmek için derin temizlik yapar"""
    print("🧹 Derin webhook temizleme başlatılıyor...")
    
    try:
        # 1. Webhook bilgilerini al
        info_url = f"{BASE_URL}/getWebhookInfo"
        info_response = requests.get(info_url, timeout=10)
        
        if info_response.status_code == 200 and info_response.json().get("ok", False):
            info = info_response.json().get("result", {})
            
            webhook_url = info.get("url", "")
            has_webhook = bool(webhook_url)
            
            if has_webhook:
                print(f"🔍 Webhook bulundu: {webhook_url} - Siliniyor...")
                
                # 2. Webhook'u zorla sil (drop_pending_updates=true)
                delete_url = f"{BASE_URL}/deleteWebhook"
                payload = {"drop_pending_updates": True}
                
                # Farklı yöntemlerle deneme yap
                # A. JSON gövdesi ile
                try:
                    requests.post(delete_url, json=payload, timeout=10)
                except:
                    pass
                    
                # B. URL parametresi ile
                try:
                    requests.get(f"{delete_url}?drop_pending_updates=true", timeout=10)
                except:
                    pass
                
                # 3. setWebhook ile boş bir webhook ayarla (eski webhook'u geçersiz kılmak için)
                try:
                    set_url = f"{BASE_URL}/setWebhook"
                    requests.post(set_url, json={"url": ""}, timeout=10)
                except:
                    pass
                
                # 4. Son olarak tekrar deleteWebhook yap
                try:
                    requests.get(delete_url, timeout=10)
                except:
                    pass
            else:
                print("✅ Webhook zaten yapılandırılmamış")
                
            # 5. getUpdates ile bekleyen güncellemeleri temizle
            try:
                clear_url = f"{BASE_URL}/getUpdates"
                clear_params = {
                    "offset": -1,
                    "limit": 1,
                    "timeout": 1,
                    "allowed_updates": json.dumps([])
                }
                
                requests.post(clear_url, json=clear_params, timeout=5)
                requests.get(clear_url, params=clear_params, timeout=5)
            except:
                pass
                
            # 6. Son durumu kontrol et
            final_check = requests.get(info_url, timeout=10).json()
            if final_check.get("ok", False) and not final_check.get("result", {}).get("url", ""):
                print("✅ Derin webhook temizleme başarılı oldu")
                BOT_INITIALIZED = True
                return True
            else:
                print("⚠️ Webhook hala tamamen temizlenemedi")
                return False
        else:
            print("⚠️ Webhook bilgisi alınamadı")
            return False
    except Exception as e:
        print(f"❌ Derin webhook temizleme hatası: {e}")
        return False

def clear_webhooks():
    """Tüm webhook ayarlarını temizle - Geliştirilmiş versiyon"""
    print("🧹 Webhook temizleme başlatılıyor...")
    max_attempts = 3
    
    for attempt in range(max_attempts):
        try:
            # 1. Adım: Mevcut webhook durumunu kontrol et
            info_url = f"{BASE_URL}/getWebhookInfo"
            info_response = requests.get(info_url, timeout=10)
            
            if info_response.status_code != 200:
                print(f"❌ Webhook bilgisi alınamadı (Deneme {attempt+1}/{max_attempts}): {info_response.status_code}")
                time.sleep(2)
                continue
                
            info_data = info_response.json()
            
            # Webhook durumunu logla
            if info_data.get("ok", False) and info_data.get("result", {}).get("url", ""):
                webhook_url = info_data.get("result", {}).get("url", "")
                print(f"🔍 Mevcut webhook bulundu: {webhook_url}, siliniyor...")
            else:
                print("✅ Aktif webhook bulunamadı, adım 2'ye geçiliyor")
                
            # 2. Adım: Her durumda webhook'u sil (önleyici tedbir)
            delete_url = f"{BASE_URL}/deleteWebhook?drop_pending_updates=true"
            delete_response = requests.get(delete_url, timeout=10)
            
            if delete_response.status_code != 200 or not delete_response.json().get("ok", False):
                print(f"⚠️ Webhook silinirken hata (Deneme {attempt+1}/{max_attempts}): {delete_response.status_code}")
                time.sleep(2)
                continue
            
            # 3. Adım: Silme işleminden sonra tekrar kontrol et
            verify_response = requests.get(info_url, timeout=10)
            
            if verify_response.status_code == 200:
                verify_data = verify_response.json()
                if verify_data.get("ok", False) and not verify_data.get("result", {}).get("url", ""):
                    print("✅ Webhook başarıyla silindi ve doğrulandı")
                else:
                    print(f"⚠️ Webhook silindi ama doğrulama başarısız (Deneme {attempt+1}/{max_attempts})")
                    time.sleep(2)
                    continue
            
            # 4. Adım: Bekleyen tüm güncellemeleri temizle
            clear_url = f"{BASE_URL}/getUpdates"
            clear_params = {
                "offset": -1,
                "limit": 1,
                "timeout": 1,
                "allowed_updates": json.dumps([])
            }
            
            clear_response = requests.get(clear_url, params=clear_params, timeout=5)
            
            if clear_response.status_code != 200:
                print(f"⚠️ Güncellemeler temizlenirken hata (Deneme {attempt+1}/{max_attempts}): {clear_response.status_code}")
                time.sleep(2)
                continue
            
            print("🌟 Webhook temizleme süreci başarıyla tamamlandı")
            return True
            
        except Exception as e:
            print(f"❌ Webhook temizlenirken beklenmeyen hata (Deneme {attempt+1}/{max_attempts}): {e}")
            time.sleep(2 * (attempt + 1))  # Artan bekleme süresi
    
    # Tüm denemeler başarısız oldu
    print("⚠️ Webhook temizleme tüm denemelere rağmen başarısız oldu!")
    return False

# Mesaj gönder
def send_message(chat_id, text, reply_markup=None):
    """Mesaj gönder"""
    url = f"{BASE_URL}/sendMessage"
    data = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "Markdown"
    }
    
    if reply_markup:
        data["reply_markup"] = reply_markup
    
    try:
        response = requests.post(url, json=data)
        return response.json()
    except Exception as e:
        print(f"Mesaj gönderilirken hata: {e}")
        return None

# Fotoğraf gönder
def send_photo(chat_id, photo_url, caption=None):
    """Fotoğraf gönder"""
    url = f"{BASE_URL}/sendPhoto"
    data = {
        "chat_id": chat_id,
        "photo": photo_url
    }
    
    if caption:
        data["caption"] = caption
        data["parse_mode"] = "Markdown"
    
    try:
        response = requests.post(url, json=data)
        if response.json().get("ok"):
            # Resim gönderildikten sonra seçenekleri göster
            buttons = [
                [
                    {"text": "🎨 Yeni Görsel Oluştur", "callback_data": "new_image"},
                    {"text": "📱 Ana Menü", "callback_data": "main_menu"}
                ]
            ]
            send_message(
                chat_id,
                "🖼️ *Başka bir görsel oluşturmak ister misiniz?*\n\n"
                "Yeni bir görsel için açıklamanızı yazabilir veya ana menüye dönebilirsiniz.",
                create_keyboard(buttons)
            )
        return response.json()
    except Exception as e:
        print(f"Fotoğraf gönderilirken hata: {e}")
        return None

# Klavye oluştur
def create_keyboard(buttons):
    """Klavye oluştur"""
    return {
        "inline_keyboard": buttons
    }

# Kullanıcı durumunu al
def get_user_state(user_id):
    """Kullanıcı durumunu al"""
    global user_states
    user_id_str = str(user_id)
    if user_id_str not in user_states:
        user_states[user_id_str] = {
            "mode": None,
            "settings": {
                "image_size": "square",
                "language": "tr",
                "favorite_prompts": []
            },
            "is_authenticated": False,
            "waiting_for_api_key": False,
            "last_interaction": time.time()
        }
    return user_states[user_id_str]

# Mesaj işleme fonksiyonlarına aktivite takibi ekleyelim
def update_user_activity(user_id):
    """Kullanıcı aktivitesini güncelle"""
    if user_id in ADMIN_IDS:
        return  # Admin aktiviteleri takip etmeye gerek yok
        
    db = load_license_db()
    user_id_str = str(user_id)
    
    if user_id_str in db.get("users", {}):
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        db["users"][user_id_str]["last_active"] = now
        
        # Kullanım sayaçlarını güncelle
        if "usage" not in db["users"][user_id_str]:
            db["users"][user_id_str]["usage"] = {
                "total_requests": 0,
                "images": 0,
                "chats": 0
            }
        
        db["users"][user_id_str]["usage"]["total_requests"] = db["users"][user_id_str]["usage"].get("total_requests", 0) + 1
        save_license_db(db)

# Resim oluştur
def generate_image(prompt, mode="flux", size=None):
    """Resim oluştur"""
    # İstatistik güncelleme
    db = load_license_db()
    stats = db.get("stats", {"total_requests": 0, "total_images": 0, "total_chats": 0})
    stats["total_requests"] = stats.get("total_requests", 0) + 1
    stats["total_images"] = stats.get("total_images", 0) + 1
    db["stats"] = stats
    save_license_db(db)
    
    # Endpoint ve parametreler
    endpoint = "/image/" if mode == "flux" else "/turbo"
    params = {"prompt": prompt}
    
    if mode == "turbo" and size:
        params["dimensions"] = size
    
    # Tüm API URL'leri dene, akıllı yeniden deneme stratejisi ile
    urls_to_try = [API_URL] + [url for url in ALTERNATE_API_URLS if url != API_URL]
    
    for url in urls_to_try:
        full_url = f"{url}{endpoint}"
        print(f"Resim isteği gönderiliyor: {full_url}")
        
        # Akıllı backoff stratejisi ile API isteği yap (görsel oluşturma için daha uzun timeout)
        response = api_request_with_backoff(
            url=full_url, 
            method="get",
            params=params,
            timeout=API_TIMEOUT_LONG,
            max_retries=3  # Görsel oluşturmada daha az deneme yap
        )
        
        # Yanıt yoksa veya hatalıysa bir sonraki URL ile dene
        if not response or response.status_code != 200:
            print(f"⚠️ Görsel API hatası, alternatif sunucu deneniyor: {url}")
            continue
        
        try:
            # Yanıtı analiz et
            data = response.json()
            print(f"Resim API yanıtı: {data}")
            
            # API yanıtı formatını kontrol et
            if "url" in data:
                return data
            elif "image_urls" in data and data["image_urls"]:
                return {"url": data["image_urls"][0]}
            else:
                print(f"Beklenmedik API yanıtı: {data}")
                continue  # Bir sonraki API ile dene
                
        except Exception as e:
            print(f"Resim yanıtı işlenirken hata: {full_url} - {str(e)}")
            continue  # Bir sonraki API ile dene
    
    # Tüm API'ler başarısız oldu
    print("❌ Tüm görsel oluşturma API'leri başarısız oldu.")
    return {"error": "all_apis_failed", "message": "Üzgünüm, şu anda resim oluşturulamıyor. Lütfen daha sonra tekrar deneyin."}

# AI ile sohbet et
def chat_with_ai(question, model="gpt4"):
    """AI ile sohbet et"""
    # İstatistik güncelleme
    db = load_license_db()
    stats = db.get("stats", {"total_requests": 0, "total_images": 0, "total_chats": 0})
    stats["total_requests"] = stats.get("total_requests", 0) + 1
    stats["total_chats"] = stats.get("total_chats", 0) + 1
    db["stats"] = stats
    save_license_db(db)
    
    # Model parametrelerini doğru formata çevir
    model_params = {
        "gpt4": "gpt-4",
        "gemini": "gemini-1.5-flash",
        "qwen-2.5-coder-32b": "qwen-2.5-coder-32b",
        "deepseek-r1": "deepseek-r1",
        "mixtral-8x7b": "mixtral-8x7b"
    }
    
    api_model = model_params.get(model, "gpt-4")
    print(f"AI isteği gönderiliyor: Model={api_model}, Soru={question[:30]}...")
    
    # Türkçe dil talimatını hazırla
    turkish_instruction = "Sen Türkçe konuşan bir yapay zeka asistanısın. Tüm sorulara SADECE TÜRKÇE yanıt vermelisin. Cevaplarını İngilizce vermemelisin. Tek bir İngilizce kelime bile kullanma."
    
    # Soruyu zenginleştir
    enhanced_question = f"{turkish_instruction} Soru: {question}"
    
    # Sistem mesajı
    system_message = "Bu AI asistanı SADECE TÜRKÇE yanıt verir. İngilizce yanıt vermesi kesinlikle yasaktır."
    
    # İstek parametreleri
    params = {
        "question": enhanced_question, 
        "model": api_model,
        "language": "tr",
        "lang": "tr",
        "system_message": system_message,
        "system": system_message
    }
    
    # Tüm API URL'leri ve endpoint'leri dene, akıllı yeniden deneme stratejisi ile
    urls_to_try = [API_URL] + [url for url in ALTERNATE_API_URLS if url != API_URL]
    endpoints_to_try = ["/chat", "/v1/chat", "/chat/", "/v1/chat/"]
    
    for url in urls_to_try:
        for endpoint in endpoints_to_try:
            full_url = f"{url}{endpoint}"
            print(f"API deneniyor: {full_url}")
            
            # Akıllı backoff stratejisi ile API isteği yap
            response = api_request_with_backoff(
                url=full_url,
                method="get",
                params=params,
                timeout=API_TIMEOUT_LONG
            )
            
            # Yanıt yoksa bir sonraki URL/endpoint ile dene
            if not response:
                continue
                
            # Yanıt 200 değilse bir sonraki URL/endpoint ile dene
            if response.status_code != 200:
                print(f"❌ API hatası: {full_url} - Status {response.status_code}")
                continue
                
            # Başarılı yanıt
            print(f"✅ API yanıtı başarılı: {full_url}")
            
            try:
                # Yanıt içerisinde İngilizce varsa, yanıtı Türkçe'ye çevirme talimatı gönder
                json_response = response.json()
                ai_response = json_response.get("response", "")
                
                # Eğer yanıt İngilizce içeriyorsa, tekrar dene
                if contains_english(ai_response) and api_model in ["deepseek-r1", "mixtral-8x7b"]:
                    print("⚠️ Yanıt İngilizce içeriyor, yeniden deneniyor...")
                    retry_question = f"Lütfen bu cevabı tamamen Türkçe olarak yeniden yaz: {ai_response}"
                    
                    # Türkçe'ye çevirme isteği için aynı backoff stratejisini kullan
                    retry_params = {
                        "question": retry_question,
                        "model": "gpt-4",  # GPT-4 ile dene, daha güvenilir
                        "language": "tr",
                        "lang": "tr"
                    }
                    
                    retry_response = api_request_with_backoff(
                        url=full_url,
                        method="get",
                        params=retry_params,
                        timeout=API_TIMEOUT_MEDIUM
                    )
                    
                    if retry_response and retry_response.status_code == 200:
                        try:
                            retry_json = retry_response.json()
                            json_response["response"] = retry_json.get("response", ai_response)
                        except:
                            pass
                
                return json_response
            except Exception as e:
                print(f"❌ API yanıtı işlenirken hata: {full_url} - {str(e)}")
                continue
    
    # Tüm API bağlantıları başarısız oldu
    print("⚠️ Tüm API bağlantıları başarısız oldu!")
    return {"error": "all_apis_failed", "message": "Üzgünüm, şu anda AI servislerimize bağlanamıyorum. Lütfen daha sonra tekrar deneyin."}

def contains_english(text):
    """Metinde İngilizce kelimeler olup olmadığını kontrol eder"""
    # Basit bir İngilizce kelime listesi
    english_words = ["the", "and", "a", "to", "of", "in", "is", "you", "that", "it", "he", "was", "for", "on", "are", "with", "as", "I", "his", "they", "be", "at", "one", "have", "this", "from", "or", "had", "by", "hot", "but", "some", "what", "there", "we", "can", "out", "other", "were", "all", "your", "when", "up", "use", "word", "how", "said", "an", "each", "she"]
    
    # Metni kelimelere ayır
    words = text.lower().split()
    
    # İlk 50 kelimeyi kontrol et (tüm metni kontrol etmek çok uzun sürebilir)
    first_50_words = words[:50]
    
    # İngilizce kelime sayısı
    english_count = sum(1 for word in first_50_words if word in english_words)
    
    # Eğer belirli bir sayıdan fazla İngilizce kelime varsa, İngilizce içeriyor demektir
    return english_count > 3  # 3'ten fazla İngilizce kelime varsa

# Ödeme bildirimlerini işle
def handle_payment_request(chat_id, user_id, message):
    """Ödeme bildirimlerini işle"""
    global payment_requests
    user_id_str = str(user_id)
    
    if user_id_str not in payment_requests:
        payment_requests[user_id_str] = {
            "step": 1,
            "package": None,
            "payment_method": None,
            "receipt": None,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    
    payment_data = payment_requests[user_id_str]
    
    if payment_data["step"] == 1:
        # Paket seçimi
        if message.strip() in ["1", "3", "12"]:
            payment_data["package"] = message.strip()
            payment_data["step"] = 2
            send_message(
                chat_id,
                "✅ Paket seçiminiz kaydedildi.\n\n"
                "Şimdi lütfen kullandığınız ödeme yöntemini yazın:\n"
                "• Havale/EFT\n"
                "• Papara"
            )
        else:
            send_message(
                chat_id,
                "❌ Geçersiz paket süresi!\n"
                "Lütfen 1, 3 veya 12 yazın."
            )
    
    elif payment_data["step"] == 2:
        # Ödeme yöntemi
        if message.lower() in ["havale", "eft", "havale/eft", "papara"]:
            payment_data["payment_method"] = message.lower()
            payment_data["step"] = 3
            send_message(
                chat_id,
                "✅ Ödeme yöntemi kaydedildi.\n\n"
                "Son olarak, lütfen ödeme dekontunun fotoğrafını gönderin."
            )
        else:
            send_message(
                chat_id,
                "❌ Geçersiz ödeme yöntemi!\n"
                "Lütfen 'Havale/EFT' veya 'Papara' yazın."
            )
    
    elif payment_data["step"] == 3 and "photo" in message:
        # Dekont fotoğrafı
        payment_data["receipt"] = message["photo"][-1]["file_id"]
        payment_data["step"] = 4
        
        # Ödeme bildirimini adminlere ilet
        notify_admins_payment(user_id, payment_data)
        
        # Kullanıcıya bilgi ver
        send_message(
            chat_id,
            "✅ Ödeme bildiriminiz alındı!\n\n"
            "En kısa sürede incelenip onaylanacaktır.\n"
            "Onay sonrası API Key'iniz otomatik olarak oluşturulacak ve size iletilecektir."
        )
        
        # Ödeme kaydını temizle
        del payment_requests[user_id_str]

def notify_admins_payment(user_id, payment_data):
    """Adminlere ödeme bildirimini ilet"""
    for admin_id in ADMIN_IDS:
        # Kullanıcı bilgilerini al
        user_info = f"user_{user_id}"  # Telegram API'den kullanıcı bilgisi alınabilir
        
        message = (
            "💰 *Yeni Ödeme Bildirimi*\n\n"
            f"👤 *Kullanıcı:* {user_info}\n"
            f"📅 *Paket:* {payment_data['package']} ay\n"
            f"💳 *Ödeme:* {payment_data['payment_method']}\n"
            f"⏰ *Tarih:* {payment_data['timestamp']}\n\n"
            "Dekontu kontrol edip onaylamak için aşağıdaki butonları kullanın:"
        )
        
        keyboard = create_keyboard([
            [
                {"text": "✅ Onayla", "callback_data": f"approve_payment_{user_id}_{payment_data['package']}"},
                {"text": "❌ Reddet", "callback_data": f"reject_payment_{user_id}"}
            ]
        ])
        
        # Önce mesajı gönder
        send_message(admin_id, message, keyboard)
        # Sonra dekontu gönder
        if payment_data["receipt"]:
            send_photo(admin_id, payment_data["receipt"])

def handle_admin_payment_action(action, user_id, package=None):
    """Admin ödeme aksiyonlarını işle"""
    if action == "approve":
        # API key oluştur
        key, expiry = generate_api_key(user_id, f"User_{user_id}", int(package) * 30)
        
        # Kullanıcıya bildir
        send_message(
            user_id,
            f"✅ *Ödemeniz Onaylandı!*\n\n"
            f"🔑 *API Key:* `{key}`\n"
            f"📅 *Bitiş Tarihi:* {expiry}\n\n"
            "API Key'inizi girmek için /apikey komutunu kullanabilirsiniz."
        )
        
        # Adminlere bilgi ver
        for admin_id in ADMIN_IDS:
            send_message(
                admin_id,
                f"✅ Kullanıcı {user_id} için {package} aylık API key oluşturuldu.\n"
                f"Key: `{key}`"
            )
    
    elif action == "reject":
        # Kullanıcıya bildir
        send_message(
            user_id,
            "❌ *Ödemeniz Onaylanmadı*\n\n"
            "Lütfen ödeme bilgilerinizi kontrol edip tekrar deneyin veya "
            "destek için yönetici ile iletişime geçin."
        )
        
        # Adminlere bilgi ver
        for admin_id in ADMIN_IDS:
            send_message(
                admin_id,
                f"❌ Kullanıcı {user_id} için ödeme reddedildi."
            )

# Admin komutlarını işle
def handle_admin_command(chat_id, user_id, command, args=None):
    """Admin komutlarını işle"""
    if command == "/users":
        # Kullanıcıları listele
        db = load_license_db()
        users = db.get("users", {})
        
        if not users:
            send_message(chat_id, "Henüz kayıtlı kullanıcı yok.")
            return
        
        message = "*📊 Kayıtlı Kullanıcılar:*\n\n"
        for uid, user_data in users.items():
            message += f"👤 *Kullanıcı:* `{user_data.get('name', 'Bilinmiyor')}`\n"
            message += f"🆔 *ID:* `{uid}`\n"
            message += f"📅 *Kayıt:* {user_data.get('created_at', 'Bilinmiyor')}\n\n"
            
            # API key sayısı ve kullanım bilgisi
            api_keys = user_data.get('api_keys', [])
            active_keys = 0
            for key in api_keys:
                key_data = db.get("api_keys", {}).get(key, {})
                if key_data.get("active", False):
                    active_keys += 1
            
            message += f"🔑 *API Key:* {len(api_keys)} adet ({active_keys} aktif)\n"
            message += f"💬 *Son Kullanım:* {user_data.get('last_active', 'Bilinmiyor')}\n\n"
            
        send_message(chat_id, message)
    
    elif command.startswith("/user "):
        # Belirli bir kullanıcının detaylı bilgilerini göster
        if not args:
            send_message(chat_id, "Lütfen kullanıcı ID belirtin. Örnek: `/user 123456789`")
            return
            
        db = load_license_db()
        user_id_to_show = args.strip()
        
        if user_id_to_show not in db.get("users", {}):
            send_message(chat_id, f"❌ Kullanıcı bulunamadı: `{user_id_to_show}`")
            return
        
        user_data = db["users"][user_id_to_show]
        message = f"*👤 Kullanıcı Detayları:* `{user_data.get('name', 'Bilinmiyor')}`\n\n"
        message += f"🆔 *ID:* `{user_id_to_show}`\n"
        message += f"📅 *Kayıt Tarihi:* {user_data.get('created_at', 'Bilinmiyor')}\n"
        message += f"🕒 *Son Aktivite:* {user_data.get('last_active', 'Bilinmiyor')}\n\n"
        
        # Kullanım istatistikleri
        if "usage" in user_data:
            usage = user_data["usage"]
            message += "*📊 Kullanım İstatistikleri:*\n"
            message += f"• Toplam İstek: {usage.get('total_requests', 0)}\n"
            message += f"• Oluşturulan Resim: {usage.get('images', 0)}\n"
            message += f"• AI Sohbet: {usage.get('chats', 0)}\n\n"
        
        # API Keyleri
        api_keys = user_data.get('api_keys', [])
        message += f"*🔑 API Keyler ({len(api_keys)} adet):*\n"
        
        for key in api_keys:
            key_data = db.get("api_keys", {}).get(key, {})
            active_status = "✅ Aktif" if key_data.get("active", False) else "❌ İptal"
            expiry = key_data.get("expiry_date", "Bilinmiyor")
            
            # Kalan gün hesaplaması
            days_left = "?"
            if expiry != "Bilinmiyor":
                try:
                    expiry_date = datetime.datetime.strptime(expiry, '%Y-%m-%d')
                    today = datetime.datetime.now()
                    days_left = (expiry_date - today).days
                    if days_left < 0:
                        days_left = "Süresi dolmuş"
                    else:
                        days_left = f"{days_left} gün kaldı"
                except:
                    pass
            
            message += f"• `{key}` - {active_status}, {expiry} ({days_left})\n"
        
        send_message(chat_id, message)
    
    elif command.startswith("/newkey"):
        # Yeni API key oluştur
        if not args or len(args.split()) < 2:
            send_message(
                chat_id,
                "*Yeni API Key Oluşturma*\n\n"
                "Kullanım: `/newkey [user_id] [isim] <gün sayısı>`\n\n"
                "Örnekler:\n"
                "• `/newkey 123456789 Ahmet Müşteri` (30 günlük)\n"
                "• `/newkey 123456789 Mehmet 90` (90 günlük)\n"
                "• `/newkey 123456789 Ali 365` (365 günlük)\n"
            )
            return
        
        parts = args.split()
        user_id_to_add = parts[0]
        
        # Gün sayısı kontrolü, varsayılan 30 gün
        expiry_days = 30
        if len(parts) >= 3 and parts[-1].isdigit():
            expiry_days = int(parts[-1])
            name = " ".join(parts[1:-1])
        else:
            name = " ".join(parts[1:])
        
        # API key oluştur
        key, expiry = generate_api_key(user_id_to_add, name, expiry_days)
        
        send_message(
            chat_id,
            f"✅ *API Key Oluşturuldu!*\n\n"
            f"👤 *Kullanıcı:* {name}\n"
            f"🆔 *ID:* `{user_id_to_add}`\n"
            f"🔑 *API Key:* `{key}`\n"
            f"⏱️ *Süre:* {expiry_days} gün\n"
            f"📅 *Son Kullanma:* {expiry}\n\n"
            f"Bu API Key'i kullanıcıya iletebilirsiniz."
        )
    
    elif command == "/revokekey":
        # API key iptal et
        if not args:
            send_message(
                chat_id,
                "*API Key İptal Etme*\n\n"
                "Kullanım: `/revokekey [API_KEY]`\n\n"
                "Örnek: `/revokekey ABI-1234567890abcdef`"
            )
            return
        
        api_key = args.strip()
        db = load_license_db()
        
        if api_key in db.get("api_keys", {}):
            db["api_keys"][api_key]["active"] = False
            save_license_db(db)
            
            # Hangi kullanıcıya ait olduğunu bul
            owner_id = db["api_keys"][api_key]["user_id"]
            owner_name = "Bilinmiyor"
            if str(owner_id) in db.get("users", {}):
                owner_name = db["users"][str(owner_id)].get("name", "Bilinmiyor")
            
            send_message(
                chat_id,
                f"✅ *API Key İptal Edildi!*\n\n"
                f"🔑 *API Key:* `{api_key}`\n"
                f"👤 *Kullanıcı:* {owner_name}\n"
                f"🆔 *ID:* `{owner_id}`\n\n"
                f"Bu API Key artık kullanılamaz."
            )
        else:
            send_message(chat_id, "❌ Bu API Key veritabanında bulunamadı!")
    
    elif command == "/listkeys":
        # API key'leri listele
        db = load_license_db()
        keys = db.get("api_keys", {})
        
        if not keys:
            send_message(chat_id, "Henüz kayıtlı API Key yok.")
            return
        
        message = "*🔑 API Key Listesi:*\n\n"
        
        for key, key_data in keys.items():
            user_id = key_data.get("user_id", "Bilinmiyor")
            user_name = "Bilinmiyor"
            
            if str(user_id) in db.get("users", {}):
                user_name = db["users"][str(user_id)].get("name", "Bilinmiyor")
            
            expiry_date = key_data.get("expiry_date", "Bilinmiyor")
            
            # Kalan gün hesaplama
            days_left = "?"
            if expiry_date != "Bilinmiyor":
                try:
                    expiry = datetime.datetime.strptime(expiry_date, '%Y-%m-%d')
                    today = datetime.datetime.now()
                    days_left = (expiry - today).days
                except:
                    pass
            
            status = "✅ Aktif" if key_data.get("active", False) else "❌ İptal Edildi"
            
            message += f"🔑 *API Key:* `{key}`\n"
            message += f"👤 *Kullanıcı:* {user_name}\n"
            message += f"📅 *Son Kullanma:* {expiry_date} ({days_left} gün kaldı)\n"
            message += f"📊 *Durum:* {status}\n\n"
        
        send_message(chat_id, message)
    
    elif command == "/broadcast":
        # Toplu mesaj gönder
        if not args:
            send_message(
                chat_id, 
                "Lütfen göndermek istediğiniz mesajı belirtin.\n"
                "Örnek: `/broadcast Yeni özellikler eklendi!`"
            )
            return
        
        broadcast_message = args
        db = load_license_db()
        users = db.get("users", {})
        success_count = 0
        
        for uid in users.keys():
            try:
                send_message(int(uid), f"📢 *Duyuru*\n\n{broadcast_message}")
                success_count += 1
            except:
                pass
        
        send_message(chat_id, f"✅ Mesaj {success_count} kullanıcıya gönderildi.")
    
    elif command == "/stats":
        # Kullanım istatistiklerini göster
        db = load_license_db()
        users_count = len(db.get("users", {}))
        keys_count = len(db.get("api_keys", {}))
        active_keys = sum(1 for k in db.get("api_keys", {}).values() if k.get("active", False))
        
        # Tarihe göre API key sayısı
        expiry_stats = {"aktif": 0, "süresi_dolmuş": 0}
        expiry_future = {"30_gün": 0, "90_gün": 0, "365_gün": 0, "diğer": 0}
        
        today = datetime.datetime.now()
        
        for key, key_data in db.get("api_keys", {}).items():
            if not key_data.get("active", False):
                continue
                
            try:
                expiry_date = datetime.datetime.strptime(key_data.get("expiry_date", "2000-01-01"), '%Y-%m-%d')
                
                if expiry_date < today:
                    expiry_stats["süresi_dolmuş"] += 1
                else:
                    expiry_stats["aktif"] += 1
                    days_left = (expiry_date - today).days
                    
                    if days_left <= 30:
                        expiry_future["30_gün"] += 1
                    elif days_left <= 90:
                        expiry_future["90_gün"] += 1
                    elif days_left <= 365:
                        expiry_future["365_gün"] += 1
                    else:
                        expiry_future["diğer"] += 1
            except:
                pass
        
        # Kullanım istatistikleri
        total_requests = db.get("stats", {}).get("total_requests", 0)
        total_images = db.get("stats", {}).get("total_images", 0)
        total_chats = db.get("stats", {}).get("total_chats", 0)
        
        message = "*📊 Sistem İstatistikleri*\n\n"
        message += f"👥 *Toplam Kullanıcı:* {users_count}\n"
        message += f"🔑 *Toplam API Key:* {keys_count}\n"
        message += f"✅ *Aktif API Key:* {active_keys}\n\n"
        
        message += "*Bitiş Tarihi İstatistikleri:*\n"
        message += f"• Aktif API Key: {expiry_stats['aktif']}\n"
        message += f"• Süresi Dolmuş: {expiry_stats['süresi_dolmuş']}\n\n"
        
        message += "*Son Kullanma Tarihi:*\n"
        message += f"• 30 gün içinde bitecek: {expiry_future['30_gün']}\n"
        message += f"• 90 gün içinde bitecek: {expiry_future['90_gün']}\n"
        message += f"• 365 gün içinde bitecek: {expiry_future['365_gün']}\n"
        message += f"• Daha uzun süreli: {expiry_future['diğer']}\n\n"
        
        message += "*Kullanım İstatistikleri:*\n"
        message += f"• Toplam İstek: {total_requests}\n"
        message += f"• Oluşturulan Resim: {total_images}\n"
        message += f"• AI Sohbet: {total_chats}\n"
        
        send_message(chat_id, message)
    
    elif command == "/help":
        # Admin yardım menüsü
        help_text = """
*🛠️ Admin Komutları*

*Kullanıcı Yönetimi:*
• `/users` - Tüm kullanıcıları listele
• `/user [ID]` - Belirli bir kullanıcının detaylarını göster
• `/broadcast [mesaj]` - Tüm kullanıcılara mesaj gönder

*API Key Yönetimi:*
• `/newkey [user_id] [isim] <gün>` - Yeni API key oluştur
• `/revokekey [API_KEY]` - API key'i iptal et
• `/listkeys` - Tüm API key'leri listele

*İstatistikler:*
• `/stats` - Sistem istatistiklerini göster
"""
        send_message(chat_id, help_text)

# API Key komutu
def handle_apikey_command(chat_id, user_id, api_key=None):
    """API Key komutunu işle"""
    global user_states
    user_state = get_user_state(user_id)
    
    # Debug için log ekleme
    print(f"API Key işleme: user_id={user_id}, api_key={api_key}")
    
    # Admin kullanıcı her zaman erişebilir
    if user_id in ADMIN_IDS:
        if not api_key:
            send_message(
                chat_id,
                "Admin olarak tam erişime sahipsiniz. API Key gerekmez."
            )
        return
    
    # Kullanıcı zaten doğrulanmış ise tekrar sorma
    if check_user_access(user_id) and not api_key:
        send_message(
            chat_id,
            "✅ API Key'iniz zaten doğrulanmış durumda.\n"
            "Tüm özellikleri kullanabilirsiniz.",
            create_ai_selection_keyboard(user_id)
        )
        return
    
    # Eğer API key parametresi verilmediyse ve callback'ten geldiyse
    if not api_key:
        user_state["waiting_for_api_key"] = True
        save_user_state(user_id, user_state)
        send_message(
            chat_id,
            "🔑 Lütfen API Key'inizi girin:\n\n"
            "API Key formatı: `ABX-xxxxxxxx-xxxxxx-xxxx`\n"
            "API Key satın almak için yönetici ile iletişime geçin."
        )
        return
    
    # API key'i boşluklardan temizle
    api_key = api_key.strip()
    
    # API key doğrulama
    success, valid_user_id = verify_api_key(api_key)
    print(f"API Key doğrulama sonucu: success={success}, valid_user_id={valid_user_id}")
    
    # API key doğrulandı, ve bu key ya bu kullanıcıya ait ya da yeni oluşturulmuş bir key
    if success and (str(valid_user_id) == str(user_id) or valid_user_id == 0 or valid_user_id is None):
        user_state["is_authenticated"] = True
        user_state["waiting_for_api_key"] = False
        save_user_state(user_id, user_state)
        
        # Lisans veritabanını güncelle
        db = load_license_db()
        user_id_str = str(user_id)
        
        if user_id_str not in db.get("users", {}):
            # Yeni kullanıcı ekle
            db["users"][user_id_str] = {
                "name": f"User_{user_id}",
                "created_at": datetime.datetime.now().strftime("%Y-%m-%d"),
                "api_keys": [api_key],
                "last_active": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "usage": {
                    "total_requests": 0,
                    "images": 0,
                    "chats": 0
                }
            }
        else:
            # Kullanıcı API key'ini güncelle
            if "api_keys" not in db["users"][user_id_str]:
                db["users"][user_id_str]["api_keys"] = []
            
            if api_key not in db["users"][user_id_str]["api_keys"]:
                db["users"][user_id_str]["api_keys"].append(api_key)
        
        # API key'in kullanıcı ID'sini güncelle (eğer yeni bir key ise)
        if api_key in db.get("api_keys", {}) and (db["api_keys"][api_key]["user_id"] == 0 or db["api_keys"][api_key]["user_id"] is None):
            db["api_keys"][api_key]["user_id"] = user_id
        
        save_license_db(db)
        
        send_message(
            chat_id,
            "✅ *API Key doğrulandı!*\n\nArtık tüm özellikleri kullanabilirsiniz.",
            create_ai_selection_keyboard(user_id)
        )
    else:
        # Hata mesajını daha bilgilendirici hale getir
        error_message = "❌ Geçersiz API Key! Lütfen doğru API Key'i girdiğinizden emin olun veya yönetici ile iletişime geçin."
        if success and valid_user_id is not None and str(valid_user_id) != str(user_id):
            error_message = "⚠️ Bu API Key başka bir kullanıcıya atanmış. Lütfen size özel API Key'i kullanın."
        
        send_message(
            chat_id,
            error_message
        )

# Komutları işle
def handle_command(chat_id, user_id, command, args=None):
    """Komutları işle"""
    user_state = get_user_state(user_id)
    
    # Son komut tekrarı kontrolü (aynı komutu kısa sürede tekrar gönderme)
    last_command = user_state.get("last_command", {})
    current_time = time.time()
    
    # Aynı komut son 3 saniye içinde işlendiyse, duplike kabul et
    if last_command.get("command") == command and \
       current_time - last_command.get("time", 0) < 3:
        print(f"⚠️ Duplike komut atlandı: {command} (kullanıcı: {user_id})")
        return
        
    # Son komutu kaydet
    user_state["last_command"] = {
        "command": command,
        "time": current_time
    }
    save_user_state(user_id, user_state)
    
    # Admin komutları
    if user_id in ADMIN_IDS and command.startswith(("/users", "/user ", "/newkey", "/revokekey", "/listkeys", "/broadcast", "/payments")):
        handle_admin_command(chat_id, user_id, command, args)
        return

    if command == "/start":
        welcome_message = (
            "🛡️ *SpartanGPT'ye Hoş Geldiniz* 🛡️\n\n"
            "*Sunduğumuz Özellikler:*\n\n"
            "• 💬 GPT-4 ile sınırsız sohbet\n\n"
            "• 🎨 AI ile yüksek kaliteli görsel oluşturma\n\n"
            "• ⚡ Gemini ile hızlı yanıtlar\n\n"
            "• 🖥️ Qwen Coder ile gelişmiş kodlama desteği\n\n"
            "• 🤖 DeepSeek AI ile akıllı analizler\n\n"
            "• 🌪️ Mistral AI (Yakında!)\n\n"
        )
        
        if check_user_access(user_id):
            welcome_message += "✅ API Key'iniz aktif! Aşağıdaki menüden istediğiniz özelliği kullanabilirsiniz."
            send_message(chat_id, welcome_message, create_ai_selection_keyboard(user_id))
        else:
            welcome_message += "🔑 Başlamak için API Key gereklidir.\n\n" \
                             "API Key'iniz varsa giriş yapabilir, yoksa satın alma işlemi için iletişime geçebilirsiniz."
            keyboard = create_keyboard([
                [
                    {"text": "🔑 API Key Gir", "callback_data": "enter_apikey"},
                    {"text": "💰 Satın Al", "url": "https://wa.me/908505503436"}
                ]
            ])
            send_message(chat_id, welcome_message, keyboard)

    elif command == "/purchase":
        if not check_user_access(user_id):
            keyboard = create_keyboard([
                [
                    {"text": "💰 Satın Al", "url": "https://wa.me/908505503436"}
                ]
            ])
            send_message(
                chat_id,
                "🔑 API Key satın almak için WhatsApp üzerinden iletişime geçebilirsiniz.",
                keyboard
            )
        else:
            send_message(
                chat_id,
                "✅ Zaten aktif bir aboneliğiniz bulunmaktadır.\n"
                "Süreniz dolmadan yeni satın alma işlemi yapamazsınız."
            )

    elif command == "/menu":
        if check_user_access(user_id):
            send_message(chat_id, "🤖 *Ana Menü*\n\nLütfen kullanmak istediğiniz özelliği seçin:", create_ai_selection_keyboard(user_id))
        else:
            send_message(
                chat_id,
                "⚠️ Menüyü kullanmak için API Key gereklidir.\n"
                "Satın alma işlemi için WhatsApp üzerinden iletişime geçebilirsiniz.",
                create_keyboard([
                    [
                        {"text": "💰 Satın Al", "url": "https://wa.me/908505503436"}
                    ]
                ])
            )

    elif command == "/help":
        help_text = (
            "🤖 *Komut Listesi:*\n\n"
            "/start - Botu başlat\n"
            "/menu - Ana menüyü göster\n"
            "/purchase - Satın alma bilgilerini göster\n"
            "/confirm_payment - Ödeme bildirimi yap\n"
            "/apikey - API Key gir\n"
            "/help - Bu yardım mesajını göster\n\n"
            "Sorularınız için yönetici ile iletişime geçebilirsiniz."
        )
        send_message(chat_id, help_text)
    else:
        send_message(
            chat_id,
            "❓ Bilinmeyen komut. Yardım için /help yazabilirsiniz."
        )

# Metin mesajlarını işle
def handle_text(chat_id, user_id, text):
    """Metin mesajlarını işle"""
    user_state = get_user_state(user_id)
    
    # API Key gerekli mi kontrol et
    if not check_user_access(user_id) and user_id not in ADMIN_IDS:
        send_message(
            chat_id,
            "⚠️ Bu özelliği kullanmak için API Key gereklidir.\n"
            "Lütfen /apikey komutunu kullanarak API Key'inizi girin veya satın almak için /purchase yazın."
        )
        return
    
    # Kullanıcı durumunu kontrol et
    if "waiting_for_api_key" in user_state and user_state["waiting_for_api_key"]:
        handle_apikey_command(chat_id, user_id, text)
        return
    
    # Ödeme bildirimi durumunda mı?
    if "waiting_for_payment" in user_state and user_state["waiting_for_payment"]:
        handle_payment_request(chat_id, user_id, text)
        return
        
    # Admin duyuru modunda mı?
    if "waiting_for_broadcast" in user_state and user_state["waiting_for_broadcast"] and user_id in ADMIN_IDS:
        # Duyuru gönderme işlemi
        send_broadcast_message(user_id, text)
        return
    
    # Chat modu aktifse
    if user_state.get("mode") == "chat":
        current_model = user_state.get("current_model", "gpt4")
        
        # Kullanıcıya bekleme mesajı gönder
        wait_message = send_message(
            chat_id,
            f"⏳ *{SUPPORTED_MODELS.get(current_model, 'AI')} yanıtı bekleniyor...*"
        )
        
        # AI'dan yanıt al
        response = chat_with_ai(text, model=current_model)
        
        # Bekleme mesajını sil
        try:
            requests.get(f"{BASE_URL}/deleteMessage", params={
                "chat_id": chat_id,
                "message_id": wait_message.get("result", {}).get("message_id")
            })
        except:
            pass
        
        # Hata kontrolü
        if response is None:
            send_message(
                chat_id, 
                "❌ *AI Yanıt Hatası*\n\n"
                "Üzgünüm, şu anda AI servislerimizle bağlantı kurulamıyor. Lütfen daha sonra tekrar deneyin veya başka bir AI modeli seçin."
            )
            return
        
        # Özel hata mesajları
        if isinstance(response, dict) and "error" in response:
            error_type = response.get("error")
            
            if error_type == "timeout":
                send_message(
                    chat_id,
                    "⏱️ *Zaman Aşımı*\n\n"
                    "AI yanıt vermek için çok uzun süre aldı. Lütfen daha kısa bir soru sorun veya başka bir model deneyin."
                )
            elif error_type == "all_apis_failed":
                send_message(
                    chat_id,
                    "🔌 *Bağlantı Hatası*\n\n"
                    "AI servislerimize şu anda bağlanamıyoruz. Sunucularımız bakımda olabilir. Lütfen biraz sonra tekrar deneyin."
                )
            else:
                send_message(
                    chat_id,
                    f"⚠️ *Bir Hata Oluştu*\n\n"
                    f"{response.get('message', 'Bilinmeyen bir hata oluştu.')}"
                )
            return
        
        # AI Yanıtını formatla ve gönder
        ai_response = response.get("response", "Üzgünüm, yanıt alınamadı.")
        
        # Uzun yanıtları böl
        if len(ai_response) > 4000:
            chunks = [ai_response[i:i+4000] for i in range(0, len(ai_response), 4000)]
            for chunk in chunks:
                send_message(chat_id, chunk)
        else:
            send_message(chat_id, ai_response)

    elif user_state.get("mode") == "image":
        # Resim oluşturma modu
        image_mode = user_state.get("image_model", "flux")
        
        # Zaman sınırı kontrolü - Kullanıcı başına 2 dakika içinde 1 görsel oluşturma limiti
        current_time = time.time()
        last_image_time = user_image_cooldowns.get(user_id, 0)
        time_since_last_image = current_time - last_image_time
        
        # Eğer son 2 dakika içinde bir görsel oluşturulmuşsa
        if time_since_last_image < 120:  # 120 saniye = 2 dakika
            remaining_time = int(120 - time_since_last_image)
            send_message(
                chat_id,
                f"⏳ *Görsel Oluşturma Sınırı*\n\n"
                f"Çok sık görsel oluşturma isteği yapıyorsunuz. Yeni bir görsel oluşturmak için {remaining_time} saniye bekleyin."
            )
            return
        
        # Kullanıcının görsel modunu güncelleyerek duble sorgu sorununu önle
        user_state["mode"] = "processing_image"  # Özel bir mod kullanarak çift sorgu önleniyor
        save_user_state(user_id, user_state)
        
        # Kullanıcıya bilgi mesajı
        send_message(chat_id, "🎨 Resim oluşturuluyor, lütfen bekleyin...")
        
        size = user_state.get("settings", {}).get("image_size", "square") if image_mode == "turbo" else None
        
        # Resim oluşturma isteği
        response = generate_image(text, mode=image_mode, size=size)
        
        # İşlem bitince kullanıcı durumunu güncelle ve zaman damgasını kaydet
        user_state["mode"] = "image"  # Modu tekrar normal görsel moduna çevir
        save_user_state(user_id, user_state)
        user_image_cooldowns[user_id] = current_time  # Zaman damgasını güncelle
        
        if response and "url" in response:
            # Açıklama kaldırıldı
            send_photo(chat_id, response["url"])
        else:
            error_msg = "Üzgünüm, resim oluşturulamadı. Lütfen daha sonra tekrar deneyin."
            if response and response.get("error") == "timeout":
                error_msg = "⏳ Resim oluşturma zaman aşımına uğradı. Lütfen daha sonra tekrar deneyin."
            send_message(chat_id, error_msg)
    
    # Eğer görsel işleme modundaysa, yeni sorguları engelle
    elif user_state.get("mode") == "processing_image":
        send_message(
            chat_id,
            "⏳ Görsel oluşturma işlemi devam ediyor. Lütfen bekleyin..."
        )

# Güncellemeleri işleme - geliştirildi
def process_update(update):
    """Güncellemeyi güvenli şekilde işle"""
    global processed_message_ids, processed_callback_ids, offset
    
    # Geçerli güncelleme kontrolü
    if not update or not isinstance(update, dict):
        return
    
    # Güncelleme ID'sini güncelle (ek güvenlik önlemi)
    update_id = update.get("update_id", 0)
    if update_id > 0 and update_id >= offset:
        offset = update_id + 1
    
    try:
        # Mesaj işleme
        if "message" in update and isinstance(update["message"], dict):
            message = update["message"]
            message_id = message.get("message_id")
            
            # Geçerli mesaj ID kontrolü
            if not message_id:
                return
                
            # Mesaj için benzersiz bir hash oluştur (chat_id + message_id) - Tam duplike kontrolü için
            chat_id = message.get("chat", {}).get("id", 0)
            message_hash = f"{chat_id}_{message_id}"
                
            # Duplike kontrolü - Hem message_id hem de hash ile kontrol
            if message_id in processed_message_ids or message_hash in processed_message_ids:
                print(f"🔄 Duplike mesaj atlandı: {message_hash}")
                return
                
            # İşlenen mesaj ID'sini kaydet
            processed_message_ids.add(message_id)
            processed_message_ids.add(message_hash)  # Hash de ekle
            
            # Bellek optimizasyonu
            if len(processed_message_ids) > 500:  # Daha fazla bellek ayır
                # En son gelen 400 mesajı tut
                processed_message_ids = set(sorted(list(processed_message_ids))[-400:])
            
            # Gerekli alanların varlığını kontrol et
            if "chat" not in message or "id" not in message["chat"]:
                return
            if "from" not in message or "id" not in message["from"]:
                return
                
            chat_id = message["chat"]["id"]
            user_id = message["from"]["id"]
            
            # Kullanıcı aktivitesini güncelle
            update_user_activity(user_id)
            
            # Mesaj işleme
            if "text" in message and isinstance(message["text"], str):
                text = message["text"]
                if text.startswith("/"):
                    command = text.split()[0]
                    args = text[len(command):].strip() if len(text) > len(command) else None
                    handle_command(chat_id, user_id, command, args)
                else:
                    handle_text(chat_id, user_id, text)
            
            # Fotoğraf işleme
            elif "photo" in message and get_user_state(user_id).get("waiting_for_payment"):
                handle_payment_request(chat_id, user_id, message)
        
        # Callback işleme
        elif "callback_query" in update and isinstance(update["callback_query"], dict):
            callback = update["callback_query"]
            callback_id = callback.get("id")
            
            # Geçerli callback ID kontrolü
            if not callback_id:
                return
                
            # Callback için benzersiz bir hash oluştur (user_id + callback_id + data) - Tam duplike kontrolü için
            user_id = callback.get("from", {}).get("id", 0)
            data = callback.get("data", "")
            callback_hash = f"{user_id}_{callback_id}_{data}"
                
            # Duplike kontrolü - Hem callback_id hem de hash ile kontrol
            if callback_id in processed_callback_ids or callback_hash in processed_callback_ids:
                # Yine de yanıtla (kullanıcıya bildirim gösterilmemesi için)
                try:
                    requests.post(
                        f"{BASE_URL}/answerCallbackQuery",
                        json={"callback_query_id": callback_id},
                        timeout=5
                    )
                except:
                    pass
                print(f"🔄 Duplike callback atlandı: {callback_hash}")
                return
                
            # İşlenen callback ID'sini kaydet
            processed_callback_ids.add(callback_id)
            processed_callback_ids.add(callback_hash)  # Hash de ekle
            
            # Bellek optimizasyonu
            if len(processed_callback_ids) > 500:  # Daha fazla bellek ayır
                # En son gelen 400 callback'i tut
                processed_callback_ids = set(sorted(list(processed_callback_ids))[-400:])
            
            # Gerekli alanların varlığını kontrol et
            if "message" not in callback or "chat" not in callback["message"] or "id" not in callback["message"]["chat"]:
                return
            if "from" not in callback or "id" not in callback["from"]:
                return
            if "data" not in callback:
                return
                
            # Kullanıcı aktivitesini güncelle
            update_user_activity(callback["from"]["id"])
                
            # Callback'i işle
            handle_callback(callback)
            
            # Callback'i yanıtla (Telegram'a işlediğimizi bildir)
            try:
                requests.post(
                    f"{BASE_URL}/answerCallbackQuery",
                    json={"callback_query_id": callback_id},
                    timeout=5
                )
            except Exception as e:
                print(f"Callback yanıtlarken hata: {e}")
    
    except Exception as e:
        print(f"⚠️ Güncelleme işlenirken hata: {e}")

# Ana fonksiyon - tamamen yeniden yazıldı
def main():
    """Ana fonksiyon"""
    global processed_message_ids, processed_callback_ids, BOT_INITIALIZED, offset, crash_times, connection_errors
    
    print("🚀 Bot başlatılıyor...")
    
    # Bot kilitleme dosyasını oluştur (çalışıyor işareti)
    try:
        with open(BOT_LOCK_FILE, "w") as lock_file:
            lock_file.write("1")
    except Exception as e:
        print(f"⚠️ Bot kilitleme dosyası oluşturulamadı: {e}")
    
    # Botu başlatmadan önce derin webhook temizliği yap
    perform_deep_webhook_cleanup()
    
    # Botu başlat
    if not initialize_bot():
        print("⚠️ Bot başlatma sırasında sorunlar oluştu")
    
    # Başlangıç durumlarını ayarla
    processed_message_ids = set()
    processed_callback_ids = set()
    connection_errors = 0
    
    # Lisans veritabanı kontrolü
    if not os.path.exists(LICENSE_DB_FILE):
        db = {"users": {}, "api_keys": {}, "stats": {"total_requests": 0, "total_images": 0, "total_chats": 0}}
        save_license_db(db)
        
        # Admin için API key oluştur
        for admin_id in ADMIN_IDS:
            key, expiry = generate_api_key(admin_id, "Admin", 365*10)
            print(f"🔑 Admin API Key oluşturuldu: {key}, Bitiş: {expiry}")
    
    print("✅ Bot hazır ve hizmet veriyor!")
    
    # Daha güvenilir update işleme için queue
    update_queue = []
    last_webhook_check = time.time()
    consecutive_409_errors = 0  # 409 hatalarını takip et
    consecutive_empty_updates = 0
    last_activity_time = time.time()
    
    # Ana döngü
    while True:
        try:
            # Bot kilitleme dosyasını kontrol et, yoksa yeniden oluştur (dışarıdan müdahale kontrolü)
            if not os.path.exists(BOT_LOCK_FILE):
                with open(BOT_LOCK_FILE, "w") as lock_file:
                    lock_file.write("1")
                print("🔒 Bot kilitleme dosyası yeniden oluşturuldu")
            
            # Periyodik webhook kontrolü (30 dakikada bir veya bağlantı sorunlarında)
            if time.time() - last_webhook_check > 1800 or connection_errors > 3:  # 30 dakika
                print("🔄 Periyodik bot durumu kontrolü yapılıyor...")
                BOT_INITIALIZED = False
                initialize_bot()
                last_webhook_check = time.time()
                connection_errors = max(0, connection_errors - 2)  # Hata sayacını azalt
                consecutive_409_errors = 0  # 409 sayacını sıfırla
            
            # Uykuda mod kontrolü - uzun süre aktivite yoksa daha az kaynak kullan
            if time.time() - last_activity_time > 600:  # 10 dakika aktivite yoksa
                sleep_time = 1.0  # Daha uzun bekleme süresi
            else:
                sleep_time = 0.5  # Normal bekleme süresi
            
            # Güncellemeleri al
            updates = get_updates()
            
            # HTTP 409 hatası sayacını yönet (get_updates içinde hata alındıysa)
            if updates is None:  # None döndüyse 409 hatası olabilir
                consecutive_409_errors += 1
                
                # Çok fazla ardışık 409 hatası - derin temizlik yap
                if consecutive_409_errors >= 5:
                    print(f"⚠️ Çok fazla ardışık HTTP 409 hatası ({consecutive_409_errors}), derin temizlik yapılıyor...")
                    perform_deep_webhook_cleanup()
                    time.sleep(5)  # Biraz daha uzun bekle
                    consecutive_409_errors = 0
                    
                # Normal işleme devam et
                updates = []
            else:
                consecutive_409_errors = 0  # Başarılı güncelleme alındıysa sayacı sıfırla
            
            # Eğer güncellemeler alındıysa aktivite zamanını güncelle
            if updates:
                last_activity_time = time.time()
                consecutive_empty_updates = 0
            else:
                consecutive_empty_updates += 1
            
            # Bağlantı hatası sayacını yönet
            if updates is not None or connection_errors > 0:
                connection_errors = max(0, connection_errors - 1)  # Başarılı alımda sayacı azalt
            
            # Bot cevap vermiyor olabilir kontrolü
            if consecutive_empty_updates > 100:  # Uzun süre boş güncelleme
                print("⚠️ Bot uzun süredir güncelleme alamıyor, webhook durumu kontrol ediliyor...")
                perform_deep_webhook_cleanup()  # Derin temizlik yap
                initialize_bot()
                consecutive_empty_updates = 0
            
            # Güncellemeleri kuyruğa ekle
            if updates:
                update_queue.extend(updates)
            
            # Kuyruktaki güncellemeleri işle
            if update_queue:
                # Doğru sırayla işle
                update_queue.sort(key=lambda u: u.get("update_id", 0))
                
                # İşlenen güncellemeleri tut
                processed = []
                
                # Her güncellemeyi işle
                for update in update_queue:
                    # Update_id kontrolü (çok eski güncellemeleri atla)
                    if offset > 0 and update.get("update_id", 0) < offset - 100:
                        processed.append(update)
                        continue
                    
                    try:
                        process_update(update)
                        processed.append(update)
                    except Exception as e:
                        print(f"⚠️ Güncelleme işlenirken hata: {e}")
                        processed.append(update)  # Hataya rağmen işaretleme
                
                # İşlenen güncellemeleri kuyruktan çıkar
                for p in processed:
                    if p in update_queue:
                        update_queue.remove(p)
            
            # CPU kullanımını azaltmak için kısa bekleme
            time.sleep(sleep_time)
            
        except KeyboardInterrupt:
            print("⚠️ Bot kullanıcı tarafından durduruldu")
            # Kilitleme dosyasını temizle
            if os.path.exists(BOT_LOCK_FILE):
                os.remove(BOT_LOCK_FILE)
            break
            
        except Exception as e:
            # Çökme zamanını kaydet
            crash_times.append(time.time())
            
            # Eski çökmeleri temizle (CRASH_WINDOW'dan eski olanları)
            current_time = time.time()
            crash_times = [t for t in crash_times if current_time - t < CRASH_WINDOW]
            
            # Kademeli yeniden bağlanma stratejisi
            connection_errors += 1
            retry_delay = min(30, connection_errors * 5)  # Maksimum 30 saniye bekle
            
            print(f"❌ Ana döngüde kritik hata (Yeniden başlatılıyor - {connection_errors}. deneme): {e}")
            print(f"⏳ {retry_delay} saniye bekleniyor...")
            
            # CRASH_WINDOW içinde MAX_CRASH_COUNT'dan fazla çökme varsa otomatik yeniden başlat
            if len(crash_times) >= MAX_CRASH_COUNT:
                print(f"🚨 Son {CRASH_WINDOW/3600} saat içinde {len(crash_times)} çökme tespit edildi!")
                print("🔄 Bot otomatik olarak yeniden başlatılıyor...")
                
                # Tüm adminlere bildirim gönder
                for admin_id in ADMIN_IDS:
                    try:
                        send_message(
                            admin_id, 
                            f"🚨 *Kritik Uyarı*\n\nBot son {CRASH_WINDOW/3600} saat içinde {len(crash_times)} kez çöktü ve otomatik olarak yeniden başlatılıyor."
                        )
                    except:
                        pass
                
                # Botu yeniden başlat
                restart_bot(manual=False, clean=True)
                return  # Restart sonrası ana fonksiyondan çık
            
            # Çok fazla bağlantı hatası varsa botu yeniden başlat
            if connection_errors > 10:
                print("🔄 Bot bağlantı sorunları nedeniyle yeniden başlatılıyor...")
                perform_deep_webhook_cleanup()  # Derin temizlik yap
                BOT_INITIALIZED = False
                initialize_bot()
                connection_errors = 5  # Sayacı azalt ama sıfırlama
            
            time.sleep(retry_delay)

def create_admin_keyboard():
    """Admin paneli için klavye oluştur"""
    return create_keyboard([
        [
            {"text": "👥 Kullanıcılar", "callback_data": "admin_users"},
            {"text": "🔑 API Keyler", "callback_data": "admin_keys"}
        ],
        [
            {"text": "💰 Ödemeler", "callback_data": "admin_payments"},
            {"text": "📊 İstatistikler", "callback_data": "admin_stats"}
        ],
        [
            {"text": "📢 Duyuru Yap", "callback_data": "admin_broadcast"},
            {"text": "⚙️ Sistem Ayarları", "callback_data": "admin_settings"}
        ],
        [
            {"text": "⬅️ Ana Menü", "callback_data": "main_menu"}
        ]
    ])

def handle_admin_panel(chat_id, user_id, callback_data=None):
    """Admin panelini işle"""
    if user_id not in ADMIN_IDS:
        return
        
    if not callback_data:
        # Ana admin paneli
        send_message(
            chat_id,
            "🛠️ *Admin Kontrol Paneli*\n\n"
            "Lütfen yapmak istediğiniz işlemi seçin:",
            create_admin_keyboard()
        )
        return
        
    if callback_data == "admin_users":
        # Kullanıcı listesi
        db = load_license_db()
        users = db.get("users", {})
        
        if not users:
            send_message(chat_id, "Henüz kayıtlı kullanıcı yok.")
            return
            
        message = "*👥 Kayıtlı Kullanıcılar:*\n\n"
        for uid, user_data in users.items():
            message += f"• ID: `{uid}`\n"
            message += f"  İsim: {user_data.get('name', 'Bilinmiyor')}\n"
            message += f"  Son Aktivite: {user_data.get('last_active', 'Bilinmiyor')}\n\n"
        
        keyboard = create_keyboard([
            [{"text": "⬅️ Admin Paneli", "callback_data": "admin_panel"}]
        ])
        send_message(chat_id, message, keyboard)
    
    elif callback_data == "admin_keys":
        # API Key yönetimi
        db = load_license_db()
        keys = db.get("api_keys", {})
        
        message = "*🔑 API Key Yönetimi*\n\n"
        message += "Aktif API Key'ler:\n\n"
        
        active_keys = 0
        for key, data in keys.items():
            if data.get("active", False):
                active_keys += 1
                message += f"• `{key}`\n"
                message += f"  Kullanıcı ID: {data.get('user_id', 'Bilinmiyor')}\n"
                message += f"  Bitiş: {data.get('expiry_date', 'Bilinmiyor')}\n\n"
        
        if active_keys == 0:
            message += "Aktif API Key bulunamadı.\n"
        
        keyboard = create_keyboard([
            [
                {"text": "🆕 Yeni Key", "callback_data": "admin_new_key"},
                {"text": "❌ Key İptal", "callback_data": "admin_revoke_key"}
            ],
            [{"text": "⬅️ Admin Paneli", "callback_data": "admin_panel"}]
        ])
        send_message(chat_id, message, keyboard)
    
    elif callback_data == "admin_new_key":
        # Yeni API Key oluşturma menüsü
        message = "*🆕 Yeni API Key Oluştur*\n\n"
        message += "Lütfen API Key'in süresini seçin:"
        
        # Süre seçenekleri için butonlar
        keyboard = create_keyboard([
            [
                {"text": "1 Ay", "callback_data": "create_key_30"},
                {"text": "3 Ay", "callback_data": "create_key_90"},
                {"text": "6 Ay", "callback_data": "create_key_180"}
            ],
            [
                {"text": "12 Ay", "callback_data": "create_key_365"},
                {"text": "24 Ay", "callback_data": "create_key_730"},
                {"text": "Sınırsız", "callback_data": "create_key_3650"}
            ],
            [{"text": "⬅️ Geri", "callback_data": "admin_keys"}]
        ])
        
        send_message(chat_id, message, keyboard)
    
    elif callback_data.startswith("create_key_"):
        # Belirli bir süre için API Key oluştur
        days = int(callback_data.split("_")[2])
        
        # Kullanıcı ID'si ata (1'den başla)
        db = load_license_db()
        users = db.get("users", {})
        # En büyük kullanıcı ID'sini bul
        max_id = 0
        for uid in users.keys():
            try:
                num_id = int(uid)
                max_id = max(max_id, num_id)
            except:
                pass
        
        new_user_id = max_id + 1 if max_id > 0 else 1  # 1'den başlat
        
        # Benzersiz, rastgele API Key oluştur
        api_key, expiry = generate_api_key(new_user_id, f"User-{new_user_id}", days)
        
        message = "*✅ Yeni API Key Oluşturuldu!*\n\n"
        message += f"🔑 API Key: `{api_key}`\n"
        message += f"👤 Kullanıcı ID: `{new_user_id}`\n"
        message += f"📅 Bitiş Tarihi: {expiry}\n"
        message += f"⏳ Süre: {days} gün\n\n"
        message += "Bu bilgileri güvenli bir şekilde saklayın!"
        
        keyboard = create_keyboard([
            [{"text": "⬅️ API Key Yönetimine Dön", "callback_data": "admin_keys"}]
        ])
        
        send_message(chat_id, message, keyboard)
        
    elif callback_data == "admin_revoke_key":
        # Key iptal etme - aktif keyler için butonlar göster
        db = load_license_db()
        keys = db.get("api_keys", {})
        
        message = "*❌ API Key İptal Et*\n\n"
        message += "İptal etmek istediğiniz kullanıcının API Key'ini seçin:\n\n"
        
        # Butonlar için aktif kullanıcıları hazırla
        buttons = []
        row = []
        count = 0
        
        # Aktif kullanıcıları ve keylerini butonlar olarak göster
        active_users = {}
        for key, data in keys.items():
            if data.get("active", False):
                user_id = data.get("user_id", "")
                if user_id not in active_users:
                    active_users[user_id] = []
                active_users[user_id].append(key)
        
        # Kullanıcı başına bir buton oluştur
        for user_id, user_keys in active_users.items():
            count += 1
            row.append({"text": f"ID: {user_id}", "callback_data": f"revoke_key_{user_id}"})
            
            # Her satırda 2 buton olsun
            if count % 2 == 0 or count == len(active_users):
                buttons.append(row)
                row = []
        
        # Geri butonu ekle
        buttons.append([{"text": "⬅️ Geri", "callback_data": "admin_keys"}])
        
        # Eğer aktif kullanıcı yoksa bilgi mesajı göster
        if not active_users:
            message += "Aktif API Key bulunamadı."
            buttons = [[{"text": "⬅️ Geri", "callback_data": "admin_keys"}]]
        
        keyboard = create_keyboard(buttons)
        send_message(chat_id, message, keyboard)
    
    elif callback_data == "admin_payments":
        # Ödeme yönetimi
        if not payment_requests:
            message = "*💰 Ödeme Bildirimleri*\n\nBekleyen ödeme bildirimi yok."
        else:
            message = "*💰 Bekleyen Ödeme Bildirimleri:*\n\n"
            for user_id, data in payment_requests.items():
                message += f"👤 Kullanıcı ID: `{user_id}`\n"
                message += f"📅 Paket: {data.get('package', 'Bilinmiyor')} ay\n"
                message += f"💳 Yöntem: {data.get('payment_method', 'Bilinmiyor')}\n"
                message += f"⏰ Tarih: {data.get('timestamp', 'Bilinmiyor')}\n\n"
        
        keyboard = create_keyboard([
            [{"text": "⬅️ Admin Paneli", "callback_data": "admin_panel"}]
        ])
        send_message(chat_id, message, keyboard)
    
    elif callback_data == "admin_stats":
        # İstatistikler
        db = load_license_db()
        stats = db.get("stats", {})
        
        message = "*📊 Sistem İstatistikleri*\n\n"
        message += f"Toplam İstek: {stats.get('total_requests', 0)}\n"
        message += f"Oluşturulan Resim: {stats.get('total_images', 0)}\n"
        message += f"AI Sohbet: {stats.get('total_chats', 0)}\n\n"
        
        # Kullanım istatistikleri
        users = db.get("users", {})
        message += f"Toplam Kullanıcı: {len(users)}\n"
        active_today = sum(1 for u in users.values() if u.get("last_active", "").startswith(datetime.datetime.now().strftime("%Y-%m-%d")))
        message += f"Bugün Aktif: {active_today}\n"
        
        keyboard = create_keyboard([
            [{"text": "⬅️ Admin Paneli", "callback_data": "admin_panel"}]
        ])
        send_message(chat_id, message, keyboard)
    
    elif callback_data == "admin_broadcast":
        # Duyuru gönderme
        user_state = get_user_state(user_id)
        user_state["waiting_for_broadcast"] = True
        
        keyboard = create_keyboard([
            [{"text": "❌ İptal", "callback_data": "admin_panel"}]
        ])
        send_message(
            chat_id,
            "*📢 Duyuru Gönderme*\n\n"
            "Lütfen göndermek istediğiniz duyuru mesajını yazın.\n"
            "İptal etmek için butonu kullanın.",
            keyboard
        )
    
    elif callback_data == "admin_settings":
        # Sistem ayarları
        keyboard = create_keyboard([
            [
                {"text": "🔄 Bot'u Yeniden Başlat", "callback_data": "admin_restart"},
                {"text": "🧹 Önbelleği Temizle", "callback_data": "admin_clear_cache"}
            ],
            [{"text": "⬅️ Admin Paneli", "callback_data": "admin_panel"}]
        ])
        send_message(
            chat_id,
            "*⚙️ Sistem Ayarları*\n\n"
            "Lütfen bir işlem seçin:",
            keyboard
        )

# Callback işleyicisine admin panel desteği ekle
def handle_callback(callback_query):
    """Callback'leri işle"""
    chat_id = callback_query["message"]["chat"]["id"]
    user_id = callback_query["from"]["id"]
    data = callback_query["data"]
    
    print(f"Callback: {data} from user {user_id}")
    
    # Kullanıcı lisans kontrolü - ancak bazı callback'ler için her zaman izin ver
    if data not in ["enter_apikey", "purchase_info", "confirm_payment", "main_menu", "help"] and not check_user_access(user_id) and user_id not in ADMIN_IDS:
        handle_unauthorized_callback(chat_id, user_id, data)
        return
    
    # Kullanıcı durumunu al
    user_state = get_user_state(user_id)
    
    # New Image callback işleme
    if data == "new_image":
        # Zaman sınırı kontrolü - Kullanıcı başına 2 dakika içinde 1 görsel oluşturma limiti
        current_time = time.time()
        last_image_time = user_image_cooldowns.get(user_id, 0)
        time_since_last_image = current_time - last_image_time
        
        # Eğer son 2 dakika içinde bir görsel oluşturulmuşsa
        if time_since_last_image < 120:  # 120 saniye = 2 dakika
            remaining_time = int(120 - time_since_last_image)
            send_message(
                chat_id,
                f"⏳ *Görsel Oluşturma Sınırı*\n\n"
                f"Çok sık görsel oluşturma isteği yapıyorsunuz. Yeni bir görsel oluşturmak için {remaining_time} saniye bekleyin."
            )
            return
            
        # Kullanıcı görsel oluşturma moduna geçisin
        current_model = user_state.get("image_model", "flux")  # Varsayılan model
        model_name = IMAGE_MODELS.get(current_model, "FLUX")
        
        user_state["mode"] = "image"
        save_user_state(user_id, user_state)
        
        send_message(
            chat_id,
            f"🎨 *{model_name} görsel oluşturma modundasınız!*\n\n"
            "Lütfen bir görsel açıklaması/promptu girin. Ana menüye dönmek için /menu yazabilirsiniz."
        )
        return
    
    # Model seçimleri
    if data in SUPPORTED_MODELS.keys():
        model_name = SUPPORTED_MODELS[data]
        user_state["mode"] = "chat"
        user_state["current_model"] = data
        save_user_state(user_id, user_state)
        
        send_message(
            chat_id,
            f"🤖 *{model_name} seçildi!*\n\n"
            "Şimdi bana bir soru sorun. Ana menüye dönmek için /menu yazabilirsiniz."
        )
        return
    
    # Görsel modeli seçimleri
    elif data in IMAGE_MODELS.keys():
        model_name = IMAGE_MODELS[data]
        user_state["mode"] = "image"
        user_state["image_model"] = data
        save_user_state(user_id, user_state)
        
        send_message(
            chat_id,
            f"🎨 *{model_name} seçildi!*\n\nLütfen bir görsel açıklaması/promptu girin. Ana menüye dönmek için /menu yazabilirsiniz."
        )
        return
    
    # Admin panel işlemleri
    if data == "admin_panel":
        if user_id in ADMIN_IDS:
            handle_admin_panel(chat_id, user_id)
        return
    
    # Admin restart ve cache temizleme işlemleri
    if data == "admin_restart" and user_id in ADMIN_IDS:
        send_message(chat_id, "🔄 *Bot yeniden başlatılıyor...*\nBu işlem birkaç saniye sürebilir.")
        restart_bot(manual=True)
        return
        
    if data == "admin_clear_cache" and user_id in ADMIN_IDS:
        clean_cache()
        send_message(chat_id, "✅ *Önbellek temizlendi*\nBot daha verimli çalışacak şekilde optimize edildi.")
        return
    
    # Admin ödeme işlemleri
    if user_id in ADMIN_IDS and data.startswith(("approve_payment_", "reject_payment_")):
        action, target_user_id = data.split("_")[0:2]
        package = data.split("_")[3] if len(data.split("_")) > 3 else None
        handle_admin_payment_action(action, int(target_user_id), package)
        return
    
    # Admin panel alt menüleri ve API key işlemleri
    if user_id in ADMIN_IDS and (data.startswith("admin_") or data.startswith("create_key_")):
        handle_admin_panel(chat_id, user_id, data)
        return
    
    # API key iptal işlemi
    if user_id in ADMIN_IDS and data.startswith("revoke_key_"):
        target_user_id = data.split("_")[2]
        db = load_license_db()
        
        # Hedef kullanıcının tüm keylerini iptal et
        for key, key_data in list(db.get("api_keys", {}).items()):
            if str(key_data.get("user_id")) == target_user_id:
                db["api_keys"][key]["active"] = False
                
        save_license_db(db)
        
        message = f"✅ *{target_user_id} ID'li kullanıcının tüm API Key'leri iptal edildi.*"
        send_message(chat_id, message)
        
        # API key yönetim ekranına geri dön
        handle_admin_panel(chat_id, user_id, "admin_keys")
        return
    
    # Satın alma bilgisi
    if data == "purchase_info":
        payment_info = (
            "*💳 Ödeme Bilgileri*\n\n"
            "*Banka Hesabı:*\n"
            "• Banka: X Bankası\n"
            "• IBAN: TR00 0000 0000 0000 0000 0000 00\n"
            "• Ad Soyad: XXXXX XXXXX\n\n"
            "*Papara:*\n"
            "• Numara: 0000000000\n"
            "• Ad Soyad: XXXXX XXXXX\n\n"
            "*📝 Ödeme Sonrası:*\n"
            "1. Ödeme dekontunu saklayın\n"
            "2. /confirm_payment komutunu kullanın\n"
            "3. İstediğiniz paketi ve ödeme yöntemini belirtin\n"
            "4. Dekontu gönderin\n\n"
            "Ödemeniz onaylandıktan sonra API Key'iniz otomatik olarak oluşturulacaktır."
        )
        keyboard = create_keyboard([
            [
                {"text": "📝 Ödeme Bildirimi Yap", "callback_data": "confirm_payment"}
            ]
        ])
        send_message(chat_id, payment_info, keyboard)
        return
    
    # Ödeme bildirimi başlat
    if data == "confirm_payment":
        if not check_user_access(user_id):
            user_state["waiting_for_payment"] = True
            send_message(
                chat_id,
                "*💳 Ödeme Bildirimi*\n\n"
                "Lütfen sırasıyla şu bilgileri gönderin:\n\n"
                "1. Seçtiğiniz paket (1/3/12 ay)\n"
                "2. Kullandığınız ödeme yöntemi\n"
                "3. Dekont görüntüsü\n\n"
                "İptal etmek için /cancel yazabilirsiniz."
            )
        else:
            send_message(
                chat_id,
                "✅ Zaten aktif bir aboneliğiniz bulunmaktadır."
            )
        return
    
    # API key giriş işlemi
    if data == "enter_apikey":
        handle_apikey_command(chat_id, user_id)
        return
        
    # Ana menü
    if data == "main_menu":
        send_message(chat_id, "🤖 *Ana Menü*\n\nLütfen kullanmak istediğiniz özelliği seçin:", create_ai_selection_keyboard(user_id))
        return
        
    # Ayarlar menüsü
    elif data == "settings":
        buttons = [
            [
                {"text": "🖌️ Varsayılan Resim Boyutu", "callback_data": "setting_image_size"}
            ],
            [
                {"text": "🔢 API Kullanım İstatistikleri", "callback_data": "setting_stats"}
            ],
            [
                {"text": "⬅️ Ana Menü", "callback_data": "main_menu"}
            ]
        ]
        send_message(
            chat_id,
            "⚙️ *Ayarlar Menüsü*\n\n"
            "Aşağıdaki ayarları düzenleyebilirsiniz:",
            create_keyboard(buttons)
        )
        return
    
    # Resim boyutu ayarları
    elif data == "setting_image_size":
        buttons = [
            [
                {"text": "🔳 Kare", "callback_data": "default_size_square"},
                {"text": "📱 Dikey", "callback_data": "default_size_portrait"},
                {"text": "🖥️ Yatay", "callback_data": "default_size_landscape"}
            ],
            [
                {"text": "⬅️ Ayarlar", "callback_data": "settings"}
            ]
        ]
        
        current_size = user_state.get("settings", {}).get("image_size", "square")
        
        send_message(
            chat_id,
            "🖌️ *Varsayılan Resim Boyutu*\n\n"
            f"Mevcut ayar: `{current_size}`\n\n"
            "Lütfen varsayılan resim boyutunu seçin:",
            create_keyboard(buttons)
        )
        return
    
    # Varsayılan boyut seçimi
    elif data.startswith("default_size_"):
        size = data.replace("default_size_", "")
        if "settings" not in user_state:
            user_state["settings"] = {}
        user_state["settings"]["image_size"] = size
        save_user_state(user_id, user_state)
        
        send_message(
            chat_id,
            f"✅ Varsayılan resim boyutu *{size}* olarak ayarlandı.",
            create_keyboard([[{"text": "⬅️ Ayarlar", "callback_data": "settings"}]])
        )
        return
    
    # İstatistikler
    elif data == "setting_stats":
        # Kullanım istatistiklerini göster
        db = load_license_db()
        user_id_str = str(user_id)
        
        if user_id_str in db.get("users", {}):
            usage = db["users"][user_id_str].get("usage", {"total_requests": 0, "images": 0, "chats": 0})
            stats_text = (
                "📊 *Kullanım İstatistikleriniz*\n\n"
                f"• Toplam İstek: {usage.get('total_requests', 0)}\n"
                f"• Resim Oluşturma: {usage.get('images', 0)}\n"
                f"• AI Sohbet: {usage.get('chats', 0)}\n\n"
            )
            
            # API key bilgisi
            api_keys = db["users"][user_id_str].get("api_keys", [])
            active_keys = 0
            expiry_dates = []
            
            for key in api_keys:
                key_data = db.get("api_keys", {}).get(key, {})
                if key_data.get("active", False):
                    active_keys += 1
                    if "expiry_date" in key_data:
                        expiry_dates.append(key_data["expiry_date"])
            
            if expiry_dates:
                latest_expiry = max(expiry_dates)
                stats_text += f"• API Key Bitiş: {latest_expiry}\n"
            
            send_message(
                chat_id,
                stats_text,
                create_keyboard([[{"text": "⬅️ Ayarlar", "callback_data": "settings"}]])
            )
        else:
            send_message(
                chat_id,
                "❌ Kullanım istatistikleri bulunamadı.",
                create_keyboard([[{"text": "⬅️ Ayarlar", "callback_data": "settings"}]])
            )
        return
    
    # Yardım menüsü
    elif data == "help":
        help_text = (
            "🤖 *Komut Listesi:*\n\n"
            "/start - Botu başlat\n"
            "/menu - Ana menüyü göster\n"
            "/purchase - Satın alma bilgilerini göster\n"
            "/confirm_payment - Ödeme bildirimi yap\n"
            "/apikey - API Key gir\n"
            "/help - Bu yardım mesajını göster\n\n"
            "Sorularınız için yönetici ile iletişime geçebilirsiniz."
        )
        send_message(chat_id, help_text)
        return
    
    # Resim boyutu seçimi (görsel oluşturma için)
    elif data.startswith("size_"):
        size_map = {
            "size_square": "square",
            "size_portrait": "portrait", 
            "size_landscape": "landscape"
        }
        if "settings" not in user_state:
            user_state["settings"] = {}
        user_state["settings"]["image_size"] = size_map.get(data, "square")
        save_user_state(user_id, user_state)
        
        send_message(
            chat_id,
            f"✅ Resim boyutu *{size_map.get(data, 'square')}* olarak ayarlandı.\n\n"
            "Şimdi resim açıklamanızı yazabilirsiniz:"
        )
        return
    
    # Eğer burada hala geldiysek, işlenmeyen bir callback var
    print(f"⚠️ İşlenmeyen callback: {data}")
    send_message(
        chat_id,
        "⚠️ Bu işlem şu anda kullanılamıyor. Lütfen ana menüye dönün.",
        create_keyboard([[{"text": "⬅️ Ana Menü", "callback_data": "main_menu"}]])
    )

# Ana menüye admin panel butonu ekle
def create_ai_selection_keyboard(user_id):
    """AI seçim klavyesini oluştur"""
    buttons = [
        [
            {"text": "💬 GPT-4", "callback_data": "gpt4"},
            {"text": "⚡ Gemini Flash", "callback_data": "gemini"}
        ],
        [
            {"text": "🧠 Qwen Coder", "callback_data": "qwen-2.5-coder-32b"},
            {"text": "🤖 Deepseek AI", "callback_data": "deepseek-r1"}
        ],
        [
            {"text": "🔮 Mistral AI", "callback_data": "mixtral-8x7b"}
        ],
        [
            {"text": "🎨 Görsel Oluştur (FLUX V3)", "callback_data": "flux"},
            {"text": "🖼️ Turbo (Özel Boyut)", "callback_data": "turbo"}
        ],
        [
            {"text": "⚙️ Ayarlar", "callback_data": "settings"},
            {"text": "❓ Yardım", "callback_data": "help"}
        ]
    ]
    
    # Admin için ekstra buton
    if user_id in ADMIN_IDS:
        buttons.append([{"text": "🛠️ Admin Paneli", "callback_data": "admin_panel"}])
    
    return create_keyboard(buttons)

# Bot başlatma ve webhook temizleme (Çok güçlendirildi)
def initialize_bot():
    """Botu tamamen temizleyerek başlat"""
    global offset, BOT_INITIALIZED
    
    if BOT_INITIALIZED:
        return True
        
    print("🚀 Bot başlatılıyor - Kritik Başlangıç Sırası...")
    
    # 1. Adım: Mevcut webhookları kontrol et ve temizle
    for _ in range(3):  # 3 deneme
        try:
            # Webhook durumunu kontrol et
            info_url = f"{BASE_URL}/getWebhookInfo"
            info_response = requests.get(info_url, timeout=10)
            
            if info_response.status_code != 200:
                print(f"❌ Webhook bilgisi alınamadı: {info_response.status_code}")
                time.sleep(3)
                continue
                
            info_data = info_response.json()
            
            # Webhook varsa sil
            if info_data.get("ok", False) and info_data.get("result", {}).get("url", ""):
                webhook_url = info_data.get("result", {}).get("url", "")
                print(f"🔍 Mevcut webhook bulundu: {webhook_url}, siliniyor...")
                
                # Webhook'u sil
                delete_url = f"{BASE_URL}/deleteWebhook?drop_pending_updates=true"
                delete_response = requests.get(delete_url, timeout=10)
                
                if delete_response.status_code != 200 or not delete_response.json().get("ok", False):
                    print(f"❌ Webhook silinirken hata: {delete_response.status_code}")
                    time.sleep(3)
                    continue
                    
                print("✅ Webhook başarıyla silindi")
                time.sleep(2)  # İşlemin tamamlanması için bekle
            else:
                print("✅ Aktif webhook bulunamadı, temiz durum")
                
            # 2. Adım: Bekleyen tüm güncellemeleri sil
            clear_url = f"{BASE_URL}/getUpdates"
            clear_params = {
                "offset": -1,
                "limit": 1,
                "timeout": 1
            }
            clear_response = requests.post(clear_url, json=clear_params, timeout=5)
            
            if clear_response.status_code != 200:
                print(f"⚠️ Güncellemeler temizlenirken hata: {clear_response.status_code}")
            
            # 3. Adım: Webhook hala ayarlı olup olmadığını son kez kontrol et
            time.sleep(1)
            final_check = requests.get(info_url, timeout=10).json()
            
            if final_check.get("ok", False) and final_check.get("result", {}).get("url", ""):
                print("⚠️ Webhook hala silinmedi, yeniden deneniyor...")
                time.sleep(3)
                continue
                
            # 4. Adım: Başarıyla temizlendi, botu başlat
            offset = 0
            BOT_INITIALIZED = True
            print("🌟 Bot tamamen başlatıldı ve temiz durumda!")
            return True
            
        except Exception as e:
            print(f"❌ Bot başlatılırken kritik hata: {e}")
            time.sleep(3)
    
    print("⚠️ Bot tam olarak başlatılamadı! Yine de devam ediliyor...")
    BOT_INITIALIZED = True  # Yine de devam et
    return False

def handle_unauthorized_callback(chat_id, user_id, data):
    """Yetkisiz callback işlemleri"""
    if data == "enter_apikey":
        handle_apikey_command(chat_id, user_id)
    elif data == "purchase_info":
        payment_info = (
            "*💳 Ödeme Bilgileri*\n\n"
            "*Banka Hesabı:*\n"
            "• Banka: X Bankası\n"
            "• IBAN: TR00 0000 0000 0000 0000 0000 00\n"
            "• Ad Soyad: XXXXX XXXXX\n\n"
            "*Papara:*\n"
            "• Numara: 0000000000\n"
            "• Ad Soyad: XXXXX XXXXX\n\n"
            "*📝 Ödeme Sonrası:*\n"
            "1. Ödeme dekontunu saklayın\n"
            "2. /confirm_payment komutunu kullanın\n"
            "3. İstediğiniz paketi ve ödeme yöntemini belirtin\n"
            "4. Dekontu gönderin\n\n"
            "Ödemeniz onaylandıktan sonra API Key'iniz otomatik olarak oluşturulacaktır."
        )
        keyboard = create_keyboard([
            [
                {"text": "📝 Ödeme Bildirimi Yap", "callback_data": "confirm_payment"}
            ]
        ])
        send_message(chat_id, payment_info, keyboard)
    elif data == "confirm_payment":
        user_state = get_user_state(user_id)
        user_state["waiting_for_payment"] = True
        send_message(
            chat_id,
            "*💳 Ödeme Bildirimi*\n\n"
            "Lütfen sırasıyla şu bilgileri gönderin:\n\n"
            "1. Seçtiğiniz paket (1/3/12 ay)\n"
            "2. Kullandığınız ödeme yöntemi\n"
            "3. Dekont görüntüsü\n\n"
            "İptal etmek için /cancel yazabilirsiniz."
        )
    else:
        send_message(
            chat_id, 
            "⚠️ Bu özelliği kullanmak için API Key gereklidir.\n"
            "Lütfen /apikey komutunu kullanarak API Key'inizi girin veya satın almak için /purchase yazın."
        )

def save_user_state(user_id, state):
    """Kullanıcı durumunu kaydet"""
    # Bu işlevi basitleştirdik - gerçek bot uygulamasında veritabanı kullanılabilir
    # Şu anda kullanıcı durumları RAM'de tutulduğu için sadece güncelleme yapıyoruz
    user_states[user_id] = state
    return True

# Bot durumu ve hata izleme için global değişkenler
MAX_CRASH_COUNT = 5  # Maksimum çökme sayısı
CRASH_WINDOW = 3600  # Çökme sayısının sıfırlanacağı süre (saniye, 1 saat)
crash_times = []     # Son çökme zamanlarını takip etmek için liste
BOT_LOCK_FILE = "bot.lock"  # Bot kilitleme dosyası
MAX_RESTART_ATTEMPTS = 3    # Maksimum yeniden başlatma girişimi

# Bot yeniden başlatma işlevi
def restart_bot(manual=False, clean=False):
    """
    Botu güvenli bir şekilde yeniden başlatır.
    
    Args:
        manual: Manuel yeniden başlatma ise True, otomatik ise False
        clean: Önbelleği temizleyerek başlatma yapılacaksa True
    """
    try:
        # Yeniden başlatma bilgisini logla
        restart_type = "Manuel" if manual else "Otomatik"
        print(f"🔄 {restart_type} yeniden başlatma başlatılıyor...")
        
        if clean:
            print("🧹 Önbellek temizleniyor...")
            # İşlem öncesi önbellek temizliği
            # Bu fonksiyon önbellekle ilgili dosyaları temizler
            clean_cache()
        
        # Kilitleme dosyası varsa sil
        if os.path.exists(BOT_LOCK_FILE):
            os.remove(BOT_LOCK_FILE)
            print("🔓 Bot kilidi kaldırıldı")
            
        # Webhook'ları temizle (yeni başlangıç için)
        clear_webhooks()
        
        print("👋 Bot yeniden başlatılıyor...")
        
        # Mevcut işlemi sonlandırıp, yeniden başlat
        if manual:
            # Admin tarafından başlatıldıysa tüm adminlere bildirim gönder
            for admin_id in ADMIN_IDS:
                try:
                    send_message(admin_id, "🔄 *Bot yeniden başlatılıyor...*\nBu işlem birkaç saniye sürebilir.")
                except:
                    pass
        
        # Mevcut script'i yeniden başlat
        python = sys.executable
        script = os.path.abspath(__file__)
        
        # Eski süreci öldürmeden önce yeni süreci başlat
        subprocess.Popen([python, script])
        
        # Kısa bir süre bekleyip mevcut süreci sonlandır
        time.sleep(2)
        sys.exit(0)
        
    except Exception as e:
        print(f"❌ Yeniden başlatma sırasında hata: {e}")
        return False

# Önbellek temizleme fonksiyonu
def clean_cache():
    """Geçici dosyaları ve önbelleği temizler"""
    try:
        # İşlenmiş mesaj ve callback ID'lerini temizle
        global processed_message_ids, processed_callback_ids
        processed_message_ids = set()
        processed_callback_ids = set()
        
        # Diğer önbellek temizleme işlemleri buraya eklenebilir
        print("✅ Önbellek başarıyla temizlendi")
        return True
    except Exception as e:
        print(f"⚠️ Önbellek temizleme hatası: {e}")
        return False

# Duyuru mesajı gönder
def send_broadcast_message(admin_id, message):
    """
    Tüm kullanıcılara duyuru mesajı gönderir
    
    Args:
        admin_id: Duyuruyu gönderen admin ID'si
        message: Gönderilecek duyuru mesajı
    """
    # Admin durumunu temizle
    user_state = get_user_state(admin_id)
    user_state.pop("waiting_for_broadcast", None)
    save_user_state(admin_id, user_state)
    
    # Duyuru mesajını formatla
    broadcast_message = (
        "*📢 BOT DUYURUSU*\n\n"
        f"{message}\n\n"
        f"_Bu duyuru yönetici tarafından gönderilmiştir._"
    )
    
    # Lisans veritabanından tüm kullanıcıları al
    db = load_license_db()
    users = db.get("users", {})
    
    # Başarı ve hata sayacı
    success_count = 0
    fail_count = 0
    
    # Admine bilgi mesajı
    status_msg = send_message(
        admin_id,
        "🔄 *Duyuru Gönderiliyor*\n\n"
        "Lütfen bekleyin, duyuru tüm kullanıcılara gönderiliyor..."
    )
    
    # Tüm kullanıcılara gönder
    for user_id_str, user_data in users.items():
        try:
            user_id = int(user_id_str)
            send_message(user_id, broadcast_message)
            success_count += 1
            
            # Her 10 kullanıcıda bir durum güncellemesi
            if success_count % 10 == 0:
                try:
                    requests.post(
                        f"{BASE_URL}/editMessageText",
                        json={
                            "chat_id": admin_id,
                            "message_id": status_msg.get("result", {}).get("message_id"),
                            "text": f"🔄 *Duyuru Gönderiliyor*\n\n"
                                    f"İşlenen: {success_count + fail_count}/{len(users)}\n"
                                    f"Başarılı: {success_count} | Başarısız: {fail_count}",
                            "parse_mode": "Markdown"
                        },
                        timeout=5
                    )
                except:
                    pass
                
            # API limitlerini aşmamak için kısa bekleme
            time.sleep(0.1)
        except Exception as e:
            print(f"Duyuru gönderme hatası (Kullanıcı {user_id_str}): {e}")
            fail_count += 1
    
    # Sonuç mesajı
    completion_message = (
        "✅ *Duyuru Tamamlandı*\n\n"
        f"Toplam: {len(users)} kullanıcı\n"
        f"Başarılı: {success_count}\n"
        f"Başarısız: {fail_count}"
    )
    
    # Durum mesajını güncelle
    try:
        requests.post(
            f"{BASE_URL}/editMessageText",
            json={
                "chat_id": admin_id,
                "message_id": status_msg.get("result", {}).get("message_id"),
                "text": completion_message,
                "parse_mode": "Markdown"
            }
        )
    except:
        # Güncelleme başarısız olursa yeni mesaj gönder
        send_message(admin_id, completion_message)
    
    # İşlem tamamlandı, admin paneline geri dön
    keyboard = create_keyboard([
        [{"text": "⬅️ Admin Paneli", "callback_data": "admin_panel"}]
    ])
    send_message(
        admin_id,
        "📊 *Duyuru istatistikleri yukarıda gösterilmiştir.*\n"
        "Admin paneline dönmek için aşağıdaki butonu kullanabilirsiniz.",
        keyboard
    )

if __name__ == "__main__":
    main()