# Çok Fonksiyonlu Telegram Botu

Bu bot, çeşitli AI servisleri ve API'ları kullanarak aşağıdaki özellikleri sunar:

- 🎨 Resim Oluşturma (Flux ve Turbo modelleri)
- 💬 AI Sohbet (GPT-4, Gemini-Flash, Mistral)
- 🎵 Müzik Tanıma

## Kurulum

1. Gerekli paketleri yükleyin:
```bash
pip install -r requirements.txt
```

2. `.env` dosyasını düzenleyin:
- `TELEGRAM_TOKEN`: Telegram Bot Token'ınızı @BotFather'dan alıp buraya ekleyin

3. Botu çalıştırın:
```bash
python bot.py
```

## Kullanım

1. Telegram'da botu başlatmak için `/start` komutunu kullanın
2. Menüden istediğiniz hizmeti seçin:
   - Resim oluşturmak için "🎨 Resim Oluştur"
   - AI ile sohbet etmek için "💬 Sohbet Et"
   - Müzik tanımak için bir ses dosyası gönderin

## Özellikler

### Resim Oluşturma
- Flux: Standart resim oluşturma
- Turbo: Özelleştirilebilir boyutlarla resim oluşturma

### AI Sohbet
- GPT-4: Gelişmiş dil anlama
- Gemini-Flash: Google'ın AI modeli
- Mistral: Teknik sorular için optimize edilmiş model

### Müzik Tanıma
- Ses dosyası veya ses kaydı göndererek şarkı bilgilerini alın
- Shazam veritabanı üzerinden tanıma 