# Python 3.10 imajı kullanıyoruz
FROM python:3.10.5

# Çalışma dizinini belirliyoruz
WORKDIR /app

# Gereksinimleri kopyalıyoruz
COPY requirements.txt /app/

# Bağımlılıkları yüklüyoruz
RUN pip install --no-cache-dir -r requirements.txt

# Proje dosyalarını kopyalıyoruz
COPY . /app/

# Flask uygulamanızı başlatmak için gerekli komut
CMD ["python", "app.py"]

# API'nin çalışacağı portu belirliyoruz
EXPOSE 5004
