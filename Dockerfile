# Python 3.10 imajı kullanıyoruz
FROM python:3.10.5

# Çalışma dizinini belirliyoruz
WORKDIR /app

# Gereksinimleri kopyalıyoruz
COPY requirements.txt /app/

# Bağımlılıkları yüklüyoruz
RUN pip install --no-cache-dir -r requirements.txt

# Oracle instantclient yükleme (cx_Oracle için gerekli)
RUN apt-get update && apt-get install -y libaio1 wget unzip \
    && wget https://download.oracle.com/otn_software/linux/instantclient/instantclient-basiclite-linuxx64.zip \
    && unzip instantclient-basiclite-linuxx64.zip \
    && rm -f instantclient-basiclite-linuxx64.zip \
    && cd /instantclient* \
    && mkdir -p /opt/oracle \
    && mv /instantclient* /opt/oracle/ \
    && echo /opt/oracle/instantclient* > /etc/ld.so.conf.d/oracle-instantclient.conf \
    && ldconfig

# Proje dosyalarını kopyalıyoruz
COPY . /app/

# Ortam değişkenleri için .env dosyasını oluştur (boş, dışarıdan mount edilecek)
RUN touch .env

# Flask uygulamanızı başlatmak için gerekli komut
CMD ["python", "app.py"]

# API'nin çalışacağı portu belirliyoruz
EXPOSE 5004