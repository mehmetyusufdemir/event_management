from flask import Flask, request, Response, jsonify
from spyne import Application, rpc, ServiceBase, Unicode, Integer, Float, Boolean, Array
from spyne.protocol.soap import Soap11
from spyne.server.wsgi import WsgiApplication
import cx_Oracle
import jwt
import datetime
import bcrypt
import os
from functools import wraps
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS

# Flask uygulamasını başlatıyoruz
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'my_super_secret_key_123456')  # .env dosyasından alınabilir

CORS(app)
# Kara liste (blacklist) ve kullanım sayısı için sözlükler
token_blacklist = set()
token_usage = {}
MAX_TOKEN_USAGE = 5  # Bir token'ın maksimum kullanım sayısı

# Rate limiter ekliyoruz - istemci IP adresine göre limitleme
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["5 per hour"],  # Varsayılan olarak saatte 5 istek
    storage_uri="memory://",  # Bellek tabanlı depolama (production için Redis önerilir)
)

# Oracle DB bağlantısı için bilgiler
DB_USER = "system"
DB_PASSWORD = "oracle123"
DB_HOST = "localhost"
DB_PORT = 1521
DB_SID = "ORCLPDB1"


class DatabaseHandler:
    @staticmethod
    def get_db_connection():
        try:
            dsn = cx_Oracle.makedsn(DB_HOST, DB_PORT, service_name=DB_SID)
            connection = cx_Oracle.connect(
                user=DB_USER,
                password=DB_PASSWORD,
                dsn=dsn,
                encoding="UTF-8"
            )
            print("Database connection successful")  # Bağlantı başarılı mı kontrol
            return connection
        except cx_Oracle.DatabaseError as e:
            error, = e.args
            print("Database Connection Error:", error)
            return None
        except Exception as e:
            print("General Connection Error:", str(e))
            return None


class JWTHandler:
    @staticmethod
    def encode_jwt(user_id, role, email, username, ip_address):
        expiration_time = datetime.datetime.utcnow() + datetime.timedelta(hours=1)

        token = jwt.encode({
            'user_id': user_id,
            'role': role,
            'email': email,
            'username': username,
            'ip_address': ip_address,
            'exp': expiration_time
        }, app.config['SECRET_KEY'], algorithm='HS256')

        return token

    @staticmethod
    def token_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            token = None

            # Token'ı header'dan al
            if 'Authorization' in request.headers:
                auth_header = request.headers['Authorization']
                if auth_header.startswith('Bearer '):
                    token = auth_header.split(' ')[1]

            if not token:
                return jsonify({'message': 'Token is missing!'}), 403

            # Kara liste kontrolü
            if token in token_blacklist:
                return jsonify({'message': 'Token is invalid or has been used!'}), 401

            # Token kullanım sayısını kontrol et
            if token in token_usage:
                if token_usage[token] >= MAX_TOKEN_USAGE:
                    token_blacklist.add(token)
                    return jsonify({'message': 'Token has exceeded its maximum usage limit!'}), 401
            else:
                token_usage[token] = 0  # İlk kez kullanılıyorsa sayaç başlat

            try:
                # Token'ı decode et
                data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
                current_user_id = data['user_id']
                current_user_role = data['role']
            except jwt.ExpiredSignatureError:
                return jsonify({'message': 'Token has expired!'}), 401
            except jwt.InvalidTokenError:
                return jsonify({'message': 'Invalid token!'}), 401

            # Token kullanım sayısını artır
            token_usage[token] += 1

            # Eğer kullanım sayısı maksimuma ulaştıysa kara listeye ekle
            if token_usage[token] >= MAX_TOKEN_USAGE:
                token_blacklist.add(token)

            return f(current_user_id, current_user_role, *args, **kwargs)

        return decorated_function


class UserHandler(DatabaseHandler, JWTHandler):
    @staticmethod
    def register():
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        connection = DatabaseHandler.get_db_connection()
        if connection is None:
            return jsonify({'message': 'Database connection error'}), 500

        cursor = connection.cursor()

        try:
            # Kullanıcı adı veya e-posta zaten var mı kontrol et
            cursor.execute("""
                SELECT COUNT(*)
                FROM EVENT_MANAGEMENT.Users
                WHERE username = :username OR email = :email
            """, {'username': username, 'email': email})

            count = cursor.fetchone()[0]

            if count > 0:
                return jsonify({'message': 'Username or email already exists'}), 409

            # Kullanıcıyı ekle
            cursor.execute("""
                INSERT INTO EVENT_MANAGEMENT.Users (username, email, password_hash)
                VALUES (:username, :email, :password)
            """, {'username': username, 'email': email, 'password': hashed_password})

            connection.commit()

            return jsonify({'message': 'User registered successfully!'}), 201

        except cx_Oracle.DatabaseError as e:
            return jsonify({'message': 'Database error', 'error': str(e)}), 500

        finally:
            cursor.close()
            connection.close()

    @staticmethod
    def login():
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        connection = DatabaseHandler.get_db_connection()
        if connection is None:
            return jsonify({'message': 'Database connection error'}), 500

        cursor = connection.cursor()
        try:
            # Kullanıcı bilgilerini ve rolünü çek
            cursor.execute("""
                SELECT u.user_id, u.password_hash, r.role_name, u.email, u.username
                FROM EVENT_MANAGEMENT.Users u
                JOIN EVENT_MANAGEMENT.User_Roles ur ON u.user_id = ur.user_id
                JOIN EVENT_MANAGEMENT.Roles r ON ur.role_id = r.role_id
                WHERE u.username = :username
            """, {'username': username})

            user = cursor.fetchone()

            if user and bcrypt.checkpw(password.encode('utf-8'), user[1].encode('utf-8')):

                # Token oluşturma (kullanıcı bilgileri ve rol de dahil)
                token = JWTHandler.encode_jwt(user[0], user[2], user[3], user[4], request.remote_addr)

                # Kullanıcı bilgilerini döndür
                return jsonify({
                    'token': token,
                    'role': user[2],
                    'username': user[4],
                    'email': user[3]
                })
            else:
                return jsonify({'message': 'Invalid credentials'}), 401

        except cx_Oracle.DatabaseError as e:
            return jsonify({'message': 'Database query error', 'error': str(e)}), 500
        finally:
            cursor.close()
            connection.close()


# Yetkilendirme yardımcı fonksiyonu
def check_permission(role, required_roles):
    return role in required_roles


#####################################################
# SOAP Servisleri Tanımlamaları
#####################################################

# Kullanıcı Servisi (SOAP)
class UserService(ServiceBase):
    @rpc(Unicode, Unicode, Unicode, _returns=Unicode)
    def register(ctx, username, email, password):
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        connection = DatabaseHandler.get_db_connection()
        if connection is None:
            return 'Database connection error'

        cursor = connection.cursor()
        try:
            # Kullanıcı adı veya e-posta zaten var mı kontrol et
            cursor.execute("""
                SELECT COUNT(*)
                FROM EVENT_MANAGEMENT.Users
                WHERE username = :username OR email = :email
            """, {'username': username, 'email': email})

            count = cursor.fetchone()[0]

            if count > 0:
                return 'Username or email already exists'

            # Kullanıcıyı ekle
            cursor.execute("""
                INSERT INTO EVENT_MANAGEMENT.Users (username, email, password_hash)
                VALUES (:username, :email, :password)
            """, {'username': username, 'email': email, 'password': hashed_password})

            connection.commit()
            return 'User registered successfully!'

        except cx_Oracle.DatabaseError as e:
            return f'Database error: {str(e)}'
        finally:
            cursor.close()
            connection.close()

    @rpc(Unicode, Unicode, _returns=Unicode)
    def login(ctx, username, password):
        connection = DatabaseHandler.get_db_connection()
        if connection is None:
            return 'Database connection error'

        cursor = connection.cursor()
        try:
            # Kullanıcı bilgilerini ve rolünü çek
            cursor.execute("""
                SELECT u.user_id, u.password_hash, r.role_name, u.email, u.username
                FROM EVENT_MANAGEMENT.Users u
                JOIN EVENT_MANAGEMENT.User_Roles ur ON u.user_id = ur.user_id
                JOIN EVENT_MANAGEMENT.Roles r ON ur.role_id = r.role_id
                WHERE u.username = :username
            """, {'username': username})

            user = cursor.fetchone()

            if user and bcrypt.checkpw(password.encode('utf-8'), user[1].encode('utf-8')):
                # Token oluşturma (kullanıcı bilgileri ve rol de dahil)
                token = JWTHandler.encode_jwt(user[0], user[2], user[3], user[4], 'SOAP-Request')

                # XML formatında yanıt döndür
                return f"""<?xml version="1.0" encoding="UTF-8"?>
                <LoginResponse>
                    <token>{token}</token>
                    <role>{user[2]}</role>
                    <username>{user[4]}</username>
                    <email>{user[3]}</email>
                </LoginResponse>"""
            else:
                return 'Invalid credentials'

        except cx_Oracle.DatabaseError as e:
            return f'Database query error: {str(e)}'
        finally:
            cursor.close()
            connection.close()


# Event Servisi (SOAP)
class EventService(ServiceBase):
    @rpc(Unicode, Unicode, Unicode, Unicode, Unicode, Integer, Float, _returns=Unicode)
    def create_event(ctx, token, name, description, date_time, location, capacity, price):
        try:
            # Token doğrulama
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user_id = data['user_id']
            current_user_role = data['role']

            # Yetki kontrolü
            if current_user_role not in ['Admin', 'Organizer']:
                return 'Unauthorized'

            connection = DatabaseHandler.get_db_connection()
            cursor = connection.cursor()

            # event_id için bir değişken oluştur
            event_id_var = cursor.var(cx_Oracle.NUMBER)

            cursor.execute("""
                INSERT INTO EVENT_MANAGEMENT.Events 
                (name, description, date_time, location, capacity, price, created_by)
                VALUES (:name, :description, TO_TIMESTAMP(:date_time, 'YYYY-MM-DD HH24:MI:SS'), 
                        :location, :capacity, :price, :created_by)
                RETURNING event_id INTO :event_id
            """, {
                'name': name,
                'description': description,
                'date_time': date_time,
                'location': location,
                'capacity': capacity,
                'price': price,
                'created_by': current_user_id,
                'event_id': event_id_var
            })

            # event_id değerini al
            event_id = event_id_var.getvalue()[0]
            connection.commit()

            return f"""
            <EventResponse>
                <message>Event created successfully</message>
                <event_id>{event_id}</event_id>
            </EventResponse>
            """

        except jwt.ExpiredSignatureError:
            return 'Token has expired!'
        except jwt.InvalidTokenError:
            return 'Invalid token!'
        except cx_Oracle.DatabaseError as e:
            return f'Database error: {str(e)}'
        finally:
            if 'cursor' in locals():
                cursor.close()
            if 'connection' in locals():
                connection.close()


# Ticket Servisi (SOAP)
class TicketService(ServiceBase):
    @rpc(Unicode, Integer, _returns=Unicode)
    def purchase_ticket(ctx, token, event_id):
        try:
            # Token doğrulama
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user_id = data['user_id']
            current_user_role = data['role']

            # Yetki kontrolü
            if current_user_role not in ['User', 'Admin']:
                return 'Unauthorized'

            connection = DatabaseHandler.get_db_connection()
            cursor = connection.cursor()

            # Event kontrolü
            cursor.execute("""
                SELECT price, capacity, 
                       (SELECT COUNT(*) FROM EVENT_MANAGEMENT.Tickets WHERE event_id = :event_id) as sold_tickets
                FROM EVENT_MANAGEMENT.Events 
                WHERE event_id = :event_id
            """, {'event_id': event_id})

            event_data = cursor.fetchone()
            if not event_data:
                return 'Event not found'

            price, capacity, sold_tickets = event_data

            if sold_tickets >= capacity:
                return 'Event is sold out'

            # Bilet oluştur
            ticket_id_var = cursor.var(cx_Oracle.NUMBER)
            cursor.execute("""
                BEGIN
                    INSERT INTO EVENT_MANAGEMENT.Tickets (event_id, user_id, status)
                    VALUES (:event_id, :user_id, 'Active')
                    RETURNING ticket_id INTO :ticket_id;
                END;
            """, {
                'event_id': event_id,
                'user_id': current_user_id,
                'ticket_id': ticket_id_var
            })

            ticket_id = ticket_id_var.getvalue()

            # Ödeme oluştur
            cursor.execute("""
                INSERT INTO EVENT_MANAGEMENT.Payments (user_id, ticket_id, amount, payment_status)
                VALUES (:user_id, :ticket_id, :amount, 'Pending')
            """, {
                'user_id': current_user_id,
                'ticket_id': ticket_id,
                'amount': price
            })

            connection.commit()

            return f"""
            <TicketResponse>
                <message>Ticket purchased successfully</message>
                <ticket_id>{ticket_id}</ticket_id>
                <amount>{float(price)}</amount>
            </TicketResponse>
            """

        except jwt.ExpiredSignatureError:
            return 'Token has expired!'
        except jwt.InvalidTokenError:
            return 'Invalid token!'
        except cx_Oracle.DatabaseError as e:
            return f'Database error: {str(e)}'
        finally:
            if 'cursor' in locals():
                cursor.close()
            if 'connection' in locals():
                connection.close()


# SOAP servislerini oluştur
soap_app = Application([UserService, EventService, TicketService],
                       tns='http://event.management.service',
                       in_protocol=Soap11(validator='lxml'),
                       out_protocol=Soap11())

# Flask ile SOAP servisini entegre et
wsgi_app = WsgiApplication(soap_app)

# Kullanıcı kaydı için endpoint
@app.route('/register', methods=['POST'])
@limiter.limit("5 per hour")
def register():
    return UserHandler.register()

# Kullanıcı giriş işlemi (Şifreyi Hash ile Karşılaştırarak)
@app.route('/login', methods=['POST'])
@limiter.limit("5 per hour")
def login():
    return UserHandler.login()

# Ana sayfa
@app.route('/')
def home():
    return "Flask API is running!"

@app.route('/profile', methods=['GET'])
@JWTHandler.token_required
@limiter.limit("5 per hour")
def profile(current_user_id, current_user_role):
    # Eğer rol admin ise, diğer kullanıcıların bilgilerini de görebilir
    if current_user_role == 'admin':
        return jsonify({
            'user_id': current_user_id,
            'role': current_user_role,
            'message': 'You have admin access!'
        })
    else:
        return jsonify({
            'user_id': current_user_id,
            'role': current_user_role,
            'message': 'You have user access!'
        })

@app.route('/user_data', methods=['GET'])
@JWTHandler.token_required
@limiter.limit("5 per hour")
def user_data(current_user_id, current_user_role):
    connection = DatabaseHandler.get_db_connection()
    cursor = connection.cursor()

    try:
        # Token'dan gelen user_id'yi kullanarak veritabanından veri alıyoruz
        cursor.execute("""
            SELECT username, email, role
            FROM EVENT_MANAGEMENT.Users u
            JOIN EVENT_MANAGEMENT.User_Roles ur ON u.user_id = ur.user_id
            JOIN EVENT_MANAGEMENT.Roles r ON ur.role_id = r.role_id
            WHERE u.user_id = :user_id
        """, {'user_id': current_user_id})

        user_data = cursor.fetchone()

        if user_data:
            return jsonify({
                'user_id': current_user_id,
                'username': user_data[0],
                'email': user_data[1],
                'role': user_data[2]
            })
        else:
            return jsonify({'message': 'User not found'}), 404

    except cx_Oracle.DatabaseError as e:
        return jsonify({'message': 'Database error', 'error': str(e)}), 500

    finally:
        cursor.close()
        connection.close()

@app.route('/validate_token', methods=['GET'])
@JWTHandler.token_required
@limiter.limit("5 per hour")
def validate_token(current_user_id, current_user_role):
    return jsonify({
        'message': 'Token is valid!',
        'user_id': current_user_id,
        'role': current_user_role
    })

# Yetkilendirme yardımcı fonksiyonu
def check_permission(role, required_roles):
    return role in required_roles

#event güncelleme
@app.route('/events/<int:event_id>', methods=['PUT'])
@JWTHandler.token_required
@limiter.limit("5 per hour")
def update_event(current_user_id, current_user_role, event_id):
    if not check_permission(current_user_role, ['Admin', 'Organizer']):
        return jsonify({'message': 'Unauthorized access'}), 403

    data = request.get_json()
    connection = DatabaseHandler.get_db_connection()
    cursor = connection.cursor()

    try:
        if current_user_role == 'Organizer':
            cursor.execute("""
                SELECT created_by 
                FROM EVENT_MANAGEMENT.Events 
                WHERE event_id = :event_id
            """, {'event_id': event_id})

            event_owner = cursor.fetchone()
            if not event_owner or event_owner[0] != current_user_id:
                return jsonify({'message': 'You can only update your own events'}), 403

        cursor.execute("""
            UPDATE EVENT_MANAGEMENT.Events 
            SET name = :name,
                description = :description,
                date_time = TO_TIMESTAMP(:date_time, 'YYYY-MM-DD HH24:MI:SS'),
                location = :location,
                capacity = :capacity,
                price = :price
            WHERE event_id = :event_id
        """, {
            'name': data['name'],
            'description': data['description'],
            'date_time': data['date_time'],
            'location': data['location'],
            'capacity': data['capacity'],
            'price': data['price'],
            'event_id': event_id
        })

        connection.commit()


        return jsonify({'message': 'Event updated successfully'})

    except cx_Oracle.DatabaseError as e:
        return jsonify({'message': 'Database error', 'error': str(e)}), 500
    finally:
        cursor.close()
        connection.close()

#event silme
@app.route('/events/<int:event_id>', methods=['DELETE'])
@JWTHandler.token_required
@limiter.limit("5 per hour")
def delete_event(current_user_id, current_user_role, event_id):
    if not check_permission(current_user_role, ['Admin', 'Organizer']):
        return jsonify({'message': 'Unauthorized access'}), 403

    connection = DatabaseHandler.get_db_connection()
    cursor = connection.cursor()

    try:
        # Organizer rolü için ek kontrol
        if current_user_role == 'Organizer':
            cursor.execute("""
                SELECT created_by 
                FROM EVENT_MANAGEMENT.Events 
                WHERE event_id = :event_id
            """, {'event_id': event_id})

            event_owner = cursor.fetchone()
            if not event_owner or event_owner[0] != current_user_id:
                return jsonify({'message': 'You can only delete your own events'}), 403

        cursor.execute("""
            DELETE FROM EVENT_MANAGEMENT.Events 
            WHERE event_id = :event_id
        """, {'event_id': event_id})

        connection.commit()



        return jsonify({'message': 'Event deleted successfully'})

    except cx_Oracle.DatabaseError as e:
        return jsonify({'message': 'Database error', 'error': str(e)}), 500
    finally:
        cursor.close()
        connection.close()

# Tüm etkinlikleri görüntüleme endpoint'i
@app.route('/events', methods=['GET'])
@JWTHandler.token_required
@limiter.limit("5 per hour")
def get_events(current_user_id, current_user_role):
    connection = None
    cursor = None
    try:
        connection = DatabaseHandler.get_db_connection()
        if connection is None:
            return jsonify({'message': 'Database connection failed'}), 500

        cursor = connection.cursor()

        # Role göre farklı sorgular
        if current_user_role.lower() == 'admin':
            # Admin tüm etkinlikleri görebilir
            query = """
                SELECT e.event_id, e.name, e.description, e.date_time, 
                       e.location, e.capacity, e.price, e.created_by, 
                       e.created_at, u.username as creator_name,
                       (SELECT COUNT(*) FROM EVENT_MANAGEMENT.Tickets t WHERE t.event_id = e.event_id) as ticket_count
                FROM EVENT_MANAGEMENT.Events e
                JOIN EVENT_MANAGEMENT.Users u ON e.created_by = u.user_id
                ORDER BY e.date_time DESC
            """
            cursor.execute(query)

        elif current_user_role.lower() == 'organizer':
            # Organizer sadece kendi etkinliklerini görebilir
            query = """
                SELECT e.event_id, e.name, e.description, e.date_time, 
                       e.location, e.capacity, e.price, e.created_by, 
                       e.created_at, u.username as creator_name,
                       (SELECT COUNT(*) FROM EVENT_MANAGEMENT.Tickets t WHERE t.event_id = e.event_id) as ticket_count
                FROM EVENT_MANAGEMENT.Events e
                JOIN EVENT_MANAGEMENT.Users u ON e.created_by = u.user_id
                WHERE e.created_by = :user_id
                ORDER BY e.date_time DESC
            """
            cursor.execute(query, {'user_id': current_user_id})

        elif current_user_role.lower() == 'user':
            # Kullanıcının bilet aldığı etkinlikleri görüntüle
            query = """
                SELECT e.event_id, e.name, e.description, e.date_time, 
                       e.location, e.capacity, e.price, e.created_by, 
                       e.created_at, u.username as creator_name,
                       'purchased' as ticket_status,
                       (SELECT COUNT(*) FROM EVENT_MANAGEMENT.Tickets t WHERE t.event_id = e.event_id) as sold_tickets
                FROM EVENT_MANAGEMENT.Events e
                JOIN EVENT_MANAGEMENT.Users u ON e.created_by = u.user_id
                JOIN EVENT_MANAGEMENT.Tickets t ON e.event_id = t.event_id
                WHERE t.user_id = :user_id
                ORDER BY e.date_time ASC
            """
            cursor.execute(query, {'user_id': current_user_id})

        events = []
        for row in cursor.fetchall():
            # LOB nesnesini string'e dönüştür
            description = row[2].read() if isinstance(row[2], cx_Oracle.LOB) else row[2]

            event = {
                'event_id': row[0],
                'name': row[1],
                'description': description,
                'date_time': row[3].strftime("%Y-%m-%d %H:%M:%S") if row[3] else None,
                'location': row[4],
                'capacity': row[5],
                'price': float(row[6]) if row[6] else 0,
                'created_by': row[7],
                'created_at': row[8].strftime("%Y-%m-%d %H:%M:%S") if row[8] else None,
                'creator_name': row[9]
            }

            # Role'e göre ek bilgiler ekle
            if current_user_role.lower() == 'admin':
                event['ticket_count'] = row[10]
            elif current_user_role.lower() == 'organizer':
                event['ticket_count'] = row[10]
            else:  # User role
                event['ticket_status'] = row[10]
                event['available_tickets'] = row[5] - row[11] if row[5] else 0
                # Hassas bilgileri kaldır
                event.pop('created_by', None)
                event.pop('created_at', None)

            events.append(event)



        return jsonify(events), 200

    except cx_Oracle.DatabaseError as e:
        error, = e.args
        print("Database Error:", error)
        return jsonify({
            'message': 'Database error',
            'error': str(error.message)
        }), 500
    except Exception as e:
        print("General Error:", str(e))
        return jsonify({
            'message': 'An error occurred',
            'error': str(e)
        }), 500
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

# Yeni etkinlik oluşturma endpoint'i
@app.route('/events', methods=['POST'])
@JWTHandler.token_required
@limiter.limit("5 per hour")
def create_event(current_user_id, current_user_role):
    if not check_permission(current_user_role, ['Admin', 'Organizer']):
        return jsonify({'message': 'Unauthorized'}), 403

    data = request.get_json()
    connection = DatabaseHandler.get_db_connection()
    cursor = connection.cursor()

    try:
        # event_id için bir değişken oluştur
        event_id_var = cursor.var(cx_Oracle.NUMBER)

        cursor.execute("""
            INSERT INTO EVENT_MANAGEMENT.Events 
            (name, description, date_time, location, capacity, price, created_by)
            VALUES (:name, :description, TO_TIMESTAMP(:date_time, 'YYYY-MM-DD HH24:MI:SS'), 
                    :location, :capacity, :price, :created_by)
            RETURNING event_id INTO :event_id
        """, {
            'name': data['name'],
            'description': data['description'],
            'date_time': data['date_time'],
            'location': data['location'],
            'capacity': data['capacity'],
            'price': data['price'],
            'created_by': current_user_id,
            'event_id': event_id_var
        })

        # event_id değerini al
        event_id = event_id_var.getvalue()[0]
        connection.commit()




        return jsonify({'message': 'Event created successfully', 'event_id': event_id}), 201

    except cx_Oracle.DatabaseError as e:
        return jsonify({'message': 'Database error', 'error': str(e)}), 500
    finally:
        cursor.close()
        connection.close()

# Bilet satın alma endpoint'i
@app.route('/tickets/purchase', methods=['POST'])
@JWTHandler.token_required
@limiter.limit("5 per hour")
def purchase_ticket(current_user_id, current_user_role):
    if not check_permission(current_user_role, ['User', 'Admin']):
        return jsonify({'message': 'Unauthorized'}), 403

    data = request.get_json()
    event_id = data.get('event_id')

    connection = DatabaseHandler.get_db_connection()
    cursor = connection.cursor()

    try:
        # Event kontrolü
        cursor.execute("""
            SELECT price, capacity, 
                   (SELECT COUNT(*) FROM EVENT_MANAGEMENT.Tickets WHERE event_id = :event_id) as sold_tickets
            FROM EVENT_MANAGEMENT.Events 
            WHERE event_id = :event_id
        """, {'event_id': event_id})

        event_data = cursor.fetchone()
        if not event_data:
            return jsonify({'message': 'Event not found'}), 404

        price, capacity, sold_tickets = event_data

        if sold_tickets >= capacity:
            return jsonify({'message': 'Event is sold out'}), 400

        # Bilet oluştur - PL/SQL bloğu kullanarak
        ticket_id_var = cursor.var(cx_Oracle.NUMBER)
        cursor.execute("""
            BEGIN
                INSERT INTO EVENT_MANAGEMENT.Tickets (event_id, user_id, status)
                VALUES (:event_id, :user_id, 'Active')
                RETURNING ticket_id INTO :ticket_id;
            END;
        """, {
            'event_id': event_id,
            'user_id': current_user_id,
            'ticket_id': ticket_id_var
        })

        ticket_id = ticket_id_var.getvalue()

        # Ödeme oluştur
        cursor.execute("""
            INSERT INTO EVENT_MANAGEMENT.Payments (user_id, ticket_id, amount, payment_status)
            VALUES (:user_id, :ticket_id, :amount, 'Pending')
        """, {
            'user_id': current_user_id,
            'ticket_id': ticket_id,
            'amount': price
        })

        connection.commit()



        return jsonify({
            'message': 'Ticket purchased successfully',
            'ticket_id': ticket_id,
            'amount': float(price)
        }), 201

    except cx_Oracle.DatabaseError as e:
        return jsonify({'message': 'Database error', 'error': str(e)}), 500
    finally:
        cursor.close()
        connection.close()

# SOAP WSDL endpoint'i için route
@app.route('/soap', methods=['POST', 'GET'])
def soap_service():
    return wsgi_app

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5004)