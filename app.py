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
from langchain_openai import OpenAI, OpenAIEmbeddings
from langchain.chains import RetrievalQA
from langchain_community.document_loaders import TextLoader
from langchain.indexes import VectorstoreIndexCreator
from langchain.text_splitter import CharacterTextSplitter
from langchain_community.vectorstores import FAISS
import requests
import json
from langchain_community.vectorstores import Chroma
import logging
from langchain.llms import OpenAI
from langchain.prompts import PromptTemplate

# Flask uygulamasını başlatıyoruz
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'my_super_secret_key_123456')  # .env dosyasından alınabilir
#loglama ayarları
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

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
DB_USER = "EVENT_MANAGEMENT"
DB_PASSWORD = "oracle123"
DB_HOST = "localhost"
DB_PORT = 1521
DB_SID = "ORCLPDB1"


class DatabaseHandler:
    @staticmethod
    def get_db_connection():
        try:
            # Veritabanı bağlantısı oluştur
            dsn = cx_Oracle.makedsn(DB_HOST, DB_PORT, service_name=DB_SID)
            connection = cx_Oracle.connect(
                user=DB_USER,
                password=DB_PASSWORD,
                dsn=dsn,
                encoding="UTF-8"
            )

            # Başarılı bağlantı logu
            logger.info("Database connection successful.")
            return connection

        except cx_Oracle.DatabaseError as e:
            # Oracle veritabanı hatası logu
            error, = e.args
            logger.error(f"Database Connection Error: {error}", exc_info=True)
            return None

        except Exception as e:
            # Genel hata logu
            logger.error(f"General Connection Error: {str(e)}", exc_info=True)
            return None
def get_database_schema():
    """Veritabanındaki tüm tabloların ve sütunların bilgisini çeker."""
    connection = DatabaseHandler.get_db_connection()
    cursor = connection.cursor()

    schema_info = {}

    cursor.execute("""
        SELECT table_name 
        FROM ALL_TABLES 
        WHERE owner = 'EVENT_MANAGEMENT'
    """)

    tables = cursor.fetchall()
    print("Veritabanındaki Tablolar:", tables)

    cursor.execute("""
        SELECT table_name, column_name, data_type 
        FROM ALL_TAB_COLUMNS 
        WHERE owner = 'EVENT_MANAGEMENT'
    """)

    for table_name, column_name, data_type in cursor.fetchall():
        if table_name not in schema_info:
            schema_info[table_name] = []
        schema_info[table_name].append({"column": column_name, "type": data_type})

    return schema_info


def clean_sql_query(sql_query):
    """SQL sorgusunu temizler ve Oracle için uygun hale getirir."""
    # SQL sorgusu birden çok satır içerebilir, boşlukları düzenle
    sql_query = sql_query.strip()

    # Sorgu sonundaki noktalı virgülü kaldır
    if sql_query.endswith(';'):
        sql_query = sql_query[:-1]

    # Kod blokları içindeyse (``` veya benzeri) temizle
    if sql_query.startswith('```') and sql_query.endswith('```'):
        sql_query = sql_query[3:-3].strip()
    elif sql_query.startswith('```sql') and sql_query.endswith('```'):
        sql_query = sql_query[6:-3].strip()

    return sql_query

class LangChainHandler:
    def __init__(self):
        load_dotenv()
        self.api_key = os.getenv("OPENAI_API_KEY")
        os.environ["OPENAI_API_KEY"] = self.api_key

        self.llm = OpenAI(temperature=0.7)
        self.schema_info = get_database_schema()

        # Şema bilgisini logla
        logger.debug(f"Database schema info: {self.schema_info}")

    def generate_sql_query(self, user_question):
        """Kullanıcının doğal dildeki sorusuna göre SQL sorgusu üretir."""
        schema_description = "\n".join([
            f"{table}: {', '.join([col['column'] for col in cols])}"
            for table, cols in self.schema_info.items()
        ])

        prompt = PromptTemplate(
            input_variables=["schema", "question"],
            template="""
            Aşağıdaki veritabanı şeması ile çalışıyorsun:
            {schema}

            Kullanıcının sorusu:
            {question}

            Bu soruya uygun Oracle SQL sorgusunu oluştur. Sadece sorgu kodunu döndür.
            Şu kurallara dikkat et:
            1. Sorgu sonunda noktalı virgül (;) KULLANMA.
            2. Oracle SQL sözdizimi kurallarına harfiyen uy.
            3. Oracle'ın desteklediği fonksiyonları kullan.
            4. Alıntıları doğru şekilde kullan (tek tırnak).
            5. Sorguda sadece şemada belirtilen tabloları ve sütunları kullan.

            SQL sorgusu:
            """
        )

        # SQL sorgusu üretme
        sql_query = self.llm(prompt.format(schema=schema_description, question=user_question))

        # Temizleme ve düzeltme işlemleri - sınıf dışı fonksiyonu çağır
        sql_query = clean_sql_query(sql_query)

        return sql_query

class JWTHandler:
    @staticmethod
    def encode_jwt(user_id, role, email, username, ip_address):
        logger.debug(f"Encoding JWT for user_id: {user_id}, role: {role}, username: {username}, ip: {ip_address}")
        expiration_time = datetime.datetime.utcnow() + datetime.timedelta(hours=1)

        token = jwt.encode({
            'user_id': user_id,
            'role': role,
            'email': email,
            'username': username,
            'ip_address': ip_address,
            'exp': expiration_time
        }, app.config['SECRET_KEY'], algorithm='HS256')

        logger.info(f"JWT token created for user {username} with expiration time {expiration_time}")
        return token

    @staticmethod
    def token_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):


            logger.debug("Validating JWT token")
            token = None

            # Token'ı header'dan al
            if 'Authorization' in request.headers:
                auth_header = request.headers['Authorization']
                if auth_header.startswith('Bearer '):
                    token = auth_header.split(' ')[1]
                    logger.debug("Bearer token extracted from Authorization header")

            if not token:
                logger.warning("Request missing token in Authorization header")
                return jsonify({'message': 'Token is missing!'}), 403

            # Kara liste kontrolü
            if token in token_blacklist:
                logger.warning(f"Token is blacklisted: {token[:15]}...")
                return jsonify({'message': 'Token is invalid or has been used!'}), 401

            # Token kullanım sayısını kontrol et
            if token in token_usage:
                logger.debug(f"Token usage count: {token_usage[token]}")
                if token_usage[token] >= MAX_TOKEN_USAGE:
                    logger.warning(f"Token usage limit exceeded: {token[:15]}...")
                    token_blacklist.add(token)
                    return jsonify({'message': 'Token has exceeded its maximum usage limit!'}), 401
            else:
                logger.debug("First time token usage, initializing counter")
                token_usage[token] = 0  # İlk kez kullanılıyorsa sayaç başlat

            try:
                # Token'ı decode et
                logger.debug("Attempting to decode token")
                data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
                current_user_id = data['user_id']
                current_user_role = data['role']
                logger.info(f"Token successfully decoded for user_id: {current_user_id}, role: {current_user_role}")
            except jwt.ExpiredSignatureError:
                logger.warning("Token has expired")
                return jsonify({'message': 'Token has expired!'}), 401
            except jwt.InvalidTokenError:
                logger.warning("Invalid token")
                return jsonify({'message': 'Invalid token!'}), 401

            # Token kullanım sayısını artır
            token_usage[token] += 1
            logger.debug(f"Incremented token usage to {token_usage[token]}")

            # Eğer kullanım sayısı maksimuma ulaştıysa kara listeye ekle
            if token_usage[token] >= MAX_TOKEN_USAGE:
                logger.warning(f"Token reached max usage, adding to blacklist: {token[:15]}...")
                token_blacklist.add(token)

            return f(current_user_id, current_user_role, *args, **kwargs)

        return decorated_function

class UserHandler(DatabaseHandler, JWTHandler):
    @staticmethod
    def register():
        logger.info("Processing user registration request")
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        logger.debug(f"Registration attempt for username: {username}, email: {email}")

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        logger.debug("Password hashed successfully")

        connection = DatabaseHandler.get_db_connection()
        if connection is None:
            logger.error("Database connection failed during user registration")
            return jsonify({'message': 'Database connection error'}), 500

        cursor = connection.cursor()

        try:
            # Kullanıcı adı veya e-posta zaten var mı kontrol et
            logger.debug("Checking if username or email already exists")
            cursor.execute("""
                SELECT COUNT(*)
                FROM EVENT_MANAGEMENT.Users
                WHERE username = :username OR email = :email
            """, {'username': username, 'email': email})

            count = cursor.fetchone()[0]

            if count > 0:
                logger.warning(f"Registration failed - username or email already exists: {username}, {email}")
                return jsonify({'message': 'Username or email already exists'}), 409

            # Kullanıcıyı ekle
            logger.debug("Inserting new user into database")
            cursor.execute("""
                INSERT INTO EVENT_MANAGEMENT.Users (username, email, password_hash)
                VALUES (:username, :email, :password)
            """, {'username': username, 'email': email, 'password': hashed_password})

            connection.commit()
            logger.info(f"User registered successfully: {username}")

            return jsonify({'message': 'User registered successfully!'}), 201

        except cx_Oracle.DatabaseError as e:
            logger.error(f"Database error during user registration: {str(e)}")
            return jsonify({'message': 'Database error', 'error': str(e)}), 500

        finally:
            logger.debug("Closing database cursor and connection")
            cursor.close()
            connection.close()

    @staticmethod
    def login():
        logger.info("Processing user login request")
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        logger.debug(f"Login attempt for username: {username}")

        connection = DatabaseHandler.get_db_connection()
        if connection is None:
            logger.error("Database connection failed during user login")
            return jsonify({'message': 'Database connection error'}), 500

        cursor = connection.cursor()
        try:
            # Kullanıcı bilgilerini ve rolünü çek
            logger.debug("Querying user information and role")
            cursor.execute("""
                SELECT u.user_id, u.password_hash, r.role_name, u.email, u.username
                FROM EVENT_MANAGEMENT.Users u
                JOIN EVENT_MANAGEMENT.User_Roles ur ON u.user_id = ur.user_id
                JOIN EVENT_MANAGEMENT.Roles r ON ur.role_id = r.role_id
                WHERE u.username = :username
            """, {'username': username})

            user = cursor.fetchone()

            if user:
                logger.debug(f"User found, verifying password for username: {username}")
                if bcrypt.checkpw(password.encode('utf-8'), user[1].encode('utf-8')):
                    logger.info(f"User authenticated successfully: {username}")

                    # Token oluşturma (kullanıcı bilgileri ve rol de dahil)
                    logger.debug("Creating JWT token for authenticated user")
                    token = JWTHandler.encode_jwt(user[0], user[2], user[3], user[4], request.remote_addr)

                    # Kullanıcı bilgilerini döndür
                    return jsonify({
                        'token': token,
                        'role': user[2],
                        'username': user[4],
                        'email': user[3]
                    })
                else:
                    logger.warning(f"Invalid password for username: {username}")
                    return jsonify({'message': 'Invalid credentials'}), 401
            else:
                logger.warning(f"Username not found: {username}")
                return jsonify({'message': 'Invalid credentials'}), 401

        except cx_Oracle.DatabaseError as e:
            logger.error(f"Database error during user login: {str(e)}")
            return jsonify({'message': 'Database query error', 'error': str(e)}), 500
        finally:
            logger.debug("Closing database cursor and connection")
            cursor.close()
            connection.close()
# Yetkilendirme yardımcı fonksiyonu
def check_permission(role, required_roles):
    return role in required_roles

# SOAP Servisleri Tanımlamaları
# Kullanıcı Servisi (SOAP)

class UserService(ServiceBase):
    @rpc(Unicode, Unicode, Unicode, _returns=Unicode)
    def register(ctx, username, email, password):
        logger.debug(f"Registering user: {username}, {email}")
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        connection = DatabaseHandler.get_db_connection()
        if connection is None:
            logger.error("Database connection error")
            return 'Database connection error'

        cursor = connection.cursor()
        try:
            logger.debug("Checking if username or email already exists")
            cursor.execute("""
                SELECT COUNT(*)
                FROM EVENT_MANAGEMENT.Users
                WHERE username = :username OR email = :email
            """, {'username': username, 'email': email})

            count = cursor.fetchone()[0]

            if count > 0:
                logger.warning(f"Username or email already exists: {username}, {email}")
                return 'Username or email already exists'

            logger.debug("Inserting new user into database")
            cursor.execute("""
                INSERT INTO EVENT_MANAGEMENT.Users (username, email, password_hash)
                VALUES (:username, :email, :password)
            """, {'username': username, 'email': email, 'password': hashed_password})

            connection.commit()
            logger.info(f"User registered successfully: {username}")
            return 'User registered successfully!'

        except cx_Oracle.DatabaseError as e:
            logger.error(f"Database error: {str(e)}")
            return f'Database error: {str(e)}'
        finally:
            cursor.close()
            connection.close()

    @rpc(Unicode, Unicode, _returns=Unicode)
    def login(ctx, username, password):
        logger.debug(f"Attempting login for user: {username}")
        connection = DatabaseHandler.get_db_connection()
        if connection is None:
            logger.error("Database connection error")
            return 'Database connection error'

        cursor = connection.cursor()
        try:
            logger.debug("Fetching user details from database")
            cursor.execute("""
                SELECT u.user_id, u.password_hash, r.role_name, u.email, u.username
                FROM EVENT_MANAGEMENT.Users u
                JOIN EVENT_MANAGEMENT.User_Roles ur ON u.user_id = ur.user_id
                JOIN EVENT_MANAGEMENT.Roles r ON ur.role_id = r.role_id
                WHERE u.username = :username
            """, {'username': username})

            user = cursor.fetchone()

            if user and bcrypt.checkpw(password.encode('utf-8'), user[1].encode('utf-8')):
                logger.info(f"User logged in successfully: {username}")
                token = JWTHandler.encode_jwt(user[0], user[2], user[3], user[4], 'SOAP-Request')

                return f"""<?xml version="1.0" encoding="UTF-8"?>
                <LoginResponse>
                    <token>{token}</token>
                    <role>{user[2]}</role>
                    <username>{user[4]}</username>
                    <email>{user[3]}</email>
                </LoginResponse>"""
            else:
                logger.warning(f"Invalid credentials for user: {username}")
                return 'Invalid credentials'

        except cx_Oracle.DatabaseError as e:
            logger.error(f"Database query error: {str(e)}")
            return f'Database query error: {str(e)}'
        finally:
            cursor.close()
            connection.close()

class EventService(ServiceBase):
    @rpc(Unicode, Unicode, Unicode, Unicode, Unicode, Integer, Float, _returns=Unicode)
    def create_event(ctx, token, name, description, date_time, location, capacity, price):
        logger.debug(f"Creating event: {name}")
        try:
            logger.debug("Validating token")
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user_id = data['user_id']
            current_user_role = data['role']

            if current_user_role not in ['Admin', 'Organizer']:
                logger.warning(f"Unauthorized access attempt by user: {current_user_id}")
                return 'Unauthorized'

            connection = DatabaseHandler.get_db_connection()
            cursor = connection.cursor()

            event_id_var = cursor.var(cx_Oracle.NUMBER)

            logger.debug("Inserting event into database")
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

            event_id = event_id_var.getvalue()[0]
            connection.commit()
            logger.info(f"Event created successfully: {event_id}")
            return f"""
            <EventResponse>
                <message>Event created successfully</message>
                <event_id>{event_id}</event_id>
            </EventResponse>
            """

        except jwt.ExpiredSignatureError:
            logger.error("Token has expired")
            return 'Token has expired!'
        except jwt.InvalidTokenError:
            logger.error("Invalid token")
            return 'Invalid token!'
        except cx_Oracle.DatabaseError as e:
            logger.error(f"Database error: {str(e)}")
            return f'Database error: {str(e)}'
        finally:
            if 'cursor' in locals():
                cursor.close()
            if 'connection' in locals():
                connection.close()

class TicketService(ServiceBase):
    @rpc(Unicode, Integer, _returns=Unicode)
    def purchase_ticket(ctx, token, event_id):
        logger.debug(f"Purchasing ticket for event: {event_id}")
        try:
            logger.debug("Validating token")
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user_id = data['user_id']
            current_user_role = data['role']

            if current_user_role not in ['User', 'Admin']:
                logger.warning(f"Unauthorized access attempt by user: {current_user_id}")
                return 'Unauthorized'

            connection = DatabaseHandler.get_db_connection()
            cursor = connection.cursor()

            logger.debug("Fetching event details")
            cursor.execute("""
                SELECT price, capacity, 
                       (SELECT COUNT(*) FROM EVENT_MANAGEMENT.Tickets WHERE event_id = :event_id) as sold_tickets
                FROM EVENT_MANAGEMENT.Events 
                WHERE event_id = :event_id
            """, {'event_id': event_id})

            event_data = cursor.fetchone()
            if not event_data:
                logger.error(f"Event not found: {event_id}")
                return 'Event not found'

            price, capacity, sold_tickets = event_data

            if sold_tickets >= capacity:
                logger.warning(f"Event is sold out: {event_id}")
                return 'Event is sold out'

            logger.debug("Creating ticket")
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

            logger.debug("Creating payment")
            cursor.execute("""
                INSERT INTO EVENT_MANAGEMENT.Payments (user_id, ticket_id, amount, payment_status)
                VALUES (:user_id, :ticket_id, :amount, 'Pending')
            """, {
                'user_id': current_user_id,
                'ticket_id': ticket_id,
                'amount': price
            })

            connection.commit()
            logger.info(f"Ticket purchased successfully: {ticket_id}")
            return f"""
            <TicketResponse>
                <message>Ticket purchased successfully</message>
                <ticket_id>{ticket_id}</ticket_id>
                <amount>{float(price)}</amount>
            </TicketResponse>
            """

        except jwt.ExpiredSignatureError:
            logger.error("Token has expired")
            return 'Token has expired!'
        except jwt.InvalidTokenError:
            logger.error("Invalid token")
            return 'Invalid token!'
        except cx_Oracle.DatabaseError as e:
            logger.error(f"Database error: {str(e)}")
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
    logger.debug("Register route called")
    try:
        result = UserHandler.register()
        logger.info("User registration successful")
        return result
    except Exception as e:
        logger.error(f"Error in register route: {str(e)}")
        return jsonify({'message': 'Internal server error'}), 500

@app.route('/login', methods=['POST'])
@limiter.limit("5 per hour")
def login():
    logger.debug("Login route called")
    try:
        result = UserHandler.login()
        logger.info("User login successful")
        return result
    except Exception as e:
        logger.error(f"Error in login route: {str(e)}")
        return jsonify({'message': 'Internal server error'}), 500

@app.route('/')
def home():
    logger.debug("Home route called")
    return "Flask API is running!"

@app.route('/profile', methods=['GET'])
@JWTHandler.token_required
@limiter.limit("5 per hour")
def profile(current_user_id, current_user_role):
    logger.debug(f"Profile route called for user: {current_user_id}")
    try:
        if current_user_role == 'admin':
            logger.info(f"Admin access granted for user: {current_user_id}")
            return jsonify({
                'user_id': current_user_id,
                'role': current_user_role,
                'message': 'You have admin access!'
            })
        else:
            logger.info(f"User access granted for user: {current_user_id}")
            return jsonify({
                'user_id': current_user_id,
                'role': current_user_role,
                'message': 'You have user access!'
            })
    except Exception as e:
        logger.error(f"Error in profile route: {str(e)}")
        return jsonify({'message': 'Internal server error'}), 500

@app.route('/user_data', methods=['GET'])
@JWTHandler.token_required
@limiter.limit("5 per hour")
def user_data(current_user_id, current_user_role):
    logger.debug(f"User data route called for user: {current_user_id}")
    connection = DatabaseHandler.get_db_connection()
    if connection is None:
        logger.error("Database connection error")
        return jsonify({'message': 'Database connection error'}), 500

    cursor = connection.cursor()
    try:
        cursor.execute("""
            SELECT username, email, role
            FROM EVENT_MANAGEMENT.Users u
            JOIN EVENT_MANAGEMENT.User_Roles ur ON u.user_id = ur.user_id
            JOIN EVENT_MANAGEMENT.Roles r ON ur.role_id = r.role_id
            WHERE u.user_id = :user_id
        """, {'user_id': current_user_id})

        user_data = cursor.fetchone()

        if user_data:
            logger.info(f"User data retrieved successfully for user: {current_user_id}")
            return jsonify({
                'user_id': current_user_id,
                'username': user_data[0],
                'email': user_data[1],
                'role': user_data[2]
            })
        else:
            logger.warning(f"User not found: {current_user_id}")
            return jsonify({'message': 'User not found'}), 404

    except cx_Oracle.DatabaseError as e:
        logger.error(f"Database error in user_data route: {str(e)}")
        return jsonify({'message': 'Database error', 'error': str(e)}), 500

    finally:
        cursor.close()
        connection.close()

@app.route('/validate_token', methods=['GET'])
@JWTHandler.token_required
@limiter.limit("5 per hour")
def validate_token(current_user_id, current_user_role):
    logger.debug(f"Validate token route called for user: {current_user_id}")
    try:
        logger.info(f"Token validated successfully for user: {current_user_id}")
        return jsonify({
            'message': 'Token is valid!',
            'user_id': current_user_id,
            'role': current_user_role
        })
    except Exception as e:
        logger.error(f"Error in validate_token route: {str(e)}")
        return jsonify({'message': 'Internal server error'}), 500
# Yetkilendirme yardımcı fonksiyonu

def check_permission(role, required_roles):
    logger.debug(f"Checking permission for role: {role}, required roles: {required_roles}")
    return role in required_roles

# Event güncelleme
@app.route('/events/<int:event_id>', methods=['PUT'])
@JWTHandler.token_required
@limiter.limit("5 per hour")
def update_event(current_user_id, current_user_role, event_id):
    logger.debug(f"Update event route called for event_id: {event_id} by user_id: {current_user_id}")

    # Yetkilendirme kontrolü
    if not check_permission(current_user_role, ['Admin', 'Organizer']):
        logger.warning(f"Unauthorized access attempt by user_id: {current_user_id}")
        return jsonify({'message': 'Unauthorized access'}), 403

    data = request.get_json()
    connection = DatabaseHandler.get_db_connection()
    if connection is None:
        logger.error("Database connection error")
        return jsonify({'message': 'Database connection error'}), 500

    cursor = connection.cursor()
    try:
        if current_user_role == 'Organizer':
            logger.debug("Checking event ownership for Organizer")
            cursor.execute("""
                SELECT created_by 
                FROM EVENT_MANAGEMENT.Events 
                WHERE event_id = :event_id
            """, {'event_id': event_id})

            event_owner = cursor.fetchone()
            if not event_owner or event_owner[0] != current_user_id:
                logger.warning(f"Organizer user_id: {current_user_id} tried to update event_id: {event_id} without ownership")
                return jsonify({'message': 'You can only update your own events'}), 403

        logger.debug(f"Updating event_id: {event_id}")
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
        logger.info(f"Event updated successfully: {event_id}")
        return jsonify({'message': 'Event updated successfully'})

    except cx_Oracle.DatabaseError as e:
        logger.error(f"Database error in update_event route: {str(e)}")
        return jsonify({'message': 'Database error', 'error': str(e)}), 500
    finally:
        cursor.close()
        connection.close()

# Event silme
@app.route('/events/<int:event_id>', methods=['DELETE'])
@JWTHandler.token_required
@limiter.limit("5 per hour")
def delete_event(current_user_id, current_user_role, event_id):
    logger.debug(f"Delete event route called for event_id: {event_id} by user_id: {current_user_id}")

    if not check_permission(current_user_role, ['Admin', 'Organizer']):
        logger.warning(f"Unauthorized access attempt by user_id: {current_user_id}")
        return jsonify({'message': 'Unauthorized access'}), 403

    connection = DatabaseHandler.get_db_connection()
    if connection is None:
        logger.error("Database connection error")
        return jsonify({'message': 'Database connection error'}), 500

    cursor = connection.cursor()
    try:
        if current_user_role == 'Organizer':
            logger.debug("Checking event ownership for Organizer")
            cursor.execute("""
                SELECT created_by 
                FROM EVENT_MANAGEMENT.Events 
                WHERE event_id = :event_id
            """, {'event_id': event_id})

            event_owner = cursor.fetchone()
            if not event_owner or event_owner[0] != current_user_id:
                logger.warning(f"Organizer user_id: {current_user_id} tried to delete event_id: {event_id} without ownership")
                return jsonify({'message': 'You can only delete your own events'}), 403

        logger.debug(f"Deleting event_id: {event_id}")
        cursor.execute("""
            DELETE FROM EVENT_MANAGEMENT.Events 
            WHERE event_id = :event_id
        """, {'event_id': event_id})

        connection.commit()
        logger.info(f"Event deleted successfully: {event_id}")
        return jsonify({'message': 'Event deleted successfully'})

    except cx_Oracle.DatabaseError as e:
        logger.error(f"Database error in delete_event route: {str(e)}")
        return jsonify({'message': 'Database error', 'error': str(e)}), 500
    finally:
        cursor.close()
        connection.close()

# Tüm etkinlikleri görüntüleme
@app.route('/events', methods=['GET'])
@JWTHandler.token_required
@limiter.limit("5 per hour")
def get_events(current_user_id, current_user_role):
    logger.debug(f"Get events route called by user_id: {current_user_id} with role: {current_user_role}")

    connection = None
    cursor = None
    try:
        connection = DatabaseHandler.get_db_connection()
        if connection is None:
            logger.error("Database connection error")
            return jsonify({'message': 'Database connection failed'}), 500

        cursor = connection.cursor()

        if current_user_role.lower() == 'admin':
            logger.debug("Admin fetching all events")
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
            logger.debug(f"Organizer fetching events for user_id: {current_user_id}")
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
            logger.debug(f"User fetching purchased events for user_id: {current_user_id}")
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

            if current_user_role.lower() == 'admin':
                event['ticket_count'] = row[10]
            elif current_user_role.lower() == 'organizer':
                event['ticket_count'] = row[10]
            else:  # User role
                event['ticket_status'] = row[10]
                event['available_tickets'] = row[5] - row[11] if row[5] else 0
                event.pop('created_by', None)
                event.pop('created_at', None)

            events.append(event)

        logger.info(f"Events fetched successfully for user_id: {current_user_id}")
        return jsonify(events), 200

    except cx_Oracle.DatabaseError as e:
        logger.error(f"Database error in get_events route: {str(e)}")
        return jsonify({'message': 'Database error', 'error': str(e)}), 500
    except Exception as e:
        logger.error(f"General error in get_events route: {str(e)}")
        return jsonify({'message': 'An error occurred', 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

# Yeni etkinlik oluşturma
@app.route('/events', methods=['POST'])
@JWTHandler.token_required
@limiter.limit("5 per hour")
def create_event(current_user_id, current_user_role):
    logger.debug(f"Create event route called by user_id: {current_user_id}")

    if not check_permission(current_user_role, ['Admin', 'Organizer']):
        logger.warning(f"Unauthorized access attempt by user_id: {current_user_id}")
        return jsonify({'message': 'Unauthorized'}), 403

    data = request.get_json()
    connection = DatabaseHandler.get_db_connection()
    if connection is None:
        logger.error("Database connection error")
        return jsonify({'message': 'Database connection error'}), 500

    cursor = connection.cursor()
    try:
        event_id_var = cursor.var(cx_Oracle.NUMBER)
        logger.debug("Inserting new event into database")
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

        event_id = event_id_var.getvalue()[0]
        connection.commit()
        logger.info(f"Event created successfully: {event_id}")
        return jsonify({'message': 'Event created successfully', 'event_id': event_id}), 201

    except cx_Oracle.DatabaseError as e:
        logger.error(f"Database error in create_event route: {str(e)}")
        return jsonify({'message': 'Database error', 'error': str(e)}), 500
    finally:
        cursor.close()
        connection.close()

# Bilet satın alma
@app.route('/tickets/purchase', methods=['POST'])
@JWTHandler.token_required
@limiter.limit("5 per hour")
def purchase_ticket(current_user_id, current_user_role):
    logger.debug(f"Purchase ticket route called by user_id: {current_user_id}")

    if not check_permission(current_user_role, ['User', 'Admin']):
        logger.warning(f"Unauthorized access attempt by user_id: {current_user_id}")
        return jsonify({'message': 'Unauthorized'}), 403

    data = request.get_json()
    event_id = data.get('event_id')
    logger.debug(f"Attempting to purchase ticket for event_id: {event_id}")

    connection = DatabaseHandler.get_db_connection()
    if connection is None:
        logger.error("Database connection error")
        return jsonify({'message': 'Database connection error'}), 500

    cursor = connection.cursor()
    try:
        cursor.execute("""
            SELECT price, capacity, 
                   (SELECT COUNT(*) FROM EVENT_MANAGEMENT.Tickets WHERE event_id = :event_id) as sold_tickets
            FROM EVENT_MANAGEMENT.Events 
            WHERE event_id = :event_id
        """, {'event_id': event_id})

        event_data = cursor.fetchone()
        if not event_data:
            logger.warning(f"Event not found: {event_id}")
            return jsonify({'message': 'Event not found'}), 404

        price, capacity, sold_tickets = event_data
        if sold_tickets >= capacity:
            logger.warning(f"Event is sold out: {event_id}")
            return jsonify({'message': 'Event is sold out'}), 400

        ticket_id_var = cursor.var(cx_Oracle.NUMBER)
        logger.debug("Creating ticket")
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
        logger.debug("Creating payment")
        cursor.execute("""
            INSERT INTO EVENT_MANAGEMENT.Payments (user_id, ticket_id, amount, payment_status)
            VALUES (:user_id, :ticket_id, :amount, 'Pending')
        """, {
            'user_id': current_user_id,
            'ticket_id': ticket_id,
            'amount': price
        })

        connection.commit()
        logger.info(f"Ticket purchased successfully: {ticket_id}")
        return jsonify({
            'message': 'Ticket purchased successfully',
            'ticket_id': ticket_id,
            'amount': float(price)
        }), 201

    except cx_Oracle.DatabaseError as e:
        logger.error(f"Database error in purchase_ticket route: {str(e)}")
        return jsonify({'message': 'Database error', 'error': str(e)}), 500
    finally:
        cursor.close()
        connection.close()
# SOAP WSDL endpoint'i için route
@app.route('/soap', methods=['POST', 'GET'])
def soap_service():
    return wsgi_app

API_URL = "http://172.20.10.3:5004"

# LangChain handler'ı bir kez başlat
langchain_handler = LangChainHandler()

@app.route('/chat', methods=['POST'])
@JWTHandler.token_required
def chat(current_user_id, current_user_role):
    try:
        # Kullanıcı sorgusunu al
        query = request.json.get('query').strip()
        logger.debug(f"Processing user query: {query}")

        # LangChain ile SQL sorgusu oluştur
        sql_query = langchain_handler.generate_sql_query(query)
        logger.debug(f"Generated SQL query: {sql_query}")

        # SQL sorgusunu temizle
        sql_query = clean_sql_query(sql_query)
        logger.debug(f"Cleaned SQL query: {sql_query}")

        # Veritabanı bağlantısını kur
        connection = DatabaseHandler.get_db_connection()
        if connection is None:
            logger.error("Veritabanı bağlantısı kurulamadı.")
            return jsonify({'message': 'Veritabanı bağlantısı kurulamadı.'}), 500

        cursor = connection.cursor()

        # Sorguyu çalıştır
        cursor.execute(sql_query)
        results = cursor.fetchall()

        # Sütun isimlerini al
        columns = [desc[0] for desc in cursor.description]

        # Sonuçları formatla ve LOB türlerini dönüştür
        response_data = []
        for row in results:
            formatted_row = {}
            for col_name, col_value in zip(columns, row):
                if isinstance(col_value, cx_Oracle.LOB):  # LOB türündeki veriyi kontrol et
                    formatted_row[col_name] = str(col_value)  # Metin formatına çevir
                else:
                    formatted_row[col_name] = col_value
            response_data.append(formatted_row)

        return jsonify({'response': response_data}), 200

    except Exception as e:
        logger.error(f"Error processing query: {str(e)}")
        return jsonify({'message': f'Error processing query: {str(e)}'}), 500
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5004)



