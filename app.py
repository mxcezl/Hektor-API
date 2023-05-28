from functools import wraps
import os
from threading import Thread
import uuid
from dotenv import load_dotenv
from flask import Flask, request, jsonify
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, get_jwt, get_jwt_identity, jwt_required, create_access_token, verify_jwt_in_request
from scanner.subdomain_scanner import scan_domain
from scanner.url_fuzzer import init_db_fuzz_object
from scanner.port_scanner import init_db_port_object
from tasks import perform_url_scan_background, perform_ports_scan_background

app = Flask(__name__)
jwt = JWTManager(app)

client = None
db = None

def get_mongo_client():
    mongodb_username = os.environ.get('MONGODB_USERNAME')
    mongodb_password = os.environ.get('MONGODB_PASSWORD')
    mongodb_url = os.environ.get('MONGODB_URL')

    if not all([mongodb_username, mongodb_password, mongodb_url]):
        raise EnvironmentError('Missing environment variables for MongoDB connection')

    return MongoClient('mongodb+srv://' + mongodb_username + ':' + mongodb_password + '@' + mongodb_url)

def load_environment():
    load_dotenv()
    app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY')
    global client
    client = get_mongo_client()
    global db
    db = client[os.environ.get('MONGODB_DB')]

@app.route('/register', methods=['POST'])
def register():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    username = request.json.get('username', None)
    password = request.json.get('password', None)
    role = request.json.get('role', None)

    if not username:
        return jsonify({"msg": "Missing username parameter"}), 400
    if not password:
        return jsonify({"msg": "Missing password parameter"}), 400
    if not role:
        return jsonify({"msg": "Missing role parameter. Valid roles are PENTESTER and RAPPORTER"}), 400
    if role not in ['PENTESTER', 'RAPPORTER']:
        return jsonify({"msg": "Invalid role parameter"}), 400

    # Vérifier si l'utilisateur existe déjà
    user = db.users.find_one({"username": username})
    if user:
        return jsonify({"msg": "Username already exists"}), 400

    hashed_password = generate_password_hash(password)
    db.users.insert_one({"username": username, "password": hashed_password, "role": role})

    return jsonify({"msg": "User " + username + " created successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    username = request.json.get('username', None)
    password = request.json.get('password', None)

    if not username:
        return jsonify({"msg": "Missing username parameter"}), 400
    if not password:
        return jsonify({"msg": "Missing password parameter"}), 400

    user = db.users.find_one({"username": username})

    if user and check_password_hash(user.get("password"), password):
        # Ajouter le rôle dans le JWT
        access_token = create_access_token(identity=username, additional_claims={"role": user.get("role")})
        return jsonify(access_token=access_token), 200

    return jsonify({"msg": "Bad username or password"}), 401

def role_required(roles, message):
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            if claims['role'] not in roles:
                return jsonify(error='Access denied. ' + message), 403
            else:
                return fn(*args, **kwargs)
        return decorator
    return wrapper

def pentester_required(fn):
    return role_required(['PENTESTER'], "This route can be accessed only by PENTESTER users.")(fn)

def rapporter_or_pentester_required(fn):
    return role_required(['RAPPORTER', 'PENTESTER'], "This route can be accessed only by PENTESTER or RAPPORTER users.")(fn)

@app.route('/scan/subdomain', methods=['POST'])
@jwt_required()
@pentester_required
def scan_subdomain():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    data = request.get_json()
    domain = data.get('domain')
    if not domain:
        return jsonify({"error": "No domain provided"}), 400
    
    username = get_jwt_identity()

    results = scan_domain(domain, username)
    results.save_to_mongo(db)
    return jsonify(results.to_dict()), 200

@app.route('/scan/url_fuzzer', methods=['POST'])
@jwt_required()
@pentester_required
def url_fuzzer_domain():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    data = request.get_json()
    domain = data.get('url')
    if not domain:
        return jsonify({"error": "No domain provided"}), 400

    # Générez un identifiant unique pour le scan
    scan_id = str(uuid.uuid4())
    username = get_jwt_identity()

    init_db_fuzz_object(scan_id, username, db)

    thread = Thread(target=perform_url_scan_background, kwargs={'domain': domain, 'db': db, 'scan_id': scan_id})
    thread.start()

    return jsonify({"scan_id": scan_id}), 200

@app.route('/scan/url_fuzzer/result/<scan_id>', methods=['GET'])
@jwt_required()
@rapporter_or_pentester_required
def get_url_scan_result(scan_id):
    scan = db.urls.find_one({'_id': scan_id})

    if scan:
        del scan['user']
        del scan['_id']
        return jsonify(scan), 200

    return jsonify({"error": "Scan introuvable"}), 400

@app.route('/scan/ports', methods=['POST'])
@jwt_required()
@pentester_required
def scan_ports():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    data = request.get_json()
    ips = data.get('ips')

    # remove duplicates
    ips = list(set(ips))
    
    if not ips:
        return jsonify({"error": "No IPs provided"}), 400

    # Générez un identifiant unique pour le scan
    scan_id = str(uuid.uuid4())
    username = get_jwt_identity()

    init_db_port_object(scan_id, db, ips, username)
    
    thread = Thread(target=perform_ports_scan_background, kwargs={'ips': ips, 'db': db, 'scan_id': scan_id})
    thread.start()

    return jsonify({"scan_id": scan_id}), 200

@app.route('/scan/ports/result/<scan_id>', methods=['GET'])
@jwt_required()
@rapporter_or_pentester_required
def get_port_scan_result(scan_id):
    # Vérifiez si le scan est terminé en consultant la base de données
    scan = db.ports.find_one({'_id': scan_id})
    
    if scan:
        del scan['user']
        del scan['_id']
        return jsonify(scan), 200

    return jsonify({"error": "Scan introuvable"}), 400

@app.route('/my_scans', methods=['GET'])
@jwt_required()
@pentester_required
def get_user_scans():
    username = get_jwt_identity()
    url_scans = db.urls.find({'user': username})
    host_scans = db.hosts.find({'user': username})
    port_scans = db.ports.find({'user': username})

    # Convertir les objets Cursor en listes de dictionnaires
    url_scans = [scan for scan in url_scans]
    host_scans = [scan for scan in host_scans]
    port_scans = [scan for scan in port_scans]

    for scan_list in [url_scans, host_scans, port_scans]:
        for scan in scan_list:
            # Supprimer les champs indésirables de la réponse
            if 'user' in scan: del scan['user']
            if '_id' in scan: del scan['_id']
            
    return jsonify(url_scans=url_scans, host_scans=host_scans, port_scans=port_scans), 200

@app.route('/my_scans_ids', methods=['GET'])
@jwt_required()
def get_user_scans_ids():
    username = get_jwt_identity()
    url_scans = db.urls.find({'user': username}, {'_id': 1})
    host_scans = db.hosts.find({'user': username}, {'_id': 1})
    port_scans = db.ports.find({'user': username}, {'_id': 1})

    # Convertir les objets Cursor en listes d'identifiants
    url_scans = [str(scan['_id']) for scan in url_scans]
    host_scans = [str(scan['_id']) for scan in host_scans]
    port_scans = [str(scan['_id']) for scan in port_scans]

    return jsonify(url_scans=url_scans, host_scans=host_scans, port_scans=port_scans), 200

if __name__ == '__main__':
    load_environment()
    app.run(host='0.0.0.0', debug=True)
