import os
from dotenv import load_dotenv
from flask import Flask, request, jsonify
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
from scanner.subdomain_scanner import scan_domain
from scanner.url_fuzzer import fuzz_urls

app = Flask(__name__)
jwt = JWTManager(app)

users = {
    "admin": None,
}
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
    global users
    users['admin'] = generate_password_hash(os.environ.get('ADMIN_PASSWORD'))

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

    if username in users and check_password_hash(users.get(username), password):
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200

    return jsonify({"msg": "Bad username or password"}), 401

@app.route('/scan/subdomain', methods=['POST'])
@jwt_required()
def scan_subdomain():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    data = request.get_json()
    domain = data.get('domain')
    if not domain:
        return jsonify({"error": "No domain provided"}), 400
    results = scan_domain(domain)
    results.save_to_mongo(db)
    return jsonify(results.to_dict()), 200

@app.route('/scan/url_fuzzer', methods=['POST'])
@jwt_required()
def url_fuzzer_domain():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    data = request.get_json()
    domain = data.get('url')
    if not domain:
        return jsonify({"error": "No domain provided"}), 400

    results = fuzz_urls(domain)
    results.save_to_mongo(db)
    return jsonify(results.to_dict()), 200

if __name__ == '__main__':
    load_environment()
    app.run(debug=True)
