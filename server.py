from pywarp import RelyingPartyManager, Credential
import base64
from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from backend import SQLliteBackend

app = Flask('Webauth_demo')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///webauthn.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(150), unique=True)
    credential_id = db.Column(db.String(250), unique=True)
    public_key = db.Column(db.String(65), unique=True)
    authentication_challenge = db.Column(db.Binary)
    registration_challenge = db.Column(db.Binary)

    def __init__(self, email):
        self.email = email


db.create_all()

rp_name = "kosci.cz"
rp = RelyingPartyManager("WebAuthn demo", credential_storage_backend=SQLliteBackend(db, User))


@app.route("/")
def hello():
    return render_template("index.html")


# Registration

@app.route("/getCredentialOptions", methods=['POST'])
def get_credential_options():
    email = request.form.get('email')
    options = rp.get_registration_options(email=email)
    if options:
        options["user"]["displayName"] = request.form.get('name')
        user = User.query.filter_by(email=email).first()
        if user is not None:
            user.name = options["user"]["displayName"]
            db.session.commit()
    return jsonify(options)


@app.route("/verifyCredentials", methods=['POST'])
def verify_credentials():
    data = request.get_json()
    email = data.get('email')
    user = User.query.filter_by(email=email).first()
    if user is not None:
        if user.public_key:
            return jsonify({'registered': False, "reason": "User already registered"})
    try:

        response = rp.register(base64.b64decode(data.get('clientData')),
                               base64.b64decode(data.get('attestationObject')),
                               bytes(email, 'utf-8'))
        return jsonify(response)
    except Exception:
        return jsonify(
            {'registered': False, "reason": "Unknown Error! (But it's probably attestation block by browser)"})


# Login

@app.route("/getAuthenticationOptions", methods=['POST'])
def get_authentication_options():
    email = request.form.get('email')
    user = User.query.filter_by(email=email).first()
    if user is None:
        return jsonify({'verified': False, "reason": "User is not registered"})
    options = rp.get_authentication_options(email=email)
    return jsonify(options)


@app.route("/verifyAuthentication", methods=['POST'])
def verify_authentication():
    email = request.form.get('email')
    auth_data = request.form.get('authenticatorData')
    client_json = request.form.get('clientData')
    signature = request.form.get('signature')
    user_handle = request.form.get('userHandle')
    raw_id = request.form.get('rawId')

    try:
        result = rp.verify(authenticator_data=base64.b64decode(auth_data),
                           client_data_json=base64.b64decode(client_json),
                           signature=base64.b64decode(signature),
                           user_handle=base64.b64decode(user_handle),
                           raw_id=base64.b64decode(raw_id),
                           email=bytes(email, 'utf-8'))
        user = User.query.filter_by(email=email).first()
        result['name'] = user.name
        return jsonify(result)
    except Exception as e:
        return jsonify({"verified": False, "reason": str(e)})
