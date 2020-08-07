
from flask import Flask,request,make_response,jsonify
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash,check_password_hash
import jwt
import datetime
from functools import wraps
application = app = Flask(__name__)

app.config['SECRET_KEY']='secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)

class Users(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    public_id = db.Column(db.String(50),unique=True)
    Full_name = db.Column(db.String(80))
    User_password = db.Column(db.String(80))

def Token(f):
    @wraps(f)
    def decorated(*args,**kwrgs):
        token=None
        if'Bearer-token' in request.headers:
            token=request.headers['Bearer-token']
        if not token:
            return jsonify({'message': 'token missing'}),401
        try:
            token = token[7:]
            data=jwt.decode(token,app.config['SECRET_KEY'])
            current_user = Users.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'not a valid token'}), 401
        return f(current_user,*args,**kwrgs)
    return decorated




@app.route('/',methods=['GET'])
@Token
def Hello_world(current_user):
    return("Hello World")

@app.route('/',methods=['GET'])
def Login():
    return ''
@app.route('/create',methods=['POST'])
@Token
def Create_user(current_user):
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'],method='sha256')
    new_user = Users(public_id= str(uuid.uuid4()),Full_name=data['name'],User_password =hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return 'User Created'



@app.route('/login',)
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response("Not verified",401,{'WWW-Authenticate':'Basic realm="Login requtired!"'})
    user = Users.query.filter_by(Full_name=auth.username).first()
    if not user:
        return make_response("Not verified",401,{'WWW-Authenticate':'Basic realm="Login requtired!"'})
    if check_password_hash(user.User_password,auth.password):
        token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow()+datetime.timedelta(minutes=15)}, app.config['SECRET_KEY'])

        return jsonify({'token':'Bearer '+token.decode('UTF-8')})
    return make_response("Not verified",401,{'WWW-Authenticate':'Basic realm="Login requtired!"'})


if __name__ == '__main__':
    app.run(host='0.0.0.0',port=80,debug=True)
