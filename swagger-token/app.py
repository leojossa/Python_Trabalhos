from flask import Flask, jsonify, render_template, url_for, request, session, logging, redirect, flash, Blueprint, current_app
from flask_restplus import Api, Resource, static,fields
from sqlalchemy.orm import scoped_session, sessionmaker
from passlib.hash import sha256_crypt
from functools import wraps
from datetime import date, timedelta
from sqlalchemy import MetaData
from flask.json import JSONEncoder
import datetime as dt
import datetime
import jwt
import sqlalchemy
import getpass
import pandas as pd

engine = sqlalchemy.create_engine('mysql+pymysql://root:haneef24@localhost/login')
metadata = MetaData(engine)
app = Flask(__name__)
#app.json_encoder = CustomJSONEncoder

authorizations = {
    'apikey': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization',
        'description': "Type in the *'Value'* input box below: **'Bearer &lt;JWT&gt;'**, where JWT is the token"
    }
}

api = Api(app, version='1.0', title='xxx',
          description='Visualizacao', authorizations=authorizations,
          security='apikey'
          )
app.config['SESSION_TYPE'] = 'xxx'
app.config['SECRET_KEY'] = 'xxx'
def token_required(f):
    @wraps(f)

    def decoreted(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization']
        if not token:
            return {'message': 'Token is missing. '}, 401
        if token == token:
            data = jwt.decode(token, app.config['SECRET_KEY'])
        return f(*args, **kwargs)
    return decoreted

@api.route('/xx/<xxx>/<xxx>/<xxx>/<xxx>/<xxx>', methods=['POST'])
class registraUsuario(Resource):
    def post(self, name, username, email, password, confirm):
        metadata.reflect(schema='xxx')
        with engine.begin() as conn:
            secure_password = sha256_crypt.encrypt(str(password))
            if password == confirm:
                conn.execute('insert into xxx.xxx (xxx, xxx, xxx, xxx) values (%s, %s, %s, %s)', name,
                         username, email, secure_password)
                return 'xxx'
            else:
                return 'xxx'

   
@api.route('/xxx/<xxx>/<xxx>', methods=['POST'])
class logaUsuario(Resource):
    def post(self, username, password):
        metadata.reflect(schema='xxx')
        with engine.begin() as conn:
            usernamedata = conn.execute('select xxx from xxx.xxx where xxx=%s', username).fetchone()
            passworddata = conn.execute('select xxx from xxx.xxx where xxx=%s', username).fetchone()
            for password_data in passworddata:
                if sha256_crypt.verify(password, password_data):
                    session['log'] = True
                    token = jwt.encode(
                        {'username': username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)}, #datetime.timedelta(minutes=30)
                        app.config['SECRET_KEY'])
                    return jsonify({'token': token.decode('UTF-8')})
                    #return 'logado'
            else:
                return 'Login nao efetuado, tente novamente!'

@api.route('/xxx/<xxx>', methods=['GET'])
class verificaUsuario(Resource):
    @token_required
    def get(self, username):
        metadata.reflect(schema='xxx'
        with engine.begin() as conn:
            query = conn.execute('select xxx, max(cast(xxx as char)) as xxx '
                                 'from xxx.xxx '
                                 'where xxx=%s', username)
            result = [dict(zip(tuple(query.keys()), i)) for i in query.cursor]
            for lista in result:
                print(lista['nome'])
                lista1 = []
                lista1.clear()
                lista1.append(lista['nome'])
                print(lista1)
            return jsonify({'result': result})

@api.route('/xxx/<xxx>/<xxx>', methods=['POST'])
class incluiUsuario(Resource):
    @token_required
    def post(self, user, id):
        metadata.reflect(schema='xxx')
        with engine.begin() as conn:
            query = conn.execute('insert into xxx.xxx(xxx, xxx) '
                                 'values(%s, %s)', user, id)
            query2 = conn.execute('update xxx.xxx set xxx = '
                                  'case when xxx=%s and xxx = x '
                                  'then "x" else "x" end where xxx=%s', user, user
                                  )
            return 'ok'

teste = api.model('usuario', {'usuario': fields.String('usuario'), 'senha': fields.String('password')})

@api.route('/xxx', methods=['POST'])
class teste(Resource):
    @api.expect(teste)
    @token_required
    def post(self):
        return teste(api.payload)
        json_data = request.json()
        
teste = api.model('teste', {'username': fields.String('username'), 'password': fields.String('password')})
@api.route('/xxx/', methods=['POST'])
class logaUsuario(Resource):
    @api.expect(teste)
    #@api.marshal_with(password)
    def post(self):
        metadata.reflect(schema='xxx')
        with engine.begin() as conn:
            json_data = request.json
            username = json_data['xxx']
            password = json_data['xxx']
            usernamedata = conn.execute('select xxx from xxx.xxx where xxx=%s', username).fetchone()
            passworddata = conn.execute('select xxx from xxx.xxx where xxx=%s', username).fetchone()
            for password_data in passworddata:
                if sha256_crypt.verify(password, password_data):
                    session['log'] = True
                    token = jwt.encode(
                        {'username': username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
                        app.config['SECRET_KEY'])
                    return jsonify({'token': token.decode('UTF-8')})
                    #return 'logado'
            else:
                return {'result': 'Senha incorreta! Tente novamente'}, 401

#alteracao da senha
teste1 = api.model('Alteracao Senha', {'xxx': fields.String('xxx'),
                                       'xxx': fields.String('xxx'),
                                       'xxx': fields.String('xxx'),
                                       'xxx': fields.String('xxx')})

@api.route('/xxx', methods=['POST'])
class alteraSenha(Resource):
    @api.expect(teste1)
    def post(self):
        username = api.payload['xxx']
        passwordold = api.payload['xxx']
        password = api.payload['xxx']
        confirm = api.payload['xxx']
        metadata.reflect(schema='xxx')
        with engine.begin() as conn:
            passworddata = conn.execute('select xxx from xxx.xxx where xxx=%s', username).fetchone()
            for password_data in passworddata:
                if sha256_crypt.verify(passwordold, password_data):
                    session['log'] = True
                    secure_password = sha256_crypt.encrypt(str(password))
                    if password == confirm:
                        conn.execute('update xxx.xxx set xxx=%s, xxx=%s where xxx=%s', username, secure_password, username)
                    return {'result': 'Senha Alterada com Sucesso'}, 201
            else:
                return {'result': 'Senha nao alterada! Tente Novamente!'}, 401

if __name__ == '__main__':
    app.run(debug=True)
