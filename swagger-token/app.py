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
'''
class CustomJSONEncoder(JSONEncoder):
    def default(self, obj):
        try:
            if isinstance(obj, date):
                return obj.isoformat()
            iterable = iter(obj)
        except TypeError:
            pass
        else:
            return list(iterable)
        return JSONEncoder.default(self, obj)
'''
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

api = Api(app, version='1.0', title='Teste de Visualizacao de API',
          description='Visualizacao', authorizations=authorizations,
          security='apikey'
          )
app.config['SESSION_TYPE'] = 'memcached'
app.config['SECRET_KEY'] = 'teste'
#password = api.model('password', {'password': fields.String}, format='password')
#password = fields.String('The password.', format='password')
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
        #else:
        #    return {'message': 'Token Incorreto'}, 401
        #print('TOKEN: {}'. format(data))
        #logger.info('Senha correta %s', getpass.getuser())
        return f(*args, **kwargs)
    return decoreted

@api.route('/Registra/<name>/<username>/<email>/<password>/<confirm>', methods=['POST'])
class registraUsuario(Resource):
    def post(self, name, username, email, password, confirm):
        metadata.reflect(schema='login')
        with engine.begin() as conn:
            #name = request.form.get('name')
            #username = request.form.get('username')
            #email = request.form.get('email')
            #password = request.form.get('password')
            #confirm = request.form.get('confirm')
            secure_password = sha256_crypt.encrypt(str(password))
            if password == confirm:
                conn.execute('insert into login.users2 (name, username, email, password) values (%s, %s, %s, %s)', name,
                         username, email, secure_password)
                return 'usuario cadastrado com sucesso'
            else:
                return 'usuario nao cadastrado'

            #usernamedata = conn.execute('insert into login.users2 (name, username, email, password) values (%s, %s, %s, %s)', name, username, email, password)
            #if usernamedata == None:
            #    if password == confirm:
            #        conn.execute('insert into login.users2 (name, username, email, password) values (%s, %s, %s, %s)', name,
            #                     username, email, secure_password)
            #        return 'usuario cadastrado com sucesso'
            #    else:
            #        return 'usuario nao cadastrado'
#senha = getpass.getpass('password')
@api.route('/Login/<username>/<password>', methods=['POST'])
#@api.doc(params={'password': getpass.getpass('digite password')})
class logaUsuario(Resource):
    #@api.marshal_with(password)
    def post(self, username, password):
        metadata.reflect(schema='login')
        with engine.begin() as conn:
            usernamedata = conn.execute('select username from login.users2 where username=%s', username).fetchone()
            passworddata = conn.execute('select password from login.users2 where username=%s', username).fetchone()
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

#@api.doc(security=[{'oauth2_password': ['member:read']}])
@api.route('/user/<username>', methods=['GET'])
class verificaUsuario(Resource):
    @token_required
    def get(self, username):
        metadata.reflect(schema='db')
        with engine.begin() as conn:
            #query = conn.execute('select nome, dataAlteracao '
            #                     'from db.consumidor '
            #                     'where nome=%s and dataAlteracao in '
            #                     '(select max(dataAlteracao) from db.consumidor'
            #                     ''
            #                     ')', username)
            query = conn.execute('select nome, max(cast(dataAlteracao as char)) as dataAlteracao '
                                 'from db.consumidor '
                                 'where nome=%s', username)
            #lista = []
            #nome = request.form.get('nome')
            #lista.clear()
            #lista.append(nome)
            #print(lista)
            #return jsonify(query)
            result = [dict(zip(tuple(query.keys()), i)) for i in query.cursor]
            #teste de retorno de um campo do select
            for lista in result:
                print(lista['nome'])
                lista1 = []
                lista1.clear()
                lista1.append(lista['nome'])
                print(lista1)
            #now = dt.datetime.now()
            #return jsonify({'now': now})
            #df = pd.DataFrame(result)
            #cs = df.to_json()
            #print(cs)
            #return cs
            #return jsonify({'result': df})
            return jsonify({'result': result})
'''
@api.route('/user/<user>', methods=['GET'])
class consultaUsuario(Resource):
    @token_required
    def get(self, user):
        metadata.reflect(schema='db')
        with engine.begin() as conn:
            query = conn.execute('select nome from db.consumidor where nome=%s', user)
            result = [dict(zip(tuple(query.keys()), i)) for i in query.cursor]
            return jsonify({'result': result})
'''
#@api.doc(security=[{'oauth2_password': ['member:read']}])
@api.route('/user/<user>/<id>', methods=['POST'])
#@api.doc(params={'id': 'id'})
class incluiUsuario(Resource):
    @token_required
    def post(self, user, id):
        metadata.reflect(schema='db')
        with engine.begin() as conn:
            query = conn.execute('insert into db.consumidor(nome, termoUso) '
                                 'values(%s, %s)', user, id)
            query2 = conn.execute('update db.consumidor set optIn_optOut = '
                                  'case when nome=%s and termoUso = 1 '
                                  'then "s" else "n" end where nome=%s', user, user
                                  )
            return 'ok'

teste = api.model('usuario', {'usuario': fields.String('usuario'), 'senha': fields.String('password')})

@api.route('/teste', methods=['POST'])
class teste(Resource):
    @api.expect(teste)
    @token_required
    def post(self):
        return teste(api.payload)
        json_data = request.json()
        #username = json_data['username']
        #password = json_data['password']

teste = api.model('teste', {'username': fields.String('username'), 'password': fields.String('password')})
@api.route('/Login/', methods=['POST'])
#@api.doc(params={'password': getpass.getpass('digite password')})
class logaUsuario(Resource):
    @api.expect(teste)
    #@api.marshal_with(password)
    def post(self):
        metadata.reflect(schema='login')
        with engine.begin() as conn:
            json_data = request.json
            username = json_data['username']
            password = json_data['password']
            usernamedata = conn.execute('select username from login.users2 where username=%s', username).fetchone()
            passworddata = conn.execute('select password from login.users2 where username=%s', username).fetchone()
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
teste1 = api.model('Alteracao Senha', {'username': fields.String('username'),
                                       'passwordold': fields.String('passwordold'),
                                       'password': fields.String('password'),
                                       'confirm': fields.String('confirm')})

@api.route('/Altera_Senha', methods=['POST'])
class alteraSenha(Resource):
    @api.expect(teste1)
    def post(self):
        username = api.payload['username']
        passwordold = api.payload['passwordold']
        password = api.payload['password']
        confirm = api.payload['confirm']
        metadata.reflect(schema='login')
        with engine.begin() as conn:
            passworddata = conn.execute('select password from login.users2 where username=%s', username).fetchone()
            for password_data in passworddata:
                if sha256_crypt.verify(passwordold, password_data):
                    session['log'] = True
                    secure_password = sha256_crypt.encrypt(str(password))
                    if password == confirm:
                        conn.execute('update login.users2 set username=%s, password=%s where username=%s', username, secure_password, username)
                    return {'result': 'Senha Alterada com Sucesso'}, 201
            else:
                return {'result': 'Senha nao alterada! Tente Novamente!'}, 401

if __name__ == '__main__':
    app.run(debug=True)
