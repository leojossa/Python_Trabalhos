from flask import Flask, jsonify, render_template, url_for, request, session, logging, redirect, flash, Blueprint, make_response, Response
from flask_restplus import Api, Resource, static
from sqlalchemy.orm import scoped_session, sessionmaker
from passlib.hash import sha256_crypt
from functools import wraps
from datetime import datetime, timedelta
from sqlalchemy import MetaData
import sqlalchemy
import jwt
import datetime
import random
import string
import pandas as pd
import csv
from io import StringIO

engine = sqlalchemy.create_engine('mysql+pymysql://root:xxx@localhost/xxx')
metadata = MetaData(engine)

app = Flask(__name__, template_folder='template')

app.config['SESSION_TYPE'] = 'memcached'
app.config['SECRET_KEY'] = 'xxx'

#session.permanent = True
app.permanent_session_lifetime = timedelta(seconds=10) # tempo da sessao
SESSION_REFRESH_EACH_REQUEST = True #informa que a sessao tera refresh

@app.route('/')
def home():
    return render_template('home1.html')

'''
@app.route('/gerasenha', methods=['GET','POST'])
def gerasenha():
    if request.method == 'POST':
        random_source = string.ascii_letters + string.digits  # + string.punctuation
        password = random.choice(string.ascii_lowercase)
        password += random.choice(string.ascii_uppercase)
        password += random.choice(string.digits)
        # password += random.choice(string.punctuation)
        for i in range(6):
            password += random.choice(random_source)
        password_list = list(password)
        random.SystemRandom().shuffle(password_list)
        password = ''.join(password_list)
        return {'senha': password}
    return render_template('gerasenha.html')
'''
@app.route('/register', methods=['GET','POST'])
def alteraUsuario():
    metadata.reflect(schema='login')
    with engine.begin() as conn:
        if request.method == 'POST':
            username = request.form.get('username')
            passwordold = request.form.get('passwordold')
            password = request.form.get('password')
            confirm = request.form.get('confirm')
            passworddata = conn.execute('select password from login.users2 where username=%s', username).fetchone()
            for password_data in passworddata:
                if sha256_crypt.verify(passwordold, password_data):
                    session['log'] = True
                    secure_password = sha256_crypt.encrypt(str(password))
                    if password == confirm:
                        conn.execute('update login.users2 set username=%s, password=%s where username=%s', username,
                                     secure_password, username)
                    #return redirect(url_for('login'))
                    flash('Registro efetuado', 'success')
                    return render_template('login1.html')
            else:
                return redirect(url_for('login'))
        return render_template('register1.html')
#def register():
#    metadata.reflect(schema='login')
#    with engine.begin() as conn:
#        if request.method == 'POST':
#            name = request.form.get('name')
#            username = request.form.get('username')
#            password = request.form.get('password')
#            confirm = request.form.get('confirm')
#            secure_password = sha256_crypt.encrypt(str(password))

#            usernamedata = conn.execute('select username from login.users2 where username=%s', username).fetchone()

#            if usernamedata == None:
#                if password == confirm:
#                    conn.execute('insert into login.users2 (name, username, password) values (%s, %s, %s)', name, username, secure_password)
#                    flash('Registro efetuado', 'success')
#                    return redirect(url_for('login'))
                    #return redirect(url_for('restplus_doc.static', filename='api'))
#                else:
#                    flash('usuario já existe, contate o administrador', 'danger')
#                    return redirect(url_for('login'))
#        return render_template('register1.html')

user = []
senha = []
@app.route('/login', methods=['GET', 'POST'])
def login():
    metadata.reflect(schema='login')
    with engine.begin() as conn:
        if request.method == 'POST':
            username = request.form.get('name')
            password = request.form.get('password')
            senha.clear()
            senha.append(password)
            user.clear()
            user.append(username)
            usernamedata = conn.execute('select username from login.users2 where username=%s', username).fetchone()
            passworddata = conn.execute('select password from login.users2 where username=%s', username).fetchone()

            if usernamedata is None:
                flash('digite o usuario', 'danger')
                return render_template('login.html')
            else:
                for password_data in passworddata:
                    if sha256_crypt.verify(password, password_data):
                        session['log'] = True
                        token = jwt.encode(
                            {'user': request.form['name'], 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
                            app.config['SECRET_KEY'])
                        #return jsonify({'token': token.decode('UTF-8')})
                        query = conn.execute('select id, name, username, email from login.users2')
                        #result = [dict(zip(tuple(query.keys()), i)) for i in query.cursor]
                        #return str(result)
                        #return render_template('tela.html', query = query)
                        #return render_template('consulta.html')
                        flash('Login Efetuado', 'success')
                        return redirect(url_for('login'))

                else:
                    flash('senha incorreta', 'danger')
                    return redirect(url_for('login'))
                    #return render_template('login.html')
                    #return make_response('nao verificado', 401, {'WWW-Authenticate': 'Basic realm="Login Necessario"'})
        return render_template('login1.html')

#código para trazer a área do usuario
def area():
    metadata.reflect(schema='login')
    with engine.begin() as conn:
        username = user
        query = conn.execute('select area from users2 where name=%s', username)
        result = [i[0] for i in query.cursor]
        return result
    return area

#token para liberar o dropdown de consulta e manutencao
def token_required(f):
    @wraps(f)
    def decoreted(*args, **kwargs):
        token = senha
        if not token:
            #return jsonify({'message': 'Efetue o Login'}), 403
            flash('Efetue o login')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decoreted

lista = []
@app.route('/consulta', methods=['GET', 'POST'])
@token_required
def consulta():
    metadata.reflect(schema='login')
    with engine.begin() as conn:
        if request.method == 'POST':
            name = request.form.get('name')
            lista.clear() # limpa a lista
            lista.append(name) # faz apende do parametro na lista
            query = conn.execute('select id, name, username, email from login.users2 where name=%s', name)
            return render_template('tela.html', query=query)

        return render_template('consulta.html')

@app.route('/consulta', methods=['GET', 'POST'])
@token_required
def consulta1():
    metadata.reflect(schema='login')
    with engine.begin() as conn:
        if request.method == 'POST':
            name = request.form.get('name')
            query = conn.execute('select id, name, username, email from login.users2 where name=%s', name)
            result = [dict(zip(tuple(query.keys()), i)) for i in query.cursor]
            return result

#download em txt ou csv usando pandas e flask
@app.route('/download')
def download():
    metadata.reflect(schema='login')
    with engine.begin() as conn:
        name = lista
        query = conn.execute('select id, name, username, email from login.users2 where name=%s', name)
        result = [dict(zip(tuple(query.keys()), i)) for i in query.cursor]
        df = pd.DataFrame(result)
        #df = pd.read_sql_query(sql='select id, name, username, email from login.users2', con=conn)
        response = make_response(df.to_csv(index=False))
        response.headers.set("Content-Disposition", "attachment", filename="test.txt")
        response.headers["Content-Type"] = "txt/csv"
        return response

dataini = []
datafim = []
@app.route('/consultadata', methods=['GET', 'POST'])
@token_required
def consultadata():
    metadata.reflect(schema='db')
    with engine.begin() as conn:
        if request.method == 'POST':
            datainicial = request.form.get('datainicial')
            #datafinal = request.form.get('datafinal')
            #tratamento da data
            dataInicial = datetime.datetime.strptime(datainicial, '%d/%m/%Y').strftime('%Y-%m-%d')
            #dataFinal = datetime.datetime.strptime(datafinal, '%d/%m/%Y').strftime('%Y-%m-%d' + ' ' + '99:99:99')
            dataini.clear()
            datafim.clear()
            dataini.append(dataInicial)
            #datafim.append(dataFinal)
            query = conn.execute("select nome, telefone, celular, datacadastro "
                                 "from db.consumidor "
                                 "where dataAlteracao >= %s", dataini)
            return render_template('tela1.html', query=query)
        return render_template('consultadata.html')

@app.route('/downloaddata')
def downloaddata():
    metadata.reflect(schema='login')
    with engine.begin() as conn:
        datainicial = dataini
        #datafinal = datafim
        query = conn.execute('select nome, telefone, celular, datacadastro '
                             'from db.consumidor '
                             'where dataAlteracao >=%s', datainicial)
        result = [dict(zip(tuple(query.keys()), i)) for i in query.cursor]
        df = pd.DataFrame(result)
        #df = pd.read_sql_query(sql='select id, name, username, email from login.users2', con=conn)
        response = make_response(df.to_csv(index=False))
        response.headers.set("Content-Disposition", "attachment", filename="test.txt")
        response.headers["Content-Type"] = "txt/csv"
        return response

@app.route('/manutencao', methods=['GET', 'POST'])
@token_required
def manutencao():
    metadata.reflect(schema='db')
    with engine.begin() as conn:
        if request.method == 'POST':
            nome = request.form.get('nome')
            termouso = request.form.get('termouso')
            areanova = area()
            termousoapp = request.form.get('termousoapp')
            query = conn.execute('INSERT INTO db.consumidor(nome, termoUso, termoUsoApp, username, area) '
                                 'VALUES(%s, %s, %s, %s, %s)', nome, termouso, termousoapp, user, areanova)
            #return redirect(url_for('manutencao'))
            return render_template('manutencao.html')
    return render_template('manutencao.html')

@app.route('/logout')
def logout():
    #session.pop('log', None)
    senha.clear()
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)
