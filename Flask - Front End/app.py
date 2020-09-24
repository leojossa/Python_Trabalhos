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

@app.route('/xxx', methods=['GET','POST'])
def alteraUsuario():
    metadata.reflect(schema='xxx')
    with engine.begin() as conn:
        if request.method == 'POST':
            username = request.form.get('xxx')
            passwordold = request.form.get('xxx')
            password = request.form.get('xxx')
            confirm = request.form.get('xxx')
            passworddata = conn.execute('select xxx from xxx.xxx where xxx=%s', username).fetchone()
            for password_data in passworddata:
                if sha256_crypt.verify(passwordold, password_data):
                    session['log'] = True
                    secure_password = sha256_crypt.encrypt(str(password))
                    if password == confirm:
                        conn.execute('update xxx.xxx set xxx=%s, xxx=%s where xxx=%s', username,
                                     secure_password, username)
                    #return redirect(url_for('login'))
                    flash('Registro efetuado', 'success')
                    return render_template('login1.html')
            else:
                return redirect(url_for('login'))
        return render_template('register1.html')

@app.route('/xxx', methods=['GET', 'POST'])
def login():
    metadata.reflect(schema='xxx')
    with engine.begin() as conn:
        if request.method == 'POST':
            username = request.form.get('xxx')
            password = request.form.get('xxx')
            usernamedata = conn.execute('select xxx from xxx.xxx where xxx=%s', username).fetchone()
            passworddata = conn.execute('select xxx from xxx.xxx where xxx=%s', username).fetchone()

            if usernamedata is None:
                flash('digite o usuario', 'danger')
                return render_template('login.html')
            else:
                for password_data in passworddata:
                    if sha256_crypt.verify(password, password_data):
                        session['log'] = True
                        token = jwt.encode(
                            {'user': request.form['xxx'], 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
                            app.config['SECRET_KEY'])
                        query = conn.execute('select xxx, xxx, xxx, xxx from xxx.xxx')
                        flash('Login Efetuado', 'success')
                        return redirect(url_for('login'))

                else:
                    flash('senha incorreta', 'danger')
                    return redirect(url_for('login'))
        return render_template('login1.html')

#código para trazer a área do usuario
def area():
    metadata.reflect(schema='xxx')
    with engine.begin() as conn:
        username = user
        query = conn.execute('select xxx from xxx where xxx=%s', username)
        result = [i[0] for i in query.cursor]
        return result
    return area

#token para liberar o dropdown de consulta e manutencao
def token_required(f):
    @wraps(f)
    def decoreted(*args, **kwargs):
        token = senha
        if not token:
            flash('Efetue o login')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decoreted

lista = []
@app.route('/xxx', methods=['GET', 'POST'])
@token_required
def consulta():
    metadata.reflect(schema='xxx')
    with engine.begin() as conn:
        if request.method == 'POST':
            name = request.form.get('xxx')
            lista.clear() # limpa a lista
            lista.append(name) # faz apende do parametro na lista
            query = conn.execute('select xxx, xxx, xxx, xxx from xxx.xxx where xxx=%s', name)
            return render_template('tela.html', query=query)

        return render_template('consulta.html')

@app.route('/xxx', methods=['GET', 'POST'])
@token_required
def consulta1():
    metadata.reflect(schema='xxx')
    with engine.begin() as conn:
        if request.method == 'POST':
            name = request.form.get('xxx')
            query = conn.execute('select xxx, xxx, xxx, xxx from xxx.xxx where xxx=%s', name)
            result = [dict(zip(tuple(query.keys()), i)) for i in query.cursor]
            return result

#download em txt ou csv usando pandas e flask
@app.route('/xxx')
def download():
    metadata.reflect(schema='xxx')
    with engine.begin() as conn:
        name = lista
        query = conn.execute('select xxx, xxx, xxx, xxx from xxx.xxx where xxx=%s', name)
        result = [dict(zip(tuple(query.keys()), i)) for i in query.cursor]
        df = pd.DataFrame(result)
        response = make_response(df.to_csv(index=False))
        response.headers.set("Content-Disposition", "attachment", filename="test.txt")
        response.headers["Content-Type"] = "txt/csv"
        return response

dataini = []
datafim = []
@app.route('/xxx', methods=['GET', 'POST'])
@token_required
def consultadata():
    metadata.reflect(schema='xxx')
    with engine.begin() as conn:
        if request.method == 'POST':
            datainicial = request.form.get('xxx')
            #tratamento da data
            dataInicial = datetime.datetime.strptime(datainicial, '%d/%m/%Y').strftime('%Y-%m-%d')
            dataini.clear()
            datafim.clear()
            dataini.append(dataInicial)
            datafim.append(dataFinal)
            query = conn.execute("select xxx, xxx, xxx, xxx "
                                 "from xxx.xxx "
                                 "where xxx >= %s", dataini)
            return render_template('tela1.html', query=query)
        return render_template('consultadata.html')

@app.route('/xxx')
def downloaddata():
    metadata.reflect(schema='xxx')
    with engine.begin() as conn:
        datainicial = dataini
        query = conn.execute('select xxx, xxx, xxx, xxx '
                             'from xxx.xxx '
                             'where xxx >=%s', datainicial)
        result = [dict(zip(tuple(query.keys()), i)) for i in query.cursor]
        df = pd.DataFrame(result)
        response = make_response(df.to_csv(index=False))
        response.headers.set("Content-Disposition", "attachment", filename="test.txt")
        response.headers["Content-Type"] = "txt/csv"
        return response

@app.route('/xxx', methods=['GET', 'POST'])
@token_required
def manutencao():
    metadata.reflect(schema='xxx')
    with engine.begin() as conn:
        if request.method == 'POST':
            nome = request.form.get('xxx')
            termouso = request.form.get('xxx')
            areanova = area()
            termousoapp = request.form.get('xxx')
            query = conn.execute('INSERT INTO db.consumidor(xxx, xxx, xxx, xxx, xxx) '
                                 'VALUES(%s, %s, %s, %s, %s)', nome, termouso, termousoapp, user, areanova)
            return render_template('manutencao.html')
    return render_template('manutencao.html')

@app.route('/xxx')
def logout():
    senha.clear()
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)
