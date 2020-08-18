import sys
from flask import Flask, render_template, redirect, request, flash
import requests
import hashlib
import json

app = Flask(__name__)
app.secret_key = "regis"

@app.route('/')
def index():
    existeErro=False
    print( alias, file=sys.stderr)
    return render_template('dados.html', existe_erro = existeErro, certificados = alias)

def user_discovery(url, parameters):
    response = requests.post(url, json=parameters)
    erro = False

    print(response.status_code, file=sys.stderr)
    if (response.status_code != 200):
        flash("Problema de conexão")
        erro = True

    data = response.json()

    status = data['status']
    print(status, file=sys.stderr)
    if (status == "N"):
        flash("Usuário não tem certificado")
        erro = True

    username = ""
    if (not erro):
        slots = data['slots']
        username = slots[0]['slot_alias']


    return username, erro

def user_authorize(url, parameters):
    response = requests.post(url, json=parameters)
    access_token = ""
    erro = False

    data = response.json()

    print(response.status_code, file=sys.stderr)
    if (response.status_code != 200):
        flash("Erro de conexão")
        erro = True
    else:
        access_token = data['access_token']

    return access_token, erro

def certificate_discovery(url, access_token):
    hed = {'Authorization': 'Bearer ' + access_token}
    response = requests.get(url , headers = hed )
    erro = False
    certificates = ""

    print( url, hed, file=sys.stderr )
    if (response.status_code != 200):
        flash("Problema de conexão")
        erro = True

    if (not erro):
        data = response.json()

        certificates = data['certificates']

    if len(certificates) == 0 and not erro:
        flash("Nenhum certificado retornado")
        erro = True

    listaCertificados = []
    if (not erro):
        for alias in certificates:
            listaCertificados.append( alias['alias'] )

    return listaCertificados, erro

@app.route('/criar', methods=['POST'])
def criar():
    cpf = request.form['cpf']
    otp = request.form['otp']
    access_token = ""
    global alias

    parameters = dict([("client_id", client_id), ("client_secret", client_secret),
                       ("user_cpf_cnpj", user_cpf_cnpj), ("val_cpf_cnpj", cpf)])

    print("- user discovery -", file=sys.stderr)
    username, erro = user_discovery(url_discovery, parameters)

    print("------------", file=sys.stderr)
    print("CPF:", cpf, "OTP: ", otp, file=sys.stderr)
    print("USERNAME: ", username)

    if ( not erro):
        parameters = dict([("client_id", client_id), ("client_secret", client_secret), ("username", username),
                           ("password", otp), ("scope", "single_signature"), ("grant_type", "password")])

        print("- user authorize -", file=sys.stderr)
        access_token, erro = user_authorize(url_authorize, parameters)

    if (not erro):
        print("------------", file=sys.stderr)
        print("ACCESS TOKEN: ", access_token, file=sys.stderr)
        print("- certificate discovery -", file=sys.stderr)
        alias, erro = certificate_discovery(url_certificate, access_token)

    return redirect('/')

client_id = "teste_mateus_torres"
client_secret = "f70b0a352b699d73777e4abb8c0b8ca75494c82d"
user_cpf_cnpj = "CPF"
alias = []

url_discovery = "https://apicloudid.hom.vaultid.com.br/v0/oauth/user-discovery"
url_authorize = "https://apicloudid.hom.vaultid.com.br/v0/oauth/pwd_authorize"
url_certificate = "https://apicloudid.hom.vaultid.com.br/v0/oauth/certificate-discovery"

app.run(debug=True)