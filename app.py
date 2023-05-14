from flask import Flask, render_template, request
from flask_cors import CORS
import requests
import urllib.parse
import base64
import hashlib
import os
import jwt
import json

CODE_VERIFIER = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode('ascii')
REDIRECT_URI = "http://localhost:5001/callback"

app = Flask(__name__)
CORS(app)

@app.route('/')
def index():
  return render_template(
    'index.html',
    directory = get_directory()
  )

@app.route('/callback', methods=['POST'])
def handle_callback():
  app.debug = True
  state = request.form.get('state')
  idp = urllib.parse.parse_qs(state).get('idp')[0]
  print(idp)

  directory = get_directory()
  tokens = get_tokens(directory[idp], request)
  userinfo = get_user_info(directory[idp], tokens)

  return render_template(
    'userinfo.html',
    userinfo = userinfo,
    idp_name = directory[idp]['name'],
    decoded_id_token = json.dumps(decode_id_token(tokens['id_token']), indent=4)
  )

def get_user_info(description, tokens):
  if 'access_token' not in tokens:
    return {}
  payload={}
  headers = {
    'Authorization': 'Bearer '+ access_token
  }
  response = requests.request("GET", description['userinfo_url'], headers=headers, data=payload)
  print(response.text)
  data = response.json()
  userinfo = {}
  userinfo['name'] = data['name'] if 'name' in data else ''
  if 'given_name' in data:
    userinfo['given_name'] = data['given_name']
  elif 'givenname' in data:
    userinfo['given_name'] = data['givenname']
  else:
    userinfo['given_name'] = ''
  if 'family_name' in data:
    userinfo['family_name'] = data['family_name']
  elif 'familyname' in data:
    userinfo['family_name'] = data['familyname']
  else:
    userinfo['family_name'] = ''
  userinfo['email'] = data['email'] if 'email' in data else ''
  userinfo['birthdate'] = data['birthdate'] if 'birthdate' in data else '' 
  return userinfo


def decode_id_token(token):
  return jwt.decode(token, options={"verify_signature": False})


def get_directory():
  directory = {
    'azuread_secret': {
      'idp': 'Azure AD',
      'name': 'Azure AD Secret',
      'tenant_id': '37530da3-f7a7-48f4-ba46-2dc336d55387',
      'client_id': 'ec77399e-41d1-437c-ba0f-d3f5d41db75b',
      'client_secret': '',
      'response_type': 'code'
    },
    'azuread_implicit': {
      'idp': 'Azure AD',
      'name': 'Azure AD Implicit - Personal',
      'tenant_id': '1c18d30e-d06b-42c3-87d3-06474fbdecd6',
      'client_id':'e42162b4-60b2-4124-9e7e-dcaf8668bfea',
      'response_type': 'id_token'
    },
    'azuread_pkce': {
      'idp': 'Azure AD',
      'name': 'Azure AD PKCE',
      'tenant_id': '1c18d30e-d06b-42c3-87d3-06474fbdecd6',
      'client_id': 'd2906235-e0f0-4dc7-afd8-63c20ab97632',
      'response_type': 'code',
      'code_challenge': get_code_challenge(),
      'code_verifier': CODE_VERIFIER
    },
    'okta_implicit': {
      'idp': 'Okta',
      'name': 'Okta Implicit - Personal',
      'url': 'https://dev-13832984.okta.com',
      'client_id':'0oa9j2nqbhyaXR81C5d7',
      'response_type': 'id_token'
    },

  }

  for key,description in directory.items():
    description['auth_url'] = get_auth_link(key, description)
    if description['idp'] == 'Azure AD':
      tenant_id = description['tenant_id']
      description['token_url'] = 'https://login.microsoftonline.com/'+tenant_id+'/oauth2/v2.0/token'
      description['userinfo_url'] = 'https://graph.microsoft.com/oidc/userinfo'

  return directory


def get_auth_link(key, description):
  if description['idp'] == 'Azure AD':
    url = 'https://login.microsoftonline.com/'+description['tenant_id']+'/oauth2/v2.0/authorize'
  else:
    url = 'https://dev-13832984.okta.com/oauth2/default/v1/authorize'
  params = {
    'client_id': description['client_id'],
    'response_type': description['response_type'],
    'response_mode': 'form_post',
    'scope': 'openid profile email',
    'nonce': '678910',
    'redirect_uri': REDIRECT_URI,
    'state': urllib.parse.urlencode({'idp': key})
  }

  if 'code_challenge' in description:
    params['code_challenge'] = description['code_challenge']
    params['code_challenge_method'] = 'S256'

  return url+"?"+urllib.parse.urlencode(params)


def get_tokens(description, request):
  if description['response_type'] != 'code':
    return extract_tokens(request.form)    

  headers = {}
  payload={
    'grant_type': 'authorization_code',
    'code': request.form['code'],
    'redirect_uri': REDIRECT_URI,
    'client_id': description['client_id']
  }
  if 'client_secret' in description:
    payload['client_secret'] = description['client_secret']
  if 'code_verifier' in description:
    payload['code_verifier'] = description['code_verifier']
    headers['Origin'] = 'http://localhost'
  response = requests.request("POST", description['token_url'], headers=headers, data=payload)
  return extract_tokens(response.json())


def get_code_challenge():
  code_challenge = hashlib.sha256(CODE_VERIFIER.encode('ascii')).digest()
  code_challenge = base64.urlsafe_b64encode(code_challenge).rstrip(b'=').decode('ascii')
  return code_challenge


def extract_tokens(source):
  tokens = {}
  if 'access_token' in source:
    tokens['access_token'] = source['access_token']
  if 'id_token' in source:
    tokens['id_token'] = source['id_token']
  return tokens


