# -*- coding: utf-8 -*-

import os
import flask
import requests
import re
import json
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
from flask import Flask, request, render_template
import pickle
import os.path
import flask
import google_auth_oauthlib
from flask import request
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
import re
import mysql.connector
# This variable specifies the name of a file that contains the OAuth 2.0
# information for this application, including its client_id and client_secret.
CLIENT_SECRETS_FILE = "credentials.json"

# This OAuth 2.0 access scope allows for full read/write access to the
# authenticated user's account and requires requests to use an SSL connection.
SCOPES = ['https://www.googleapis.com/auth/userinfo.profile',
          'https://www.googleapis.com/auth/userinfo.email',
          'https://www.googleapis.com/auth/gmail.readonly',
          'https://www.googleapis.com/auth/gmail.modify',
          'https://www.googleapis.com/auth/drive.metadata.readonly',
          'https://mail.google.com/']
API_SERVICE_NAME = 'gmail'
API_VERSION = 'v1'

app = flask.Flask(__name__)
# Note: A secret key is included in the sample so that it works.
# If you use this code in your application, replace this with a truly secret
# key. See https://flask.palletsprojects.com/quickstart/#sessions.
app.secret_key = 'buf1gUDQkej8GY9hE5pYGC7O'


@app.route('/')
def index():
  return print_index_table()\


@app.route('/test')
def test_api_request():
  #if 'credentials' not in flask.session:
  #  return flask.redirect('authorize')
  db = mysql.connector.connect(host="localhost",  # your host, usually localhost
                       user="root",  # your username
                       passwd="",  # your password
                       db="suividelist")  # name of the data base
  cur = db.cursor()
  cur.execute("select * FROM boite WHERE mailer_id=1;")
  myresult = cur.fetchall()
  boite_list = []
  for boite in myresult :
  # Load credentials from the session.
      dbtoken = eval(boite[5])
      credentials = google.oauth2.credentials.Credentials(**dbtoken)
      service = googleapiclient.discovery.build('gmail', 'v1', credentials=credentials)
      service_oauth2 = googleapiclient.discovery.build('oauth2', 'v2', credentials=credentials)
      user_info = service_oauth2.userinfo().get().execute()
      boite_content = []

      message_list = []
      boite_content.append(user_info['email'])
      list1 = service.users().messages().list(userId=user_info['id'], maxResults=3).execute()
      x = list1['messages']

      for i in x:
          message = []
          labels = []
          ips = []
          user_msg = service.users().messages().get(userId=user_info['id'], id=i['id'], ).execute()
          labelslist = user_msg['labelIds']
          for label in labelslist:
              labels.append(label)
          message.append(labels)

          filtre = user_msg['payload']['headers']
          for i in filtre:
              if i['name'] == 'Subject':
                  subject = i['value']
              if i['name'] == 'Received':
                  ipvalue = re.search(
                      r"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)", i['value'])
                  if ipvalue is not None:
                      ips.append(ipvalue.group(0))
          message.append(subject)
          message.append(ips)
          message_list.append(message)
      boite_content.append(message_list)
      boite_list.append(boite_content)
  # Save credentials back to session in case access token was refreshed.
  # ACTION ITEM: In a production app, you likely want to save these
  #              credentials in a persistent database instead.
  #flask.session['credentials'] = credentials_to_dict(credentials)
  return display(boite_list)

def display(boite_list):
    #return render_template('display.html', boite_list=boite_list)
    #return flask.jsonify(boite_list)
    html = '<!DOCTYPE html><html><head><link rel="stylesheet" href="mystyle.css"></head><body>'
    html += '<div class="container" style="margin-top: 100px"> '
    html +='	<div class="row">'
    html +='		<div class="table-wrap">'
    html +='			<table data-address="" class="result-table">'
    html +='				<tbody id="tbodyedit">        '
    for boite_centent in boite_list:
        html +='                    <div  class ="email">' + str(boite_centent[0])
        for message_list in boite_centent[1]:
            html += '				<ul>       '
            html += '<li style = "position: relative; height: 125px; vertical-align:top; background-color: #D4D9B2" class ="">'
            html +='</div><div  class ="subject"> ' + str(message_list[1])
            html +=' </div>'
            html +='                    <div class ="time"> '  + str(message_list[2])
            html +='                </div>    <div class ="result-label">'
            html +='                    <span  class ="result Spam"> ' + str(message_list[0])
            html +='</span>             </div>'
            html += '                   </li> '
            html +='				</ul>'
    html +='				</tbody>'
    html += '			</table>'
    html += '		</div>'
    html += '	</div>'
    html += '</div>'
    html += '</body>'
    html += '</html>'
    return html

@app.route('/authorize')
def authorize():
  # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps.
  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES)

  # The URI created here must exactly match one of the authorized redirect URIs
  # for the OAuth 2.0 client, which you configured in the API Console. If this
  # value doesn't match an authorized URI, you will get a 'redirect_uri_mismatch'
  # error.
  flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

  authorization_url, state = flow.authorization_url(
      # Enable offline access so that you can refresh an access token without
      # re-prompting the user for permission. Recommended for web server apps.
      access_type='offline',
      prompt='consent',
      # Enable incremental authorization. Recommended as a best practice.
      include_granted_scopes='false')

  # Store the state so the callback can verify the auth server response.
  flask.session['state'] = state

  return flask.redirect(authorization_url)


@app.route('/oauth2callback')
def oauth2callback():
  # Specify the state when creating the flow in the callback so that it can
  # verified in the authorization server response.
  state = flask.session['state']

  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
  flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

  # Use the authorization server's response to fetch the OAuth 2.0 tokens.
  authorization_response = flask.request.url
  flow.fetch_token(authorization_response=authorization_response)

  # Store credentials in the session.
  # ACTION ITEM: In a production app, you likely want to save these
  #              credentials in a persistent database instead.
  credentials = flow.credentials
  flask.session['credentials'] = credentials_to_dict(credentials)
  service_oauth2 = googleapiclient.discovery.build('oauth2', 'v2', credentials=credentials)
  user_info = service_oauth2.userinfo().get().execute()
  db = mysql.connector.connect(host="localhost",  # your host, usually localhost
                       user="root",  # your username
                       passwd="",  # your password
                       db="suividelist")  # name of the data base
  cur = db.cursor()

  sql = "INSERT IGNORE  INTO boite (email,mailer_id,user_id,img,code) VALUES (%s, %s, %s, %s, %s)"
  val = (user_info['email'], "1", user_info['id'], str(user_info['picture']), str(flask.session['credentials']))
  cur.execute(sql, val)
  db.commit()

  return flask.redirect(flask.url_for('test_api_request'))


@app.route('/revoke')
def revoke():
  if 'credentials' not in flask.session:
    return ('You need to <a href="/authorize">authorize</a> before ' +
            'testing the code to revoke credentials.')

  credentials = google.oauth2.credentials.Credentials(
    **flask.session['credentials'])

  revoke = requests.post('https://oauth2.googleapis.com/revoke',
      params={'token': credentials.token},
      headers={'content-type': 'application/x-www-form-urlencoded'})

  status_code = getattr(revoke, 'status_code')
  if status_code == 200:
    return('Credentials successfully revoked.' + print_index_table())
  else:
    return('An error occurred.' + print_index_table())


@app.route('/clear')
def clear_credentials():
  if 'credentials' in flask.session:
    del flask.session['credentials']
  return ('Credentials have been cleared.<br><br>' +
          print_index_table())


def credentials_to_dict(credentials):
  return {'token': credentials.token,
          'refresh_token': credentials.refresh_token,
          'token_uri': credentials.token_uri,
          'client_id': credentials.client_id,
          'client_secret': credentials.client_secret,
          'scopes': credentials.scopes}



def print_index_table():
  return ('<table>' +
          '<tr><td><a href="/test">Test an API request</a></td>' +
          '<td>Submit an API request and see a formatted JSON response. ' +
          '    Go through the authorization flow if there are no stored ' +
          '    credentials for the user.</td></tr>' +
          '<tr><td><a href="/authorize">Test the auth flow directly</a></td>' +
          '<td>Go directly to the authorization flow. If there are stored ' +
          '    credentials, you still might not be prompted to reauthorize ' +
          '    the application.</td></tr>' +
          '<tr><td><a href="/revoke">Revoke current credentials</a></td>' +
          '<td>Revoke the access token associated with the current user ' +
          '    session. After revoking credentials, if you go to the test ' +
          '    page, you should see an <code>invalid_grant</code> error.' +
          '</td></tr>' +
          '<tr><td><a href="/clear">Clear Flask session credentials</a></td>' +
          '<td>Clear the access token currently stored in the user session. ' +
          '    After clearing the token, if you <a href="/test">test the ' +
          '    API request</a> again, you should go back to the auth flow.' +
          '</td></tr></table>')



if __name__ == '__main__':
  # When running locally, disable OAuthlib's HTTPs verification.
  # ACTION ITEM for developers:
  #     When running in production *do not* leave this option enabled.
  os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
  os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'
  # Specify a hostname and port that are set as a valid redirect URI
  # for your API project in the Google API Console.
  app.run('localhost', 5000, debug=True)