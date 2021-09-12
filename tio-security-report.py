import urllib.request
from urllib.error import HTTPError
import ssl
import json
from configparser import ConfigParser
from argparse import ArgumentParser
from getpass import getpass
from csv import DictWriter

config = ConfigParser()
config.read('tenable.ini')
arguments = ArgumentParser(description='Tenable.io security report')
arguments.add_argument('-p', '--proxy', metavar='127.0.0.1:8080', default=None, dest='proxy', help='HTTPS proxy')
arguments.add_argument('-i', '--insecure', action='store_false', dest='verify', default=True,
                       help='Disable SSL verification')
arguments = arguments.parse_args()
proxy = arguments.proxy
verify = arguments.verify


def request(method, endpoint, headers=None, data=None, proxy=proxy, verify=verify):
    request_ = urllib.request.Request('https://cloud.tenable.com' + endpoint)
    request_.method = method
    request_.add_header('accept', 'application/json')
    request_.add_header('content-type', 'application/json')
    context = ''
    if headers:
        for key, value in headers.items():
            request_.add_header(key, value)
    if data:
        request_.data = json.dumps(data).encode()
    if proxy:
        request_.set_proxy(proxy, 'https')
    if verify is False:
        # https://www.python.org/dev/peps/pep-0476
        context = ssl._create_unverified_context()
    try:
        response = urllib.request.urlopen(request_, context=context)
        return response
    except HTTPError as error:
        print('\nERROR: HTTP ' + str(error.code))
        print(error.reason)


def logout():
    if auth == 'local':
        request('DELETE', '/session', headers)
    else:
        pass


if 'tenable_io' in config:
    if 'access_key' in config['tenable_io'] and 'secret_key' in config['tenable_io']:
        auth = 'api'
        headers = {"x-apikeys": "accessKey=" + config['tenable_io']['access_key'] + ';secretKey=' +
                                config['tenable_io']['secret_key']}
else:
    username = input('Username: ')
    password = getpass()
    auth = 'local'
    response = request(
        method='POST',
        endpoint='/session',
        data={
            "username": username,
            "password": password
        },
        proxy=proxy,
        verify=verify
    )
    if 'two_factor' in json.load(response):
        two_factor_token = getpass('Authentication code: ')
        response = request(
            method='POST',
            endpoint='/session',
            data={
                "username": username,
                "password": password,
                "two_factor_token": two_factor_token
            },
            proxy=proxy,
            verify=verify
        )
    headers = {"x-cookie": "token=" + json.load(response)['token']}

session = json.load(request('GET', '/session', headers))
if session['permissions'] != 64:
    print('ERROR: User is not an Administrator')
    logout()
    quit()

report = []
report_user = {}

users = json.load(request('GET', '/users', headers))
for user in users['users']:
    details = json.load(request('GET', '/users/' + str(user['id']), headers))
    authorizations = json.load(request('GET', '/users/' + str(user['id']) + '/authorizations', headers))
    if session['container_type'] == 'mssp':
        mssp_accounts = json.load(request('GET', '/mssp/accounts/childContainers/' + user['uuid'], headers))
    else:
        mssp_accounts = None

    if 'name' in user:
        report_user['name'] = user['name']
    else:
        report_user['name'] = ''
    report_user['username'] = user['username']
    if 'email' in user:
        report_user['email'] = user['email']
    else:
        report_user['email'] = ''
    report_user['enabled'] = details['enabled']
    report_user['permissions'] = user['permissions']
    if mssp_accounts is not None:
        report_user['mssp_accounts'] = len(mssp_accounts)
    else:
        report_user['mssp_accounts'] = 'N/A'
    report_user['password_permitted'] = authorizations['password_permitted']
    if 'two_factor' in details:
        report_user['two_factor_enabled'] = True
    else:
        report_user['two_factor_enabled'] = False
    report_user['api_permitted'] = authorizations['api_permitted']
    report_user['saml_permitted'] = authorizations['saml_permitted']
    if (session['container_type'] == 'mssp' and
        report_user['enabled'] and
        report_user['permissions'] >= 32 and
        report_user['mssp_accounts'] > 0 and
        not report_user['two_factor_enabled']):
        report_user['notes'] = 'CRITICAL: This is a powerful account with weak authentication'
    else:
        report_user['notes'] = ''

    report.append(report_user.copy())

keys = report[0].keys()
with open('tio_security_report.csv', mode='w') as csv_file:
    dict_writer = DictWriter(csv_file, fieldnames=report[0].keys())
    dict_writer.writeheader()
    dict_writer.writerows(report)

logout()
