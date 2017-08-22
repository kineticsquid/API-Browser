"""
Browser to allow one to navigate Bluemix CF API. Authentication is IBM id, but not w3id federated IDs.

See readme.md
"""

"""
Setting FLASK_DEBUG=1 environment variable to enable debugging and auto reloading of changed files
"""
import json
import re
import os
import random
import requests
from flask import Flask, request, render_template, make_response, session, redirect
from functools import wraps



app = Flask(__name__)

PORT = '5000'
USERNAME_KEY = 'username'
PASSWORD_KEY = 'password'
REGION_KEY = 'region'
REDIRECT_KEY = 'redirect'
AUTHORIZATION_HEADER_KEY = 'Authorization'
BLUEMIX_REGIONS = ['api.ng.bluemix.net',
                   'api.eu-gb.bluemix.net',
                   'api.eu-de.bluemix.net',
                   'api.au-syd.bluemix.net']

"""
Custom exception to surface HTTP status codes
"""
class AppHTTPError(Exception):
    def __init__(self, code, message):
        self.code = code
        self.message = message
    def __str__(self):
        return repr('%s - %s' % (self.code,self.message))

"""
Method to define and return a logger for logging
"""
import logging
import sys

def get_my_logger():
    logger = logging.getLogger('My Logger')
    logger.setLevel(logging.INFO)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(threadName)s - %(message)s', "%H:%M:%S")
    ch.setFormatter(formatter)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    return logger

"""
Method to display an error page given various errors
"""
def display_error_page(error, **kwargs):
    error_message = kwargs.get('error_message', None)
    log_message = kwargs.get('log_message', None)
    if error == 404:
        if error_message is None:
            error_message = 'Hmmm... not sure where you\'re trying to go.'
        image_file = '404.jpeg'
    elif error == 403:
        if error_message is None:
            error_message = 'You need better connections.'
        image_file = '403.jpeg'
    else:
        if error_message is None:
            error_message = 'Bad, bad server error: %s' % str(error)
        image_file = 'any_error.jpeg'
    if log_message is None:
        log_message = error_message
    logger.info('Error %s: %s' % (str(error),log_message))
    return render_template('error.html', image_file=image_file, error_message=error_message)


"""
Routine to generate the secret key needed to use the Flask session object
"""
def generate_secret_key():
    secret_key = ''
    for i in range(0, 50):
        char = chr(random.randint(0, 255))
        secret_key += char
    return secret_key


"""
Routine to authenticate to Bluemix using IBMid, returns a bearer token
"""

def bluemix_auth(bluemix_api_endpoint, **kwargs):
    global AUTHORIZATION_HEADER_KEY

    if 'userid' in kwargs:
        ibm_id = kwargs['userid']
    else:
        ibm_id = os.getenv('IBM_ID')
        if ibm_id is None:
            raise Exception('IBM_ID environment variable not defined.')
    if 'password' in kwargs:
        ibm_id_pw = kwargs['password']
    else:
        ibm_id_pw = os.getenv('IBM_ID_PW')
        if ibm_id_pw is None:
            raise Exception('IBM_ID_PW environment variable not defined.')
    info_endpoint = '/info'
    oauth_endpoint = '/oauth/token'

    response = requests.get(bluemix_api_endpoint + info_endpoint)

    if response.status_code == 200:
        results = response.json()
        auth_endpoint = results['authorization_endpoint'] + oauth_endpoint
        http_headers = {
            AUTHORIZATION_HEADER_KEY: 'Basic Y2Y6'
        }
        http_payload = {
            'grant_type': 'password',
            'username': ibm_id,
            'password': ibm_id_pw
        }
        response = requests.post(auth_endpoint, data=http_payload, headers=http_headers)

        if response.status_code == 200:
            results = response.json()
            authorization = results['token_type'] + ' ' + results['access_token']
            http_headers = {
                # 'accept': '*/*',
                # 'content-type': 'application/json;charset=utf-8',
                # 'content-type': 'application/json',
                AUTHORIZATION_HEADER_KEY: authorization
            }
            return http_headers
        else:
            raise AppHTTPError(response.status_code, 'Error getting bearer token: %s' % response.content)
    else:
        raise AppHTTPError(response.status_code, 'Error getting bearer token: %s' % response.content)

"""
Routine to get all results from a Bluemix CF API call by handling paging
"""

def get_all_bluemix_results(url, http_headers):
    all_results = []
    while url is not None:
        response = requests.get(url, headers=http_headers)
        if response.status_code == 200:
            http_results = response.json()
            results = http_results.get('resources', None)
            if results is not None:
                # results key is returned if the response is a list
                all_results += results
                next_url = http_results['next_url']
                if next_url is not None:
                    index = url.find(next_url[0:3])
                    url = url[0:index] + next_url
                else:
                    url = None
            else:
                # if there is no results key, just a single result, so return it.
                all_results.append(http_results)
                url = None
        else:
            raise AppHTTPError(response.status_code, 'Error getting results from %s: %s' %
                            (url, response.content))
    return all_results

"""
Method to transform JSON results to a formatted string, including hrefs for display using <pre> tags
"""
def get_disp_content(api_results, region):
    if len(api_results) == 1:
        output = '%s result:\n\n' % str(len(api_results))
    else:
        output = '%s results:\n\n' % str(len(api_results))
    for r in api_results:
        displayable_content = json.dumps(r, indent=4)
        displayable_content_with_links = add_links(displayable_content, region)
        output += displayable_content_with_links
    return output

"""
Routine to add href links to URLs enbedded in the JSON returned nby the CF api. 
"""

def add_links(json_results, region):
    api_url_regex = '\"\/v2\/\S+\"'
    matches = re.findall(api_url_regex, json_results)
    i = 1
    for match in matches:
        url = match.replace('"', '')
        href = '<a href="/%s%s">%s</a>' % (region, url, match)
        json_results = json_results.replace(match, href)
        i += 1
    return json_results


"""
Method to check for referrer header to prevent someone from going directly to the login url. We want them to come from 
the main page and click one of the links there. Slightly separate logic for running locally vs in Bluemix. Note in
both cases the server address is 0.0.0.0. Presence of VCAP_APPLICATION environment variable indicates we're in
Bluemix
"""

def check_referer(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        referer = request.environ.get('HTTP_REFERER', None)
        if referer is None:
            return display_error_page(404, log_message='Attempt to login with no HTTP_REFERER.')
        if vcap_application is None:
            server = request.environ.get('SERVER_NAME', None)
            if server is None:
                return display_error_page(404, log_message='Attempt to login with no SERVER_NAME.')
            else:
                if server not in referer:
                    return display_error_page(404, log_message='HTTP_REFERER and SERVER_NAME do not match: %s %s.' % (
                    referer, server))
        else:
            uris = vcap_application.get('uris', None)
            valid_referer = False
            for uri in uris:
                if uri.lower() in referer:
                    valid_referer = True
                    break
            if not valid_referer:
                return display_error_page(404, log_message='HTTP_REFERER not a valid URI: %s %s.' % (referer, uris))
        return function(*args, **kwargs)

    return wrapper


"""
Method to check to see if the user has authenticated to one of the regions
"""

def check_login(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        logged_in = False
        for key in session.keys():
            if key in BLUEMIX_REGIONS:
                logged_in = True
                break
        if not logged_in:
            return display_error_page(500, error_message='Ya gotta be logged in to try this.')
        else:
            return function(*args, **kwargs)

    return wrapper

"""
Method to force https when http is specified.
"""
@app.before_request
def force_https():
    # We want to redirect the request to use https. We only want this
    # redirect if we're running in Bluemix because it'll fail running locally
    if request.endpoint in app.view_functions:
        forwarded_protocol = request.headers.get('X-Forwarded-Proto', None)
        if forwarded_protocol == 'http':
            new_url = request.url.replace('http://', 'https://')
            logger.info('Redirecting from %s to %s.' % (request.url, new_url))
            return redirect(new_url)


@app.errorhandler(Exception)
def handle_bad_request(e):
    return display_error_page(500, error_message=str(e))

@app.route('/')
def Welcome():
    # todo: Replace Flask session with Redis use - question on dw answers
    # todo: Once we have Redis in place, spin up multiple instances and test
    return render_template('results.html', modalstyle='modal-hidden')

@app.route('/test')
# @check_login
# Route for testing purposes only
def Test():
    session_str = json.dumps(dict(session), indent=4)
    u = request.url
    a = request.authorization
    r = request
    output_string = '\nUrl: \n%s\n\nAuth: \n%s\n\nSession: \n%s\n\n' % (u, a, session_str)
    output_string += '\nVCAP_SERVICES: \n%s\n\nVCAP_APPLICATION: \n%s\n\nHTTP_REFERER: \n%s\n\nSERVER_NAME: \n%s\n' % \
                    (json.dumps(vcap_services, indent=4), json.dumps(vcap_application, indent=4),
                     request.environ.get('HTTP_REFERER', None),
                     request.environ.get('SERVER_NAME', None))
    return render_template('test.html', content=output_string)

@app.route('/error/<string:str>')
@check_login
# Route for testing error handler
def Error(str):
    raise Exception(str)

@app.route('/<path:api_path>')
def Handle_Everything_Else(api_path):
    # regex to recognize a Bluemix API domain
    region_regex = 'api\.\S*\.bluemix\.net'
    re_region = re.compile(region_regex)
    # regex to recognize a Bluemix API URL call
    api_regex = '\S+\/v2\/\S*'
    re_api = re.compile(api_regex)
    region_hits = re_region.match(api_path)
    api_hits = re_api.match(api_path)
    # Get the region, and if we don't find one or it's not one we recognize, return a 404
    if region_hits is not None:
        region = region_hits.group()
        if region not in BLUEMIX_REGIONS:
            return display_error_page(404, log_message='Unrecognized region: \'%s\' in \'%s\'.' % (region, api_path))
    else:
        return display_error_page(404, log_message='No region found in \'%s\'.' % api_path)
    if api_hits is not None:
        api = api_hits.group()
    else:
        api = None

    # if we don't find the region in the session object, it means that the user is not authenticated to this region.
    # In which case, cause the login modal prompt to be displayed and set the redirect
    if region not in session:
        if api is None:
            return render_template('results.html', redirect=region, region=region, modalstyle='modal')
        else:
            return render_template('results.html', redirect=api, region=region, modalstyle='modal')
    # otherwise, the user is authenticated to this region.
    else:
        # if only the region is sent (not CF API call), display a page with links to make top level CF API calls.
        if api is None:
            # this render statement adds the right region to the hrefs
            initial_links = render_template('initial-content.html', region=region)
            initial_page = render_template('results.html', title=region, region=region, content=initial_links,
                                           modalstyle='modal-hidden')
            resp = make_response(initial_page, 200)
            return resp
        # otherwise, this is a CF API call. Get the bearer token from the session object. Set the HTTP header with the
        # auth information. Make the call and format and display the results.
        else:
            bearer_token = session[region]['Authorization']
            api_url = 'https://%s' % api
            try:
                api_results = get_all_bluemix_results(api_url, { 'Authorization': bearer_token})
                displayable_content_with_links = get_disp_content(api_results, region)
                page = render_template('results.html', title=api, region=region, content=displayable_content_with_links,
                                       modalstyle='modal-hidden')
                resp = make_response(page, 200)
                return resp
            except(Exception) as e:
                if type(e) is AppHTTPError:
                    return display_error_page(e.code, log_message=e.message)
                else:
                    return display_error_page(404, log_message=str(e))


@app.route('/login', methods=['POST'])
@check_referer
def Login():
    username = request.form[USERNAME_KEY]
    password = request.form[PASSWORD_KEY]
    bluemix_region = request.form[REGION_KEY]
    # get the redirect URL. If none, make it the main page for a region
    redirect_url = request.args.get(REDIRECT_KEY, None)
    if redirect_url is None:
        redirect_url = bluemix_region
    # Just in case, if there is no leading '/', add one
    if redirect_url[0] != '/':
        redirect_url = '/%s' % redirect_url
    # make the call to authenticate. Save the bearer token in the session object if successful. Then redirect to the
    # redirect URL. Otherwise, something went wrong, return a 403.
    try:
        authorization_header = bluemix_auth('https://%s' % bluemix_region, userid=username, password=password)
        if authorization_header is not None:
            session[bluemix_region] = authorization_header
            return redirect(redirect_url)
        else:
            return display_error_page(403, log_message='Username: \'%s\'.' % username)
    except Exception as e:
        return display_error_page(403, log_message='Username: \'%s\'.' % username)

port = os.getenv('PORT', PORT)
# This secret key is to encode the Flask session object
app.secret_key = generate_secret_key()
logger = get_my_logger()
logger.info('Starting....')
vcap_application = os.getenv('VCAP_APPLICATION')
if vcap_application is not None:
    vcap_application = json.loads(vcap_application)
    logger.info('VCAP_APPLICATION:')
    logger.info(json.dumps(vcap_application, indent=4))
    # these next two statements set logging level of the logger in Flask so that messages don't show up as errors in the
    # Bluemix logs. Only set this if running in Bluemix and not locally
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.INFO)
else:
    logger.info('No VCAP_APPLICATION environment variable')
vcap_services = os.getenv('VCAP_SERVICES')
if vcap_services is not None:
    vcap_services = json.loads(vcap_services)
    logger.info('VCAP_SERVICES:')
    logger.info(json.dumps(vcap_services, indent=4))
else:
    logger.info('No VCAP_SERVICES environment variable')
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=int(port))
