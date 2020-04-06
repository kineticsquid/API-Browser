"""
Browser to allow one to navigate IBM Cloud API. Authentication is IBM id, but not w3id federated IDs.
Define and use an APIKEY to access. Either specify at the login prompt or define APIKEYs to environment variables.
Setting FLASK_DEBUG=1 environment variable to enable debugging and auto reloading of changed files
"""
import json
import logging
import os
import os.path
import re
import sys
import time
from datetime import timedelta
from functools import wraps
import requests
from flask import Flask, request, render_template, make_response, session, redirect
# from flask_sslify import SSLify

app = Flask(__name__)

API_BROWSER_DEBUG = 'API_BROWSER_DEBUG'
os.environ[API_BROWSER_DEBUG] = 'Y'

SESSION_EXPIRATION_IN_SECONDS = 3600
USERNAME_KEY = 'username'
APIKEY_KEY = 'api_key'
APIKEYS_KEY = 'apikeys'
SERVICEIDS_KEY = 'serviceids'
DOMAIN_KEY = 'domain'
REDIRECT_KEY = 'redirect'
AUTHORIZATION_HEADER_KEY = 'Authorization'

RESOURCE_CONTROLLER = 'resource-controller'
CLOUD_DOMAIN = 'cloud.ibm.com'
TEST_CLOUD_DOMAIN = 'test.cloud.ibm.com'
IAM_DOMAIN = 'iam.cloud.ibm.com'
TEST_IAM_DOMAIN = 'iam.test.cloud.ibm.com'

PPRD_APIKEY_KEY = 'PPRD_APIKEY'
PSTG_APIKEY_KEY = 'PSTG_APIKEY'

URL_ROOT_KEY = 'URL_ROOT'

url_root = os.environ.get(URL_ROOT_KEY, None)
if url_root is None:
    url_root = ''

"""
Custom exception to surface HTTP status codes
"""


class AppHTTPError(Exception):
    def __init__(self, code, message):
        self.code = code
        self.message = message

    def __str__(self):
        return repr('%s - %s' % (self.code, self.message))


"""
Method to define and return a logger for logging
"""


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
    logger.info('Error %s: %s' % (str(error), log_message))
    return render_template('error.html', image_file=image_file, error_message=error_message, url_root=url_root)


"""
Routine to authenticate to Bluemix using IBMid, returns a bearer token
"""


def bluemix_auth(api_endpoint, apikey):
    global AUTHORIZATION_HEADER_KEY

    http_headers = {'Content-Type': 'application/x-www-form-urlencoded',
                    'Accept': 'application/json'}
    data = {'grant_type': 'urn:ibm:params:oauth:grant-type:apikey',
            'apikey': apikey}
    if TEST_CLOUD_DOMAIN in api_endpoint:
        response = requests.post('https://%s/identity/token' % TEST_IAM_DOMAIN, headers=http_headers, data=data)
    else:
        response = requests.post('https://%s/identity/token' % IAM_DOMAIN, headers=http_headers, data=data)
    if response.status_code == 200:
        results = response.json()
        authorization = results['token_type'] + ' ' + results['access_token']
        http_headers = {
            AUTHORIZATION_HEADER_KEY: authorization
        }
        return http_headers
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
            if APIKEYS_KEY in url:
                results = http_results.get(APIKEYS_KEY)
            else:
                if SERVICEIDS_KEY in url:
                    results = http_results.get(SERVICEIDS_KEY, None)
                else:
                    results = http_results.get('resources', None)
            if results is not None:
                # results key is returned if the response is a list
                all_results += results
                if APIKEYS_KEY in url or SERVICEIDS_KEY in url:
                    next_url = http_results.get('next', None)
                else:
                    next_url = http_results.get('next_url', None)
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
Routine to add href links to URLs embedded in the JSON returned nby the CF api. 
"""


def add_links(json_results, region):
    # Add hrefs for links of this form: "/v2/service_instances/b51f1a24-9395-46f1-a004-f1632f75e4f7"
    api_url_regex = '\"\/v2\/\S+\"'
    matches = re.findall(api_url_regex, json_results)
    for match in matches:
        url = match.replace('"', '')
        href = '<a href="%s/resource-controller.%s%s">%s</a>' % (url_root, region, url, match)
        json_results = json_results.replace(match, href)

    # Add hrefs for links of this form: "https://www.ibm.com/smarterplanet/us/en/ibmwatson/developercloud/nl-classifier-dashboard.html"
    http_url_regex = '\"https*:\/\/\S+\"'
    matches = re.findall(http_url_regex, json_results)
    for match in matches:
        url = match.replace('"', '')
        href = '<a href=%s target="_blank">%s</a>' % (match, match)
        json_results = json_results.replace(match, href)

    # Now add emphasis for instance names to make the output more readable
    name_regex = '"name":\s*".+"'
    matches = re.findall(name_regex, json_results)
    for match in matches:
        bold = '<b><i>%s</b></i>' % match
        json_results = json_results.replace(match, bold)
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
        return function(*args, **kwargs)

    return wrapper


@app.before_request
def do_something_whenever_a_request_comes_in():
    url = request.url
    if os.environ[API_BROWSER_DEBUG] == 'Y':
        logger.info("Api-browser request: %s" % url)
        logger.info('Referer:\t%s' % request.headers.get('Referer'))
        logger.info('Environ:\t%s' % request.environ)
        logger.info('Path:\t%s' % request.path)
        logger.info('Full_path:\t%s' % request.full_path)
        logger.info('Script_root:\t%s' % request.script_root)
        logger.info('Url:\t%s' % request.url)
        logger.info('Base_url:\t%s' % request.base_url)
        logger.info('Url_root:\t%s' % request.url_root)
        logger.info('Scheme:\t%s' % request.scheme)

@app.errorhandler(Exception)
def handle_bad_request(e):
    return display_error_page(500, error_message=str(e))


@app.route('/')
def Welcome():
    return render_template('results.html', modalstyle='modal-hidden', url_root=url_root)


@app.route('/printenv')
def printenv():
    output = 'Environment Variables:'
    for key in os.environ.keys():
        output = '%s\n%s - %s' % (output, key, os.environ.get(key))
    return render_template('blank.html', message=str(output), title='Environment Variables', url_root=url_root)


@app.route('/build')
def build():
    return app.send_static_file('build.txt')


@app.route('/webwidget')
def webwidget():
    return render_template('webwidget.html', title='Webwidget ASoC Test', url_root=url_root)


@app.route('/echo', methods=['GET', 'POST'])
def echo():
    url = request.url
    output = 'URL: %s\n\n' % url
    form = request.form
    for key in form.keys():
        output = '%s\n%s - %s' % (output, key, form.get(key))
    return render_template('blank.html', message=str(output), title='Echo Input', url_root=url_root)


@app.route('/test')
# Route for testing purposes only
def Test():
    session_str = json.dumps(dict(session), indent=4)
    u = request.url
    a = request.authorization
    r = request
    output_string = '\nUrl: \n%s\n\nAuth: \n%s\n\nSession: \n%s\n\n' % (u, a, session_str)
    output_string += '\nHTTP_REFERER: \n%s\n\nSERVER_NAME: \n%s\n' % (request.environ.get('HTTP_REFERER', None),
                                                                      request.environ.get('SERVER_NAME', None))
    output_string += '\nSecret key for session: %s\n' % app.secret_key
    return render_template('test.html', content=output_string, url_root=url_root)


@app.route('/error/<string:str>')
# Route for testing error handler
def Error(str):
    raise Exception(str)


@app.route('/login', methods=['POST'])
@check_referer
def Login():
    apikey = request.form[APIKEY_KEY]
    bluemix_domain = request.form[DOMAIN_KEY]
    # get the redirect URL. If none, make it the main page for a domain
    redirect_url = request.args.get(REDIRECT_KEY, None)
    if redirect_url is None:
        redirect_url = bluemix_domain
    # Just in case, if there is no leading '/', add one
    if redirect_url[0] != '/':
        redirect_url = '%s/%s' % (url_root, redirect_url)
    else:
        redirect_url = '%s%s' % (url_root, redirect_url)
    # make the call to authenticate. Save the bearer token in the session object if successful. Then redirect to the
    # redirect URL. Otherwise, something went wrong, return a 403.
    try:
        authorization_header = bluemix_auth(bluemix_domain, apikey)
        if authorization_header is not None:
            session[bluemix_domain] = authorization_header
            return redirect(redirect_url)
        else:
            return display_error_page(403, log_message='Authentication error')
    except Exception as e:
        return display_error_page(403, log_message='Authentication error')


"""
Method (hack) to handle a short cut where we specify APIKEYs are environment variables.
"""
def login_for_apikeys_as_environment_variables():
    pprd_apikey = os.environ.get(PPRD_APIKEY_KEY, None)
    pstg_apikey = os.environ.get(PSTG_APIKEY_KEY, None)
    if pprd_apikey is not None:
        try:
            authorization_header = bluemix_auth(CLOUD_DOMAIN, pprd_apikey)
            if authorization_header is not None:
                session[CLOUD_DOMAIN] = authorization_header
            else:
                return display_error_page(403, log_message='Authentication error')
        except Exception as e:
            return display_error_page(403, log_message='Authentication error')
    if pstg_apikey is not None:
        try:
            authorization_header = bluemix_auth(TEST_CLOUD_DOMAIN, pstg_apikey)
            if authorization_header is not None:
                session[TEST_CLOUD_DOMAIN] = authorization_header
            else:
                return display_error_page(403, log_message='Authentication error')
        except Exception as e:
            return display_error_page(403, log_message='Authentication error')



@app.route('/logout', methods=['POST', 'GET'])
@check_referer
def Logout():
    for key in list(session):
        if key[0] != '_':
            session.pop(key, None)
    if url_root == '':
        return redirect('/')
    else:
        return redirect(url_root)


@app.route('/<path:request_path>')
def Handle_Everything_Else(request_path):
    full_path = request.full_path
    # Get the region, and if we don't find one or it's not one we recognize, return a 404
    if TEST_CLOUD_DOMAIN in request_path:
        domain = TEST_CLOUD_DOMAIN
    else:
        if CLOUD_DOMAIN in request_path:
            domain = CLOUD_DOMAIN
        else:
            return display_error_page(404, error_message='Invalid request \'%s\'.' % request_path)
    # Look to see if this is a call to the domain or an API call
    if '/v1' in request_path or '/v2' in request_path:
        api = request_path
    else:
        api = None

    # if we don't find the region in the session object, it means that the user is not authenticated
    # to this region. First, try logging on if environment variables are defined.
    if domain not in session:
        login_for_apikeys_as_environment_variables()
    # Now try again to look for credentials. If we don't find them, meaning no environment variables
    # were defined, cause the login modal prompt to be displayed and set the redirect
    if domain not in session:
        return render_template('results.html', redirect=full_path, domain=domain, modalstyle='modal', url_root=url_root)
    # otherwise, the user is authenticated to this region.
    else:
        # if only the region is sent, display a page with links to make top level API calls.
        if api is None:
            # this render statement adds the right region to the hrefs
            if TEST_CLOUD_DOMAIN in domain:
                initial_links = render_template('initial-content.html', domain=domain, url_root=url_root)
            else:
                initial_links = render_template('initial-content.html', domain=domain, url_root=url_root)
            initial_page = render_template('results.html', title=domain,
                                           domain=domain, content=initial_links,
                                           modalstyle='modal-hidden', url_root=url_root)
            resp = make_response(initial_page, 200)
            return resp
        # otherwise, this is an API. Get the bearer token from the session object.
        # Set the HTTP header with the auth information. Make the call and format
        # and display the results.
        else:
            bearer_token = session[domain]['Authorization']
            api_url = 'https:/%s' % full_path
            # api_url = 'https://%s' % api
            try:
                api_results = get_all_bluemix_results(api_url, {'Authorization': bearer_token})
                displayable_content_with_links = get_disp_content(api_results, domain)
                page = render_template('results.html', title=api, domain=domain, content=displayable_content_with_links,
                                       modalstyle='modal-hidden', url_root=url_root)
                resp = make_response(page, 200)
                return resp
            except(Exception) as e:
                if type(e) is AppHTTPError:
                    return display_error_page(e.code, log_message=e.message)
                else:
                    return display_error_page(404, log_message=str(e))

port = os.getenv('PORT', '5000')

if __name__ == "__main__":
    logger = get_my_logger()
    logger.info('Starting %s....' % sys.argv[0])
    logger.info('Build: %s' % time.ctime(os.path.getmtime(sys.argv[0])))
    logger.info('Python: ' + sys.version)
    logger.info('Environment Variables:')
    for key in os.environ.keys():
        logger.info('%s:\t%s' % (key, os.environ.get(key)))
    # Set session cookies to be permanent. We're doing this so we can set a shorter expiration. See @before_request.
    app.permanent_session_lifetime = timedelta(seconds=SESSION_EXPIRATION_IN_SECONDS)
    app.secret_key = '\n¨üdõ¿\x1a\x97\x96¤\x94¹ÃÊ$<\x13¼±Ç.e1Ø\x11>¹\nM¤|^u\x08P\x12!¦¯§\x13\x07\x95w\x90²-]L"'
    app.run(host='0.0.0.0', port=int(port))
    # app.run(host='0.0.0.0', port=int(port), ssl_context='adhoc')
    # app.run(host='0.0.0.0', port=int(port), ssl_context=('cert.pem', 'key.pem'))

    session.permanent = True

