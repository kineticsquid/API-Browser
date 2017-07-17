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

PORT = '5000'
USERNAME_KEY = 'username'
PASSWORD_KEY = 'password'
REGION_KEY = 'region'
REDIRECT_KEY = 'redirect'
BLUEMIX_REGIONS = ['api.ng.bluemix.net',
                   'api.eu-gb.bluemix.net',
                   'api.eu-de.bluemix.net',
                   'api.au-syd.bluemix.net',
                   'api.stage1.bluemix.net']
AUTHORIZATION_HEADER_KEY = 'Authorization'

app = Flask(__name__)

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
            raise Exception('Error getting bearer token: %s %s' % (response.status_code, response.content))
    else:
        raise Exception('Error getting bearer token: %s %s' % (response.status_code, response.content))

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
                all_results += http_results['resources']
                next_url = http_results['next_url']
                if next_url is not None:
                    index = url.find(next_url[0:3])
                    url = url[0:index] + next_url
                else:
                    url = None
            else:
                # if there is no results key, just a single result, so return it.
                all_results = http_results
                url = None
        else:
            raise Exception('Error getting results from %s: %s %s' %
                            (url, response.status_code, response.content))
    return all_results

"""
Routine to add href links to URLs enbedded in the JSON returned nby the CF api. 
"""

def add_links(json_results, region):
    api_url_regex = '\"\/v2\/\S+\"'
    matches = re.findall(api_url_regex, json_results)
    for match in matches:
        url = match.replace('"', '')
        href = '<a href="/%s%s">%s</a>' % (region, url, match)
        json_results = json_results.replace(match, href)
    return json_results

@app.route('/')
def Welcome():
    return render_template('results.html', modalstyle='modal-hidden')


@app.route('/<path:api_path>')
def Handle_Everything_Else(api_path):
    # regex to recognize a Bluemix API domain
    region_regex = 'api\.\S*\.bluemix\.net'
    re_region = re.compile(region_regex)
    # regex to recognize a Bluemix API URL call
    api_regex = '\S+\/v2\/\S*'
    re_api = re.compile(api_regex)
    region_results = re_region.match(api_path)
    api_results = re_api.match(api_path)
    # Get the region, and if we don't find one or it's not one we recognize, return a 404
    if region_results is not None:
        region = region_results.group()
        if region not in BLUEMIX_REGIONS:
            return 'Duh', 404
    else:
        return 'Duh', 404
    if api_results is not None:
        api = api_results.group()
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
            initial_links = render_template('initial_content.html', region=region)
            initial_page = render_template('results.html', title=region, region=region, content=initial_links,
                                           modalstyle='modal-hidden')
            resp = make_response(initial_page, 200)
            return resp
        # otherwise, this is a CF API call. Get the bearer token from the session object. Set the HTTP header with the
        # auth information. Make the call and format and display the results.
        else:
            bearer_token = session[region]['Authorization']
            api_url = 'https://%s' % api
            api_results = get_all_bluemix_results(api_url, { 'Authorization': bearer_token})
            displayable_content = json.dumps(api_results, indent=4)
            # add the href links to the API URLs found in the JSON results
            displayable_content_with_links = add_links(displayable_content, region)

            page = render_template('results.html', title=api, region=region, content=displayable_content_with_links,
                                           modalstyle='modal-hidden')
            resp = make_response(page, 200)
            return resp


@app.route('/login')
def Login():
    # information to log the user into a region
    username = request.args[USERNAME_KEY]
    password = request.args[PASSWORD_KEY]
    bluemix_region = request.args[REGION_KEY]
    # get the redirect URL. If none, make it the main page for a region
    redirect_url = request.args.get(REDIRECT_KEY, None)
    if redirect_url is None:
        redirect_url = bluemix_region
    # Just in case, if there is no leading '/', add one
    if redirect_url[0] is not '/':
        redirect_url = '/%s' % redirect_url
    # make the call to authenticate. Save the bearer token in the session object if successful. Then redirect to the
    # redirect URL. Otherwise, something went wrong, return a 403.
    try:
        authorization_header = bluemix_auth('https://%s' % bluemix_region, userid=username, password=password)
        if authorization_header is not None:
            session[bluemix_region] = authorization_header
            return redirect(redirect_url)
        else:
            return 'Doh', 403
    except Exception as e:
        return str(e), 403


port = os.getenv('PORT', PORT)
app.secret_key = generate_secret_key()
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=int(port))