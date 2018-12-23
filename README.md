# CF API Browser

Simple Python application using Flask to allow one to browse artifacts in a Bluemix account using the CF API. Authentication is through IBMid.

Current URL: []http://169.61.113.149:31788/](http://169.61.113.149:31788/)

Run command `kubectl describe service cf-api-browser` to get IP (public Nodeport)


[CF API documentation](https://apidocs.cloudfoundry.org/)

Setting FLASK_DEBUG=1 environment variable to enable debugging and auto reloading of changed files

Also, needed to all Python requests package to requirements.txt otherwise app fails on startup.

General info on setting up SSL:
http://www.howto-expert.com/how-to-get-https-setting-up-ssl-on-your-website/

Notes in implementing HTTPS
1. Secure a custom domain name and define it to Bluemix: https://developer.ibm.com/answers/questions/8855/how-to-get-your-custom-domain-up-and-running.html.
1. Add a custom route to the app in Bluemix using the custom domain. This is on the app page under the "Routes" tab.
1. Make changes at domain name provider to route custom domain name to bluemix app domain name (*.mybluemix.net)
1. Requested an SSL certificate from GoDaddy. To set this up GD wants my CSR.
1. Generated a CSR with the following: 
    - `openssl req -new -newkey rsa:2048 -nodes -keyout cf-api-browser.johnkellerman.me.key -out cf-api-browser.johnkellerman.me.csr`
1. Set up the certificate at godaddy by copying the contents of the *.csr file.
1. Next, need to look for email from godaddy with a code in it... need to get the actual certificate to upload to bluemix

Info on forcing HTTPS:
  - https://developer.ibm.com/answers/questions/16016/how-do-i-enforce-ssl-for-my-bluemix-application.html
  - https://github.com/kennethreitz/flask-sslify

According to the first article and verified in the code through the $WSSC header, HTTP and HTTPS come into the app
as HTTP. the $WSSC header value specifies the protocol specified by the user.

Primer on Python decorators:
https://realpython.com/blog/python/primer-on-python-decorators/

Info on connection to Redis from Python:
https://github.com/andymccurdy/redis-py
