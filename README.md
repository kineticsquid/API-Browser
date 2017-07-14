# CF API Browser

Simple Python application using Flask to allow one to browse artifacts in a Bluemix account using the CF API. Authentication is through IBMid.


[CF API documentation](https://apidocs.cloudfoundry.org/)

Setting FLASK_DEBUG=1 environment variable to enable debugging and auto reloading of changed files

http://www.howto-expert.com/how-to-get-https-setting-up-ssl-on-your-website/

Notes in implementing HTTPS
1. Requested an SSL certificate from GoDaddy. To set this up GD wants my CSR.
2. Here's info on generating a CSR for Bluemix. https://console.bluemix.net/docs/manageapps/secapps.html#securingapps
3. And an article on generating a CSR: https://developer.ibm.com/answers/questions/179640/how-to-generate-the-certificate-signing-request-cs.html