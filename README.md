# API Browser

Simple Python application using Flask to allow one to browse artifacts in a Bluemix account using the CF API. Authentication is through IBMid.


[CF API documentation](https://apidocs.cloudfoundry.org/)

[Resource Controller API](https://console.bluemix.net/apidocs/resource-controller)

[IAM API](https://cloud.ibm.com/apidocs/iam-identity-token-api)

[IAM Authentication](https://cloud.ibm.com/docs/iam/apikey_iamtoken.html#iamtoken_from_apikey)

Setting FLASK_DEBUG=1 environment variable to enable debugging and auto reloading of changed files

To generate self signed certificate:
```bash
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
```

GitHub actions:
https://github.com/google-github-actions/setup-gcloud/blob/master/example-workflows/cloud-build/README.md

