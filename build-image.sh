#!/bin/bash
echo "Tagging and pushing docker image. Be sure to start docker.app first"

ibmcloud cr login
ibmcloud cr image-rm registry.ng.bluemix.net/utils/cf-api-browser
docker rmi registry.ng.bluemix.net/utils/cf-api-browser
docker rmi cf-api-browser
docker build --rm -t cf-api-browser .

docker tag cf-api-browser registry.ng.bluemix.net/utils/cf-api-browser:latest
docker push registry.ng.bluemix.net/utils/cf-api-browser:latest

# list the current images
echo "Docker Images..."
docker images
echo ""
echo "Container Registry Images..."
ibmcloud cr images

