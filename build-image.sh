#!/bin/bash
echo "Tagging and pushing docker image. Be sure to start docker.app first"

ibmcloud cr login
docker login us.icr.io -u token -p ${DOCKER_TOKEN}
ibmcloud cr image-rm us.icr.io/utils/api-browser-alpine:latest
docker rmi us.icr.io/utils/api-browser-alpine:latest
docker rmi api-browser-alpine
docker build --rm -t api-browser-alpine -f Dockerfile .

ibmcloud cr login
docker tag api-browser-alpine us.icr.io/utils/api-browser-alpine:latest
docker push us.icr.io/utils/api-browser-alpine:latest

# list the current images
echo "Docker Images..."
docker images
echo ""
echo "Container Registry Images..."
ibmcloud cr images

