#!/bin/bash
echo "Tagging and pushing docker image. Be sure to start docker.app first"

docker rmi kineticsquid/api-browser-alpine:latest
docker build --rm --no-cache --pull -t kineticsquid/api-browser-alpine:latest -f Dockerfile .
docker push kineticsquid/api-browser-alpine:latest

# list the current images
echo "Docker Images..."
docker images

