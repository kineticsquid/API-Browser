#!/bin/bash
echo "Tagging and pushing docker image. Be sure to start docker.app first"

docker rmi kineticsquid/api-browser:latest
docker build --rm --no-cache --pull -t kineticsquid/api-browser:latest -f Dockerfile .
docker push kineticsquid/api-browser:latest

# list the current images
echo "Docker Images..."
docker images

