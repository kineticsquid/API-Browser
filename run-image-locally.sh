#!/bin/bash

echo "http://0.0.0.0:5000/"

# Now run locally. Use "rm" to remove the container once it finishes
docker run --rm -p 5000:5000 kineticsquid/api-browser:latest
#docker run --rm --env URL_ROOT="/api-browser"  -p 5000:5000 us.icr.io/utils/api-browser-alpine:latest

