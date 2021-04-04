#!/bin/bash

# Now run locally. Use "rm" to remove the container once it finishes
docker run --rm -p 5000:5000 --env kineticsquid/api-browser-alpine:latest
#docker run --rm --env URL_ROOT="/api-browser"  -p 5000:5000 us.icr.io/utils/api-browser-alpine:latest

