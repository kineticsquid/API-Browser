#!/bin/bash
echo "https://kellrman-074b55ec662880a9b91b986213323a0b-0000.us-east.containers.appdomain.cloud/api-browser"
echo "https://api-browser.9mzop27k89f.us-south.codeengine.appdomain.cloud/"
ic target -r us-south -g default
ic ce project select --name Utils
REV=$(date +"%y-%m-%d-%H-%M-%S")
echo ${REV}

ic ce app update -n api-browser -i docker.io/kineticsquid/api-browser:latest --rn ${REV} --min 1
ic ce rev list --app api-browser
ic ce app events --app api-browser
ic ce app logs --app api-browser