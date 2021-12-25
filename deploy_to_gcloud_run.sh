#!/bin/bash

echo 'Be sure to "gcloud auth login" first'

export DATE=`date '+%F_%H:%M:%S'`

# Run this to create or re-deploy the function
gcloud run deploy api-browser --allow-unauthenticated --project cloud-run-stuff --region us-central1 \
  --source ./ --set-env-vars=DATE=$DATE