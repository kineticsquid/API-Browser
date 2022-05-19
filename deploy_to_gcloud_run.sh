#!/bin/bash

# Run this to create or re-deploy the function
gcloud run deploy api-browser --allow-unauthenticated --project cloud-run-stuff --region us-central1 \
  --source ./