#!/bin/bash
echo "https://kellrman-074b55ec662880a9b91b986213323a0b-0000.us-east.containers.appdomain.cloud/api-browser"
echo "ibmcloud login --sso -a cloud.ibm.com -r us-east"

ibmcloud ks cluster config --cluster bp2vucbw0acqse0v8p9g

kubectl scale -n default deployment api-browser-deployment --replicas=0
kubectl scale -n default deployment api-browser-deployment --replicas=2

echo "Pods:"
kubectl get pods