#!/bin/bash
echo "Logon first with 'ibmcloud logon --sso'"
echo "then execute 'ibmcloud ks cluster-config kellrman'"

export KUBECONFIG=/Users/jk/.bluemix/plugins/container-service/clusters/kellrman/kube-config-wdc07-kellrman.yml

kubectl delete deployment cf-api-browser
kubectl delete service cf-api-browser
kubectl run cf-api-browser --image=registry.ng.bluemix.net/utils/cf-api-browser:latest --port=80 --replicas=4
kubectl expose deployment cf-api-browser --port=80 --target-port=5000 --type=NodePort
echo "public IP address:"
ibmcloud ks workers kellrman
echo "public port (nodeport):"
kubectl describe service cf-api-browser

# These two statements forward log info to log service. They will fail because kubernetes plan is lite and not paid
#echo "These two statements forward log info to log service. They will fail because kubernetes plan is lite and not paid"
#bx cs logging-config-create sudoku --logsource container --namespace '*' --type ibm --hostname ingest.logging.ng.bluemix.net --port 9091 --org kellrman@us.ibm.com --space dev
#bx cs logging-config-create sudoku --logsource worker --type ibm --hostname ingest.logging.ng.bluemix.net --port 9091 --org kellrman@us.ibm.com --space dev


