#!/usr/bin/env bash
echo "Deploying now..."

# IF CF_ORG is not defined, this is not running as part of a DevOps Pipeline in Bluemix, so set these values
#if [[ -z "${CF_ORG}" ]]; then
#  export CF_ORG='kellrman@us.ibm.com'
#  export CF_SPACE='dev'
#  export AUTH='7vZob_7TCakks64OV9C4aJxBD9FPscVf1rdoSHdJazs5'
#fi

# Authenticate to Bluemix
bx api https://api.ng.bluemix.net
# bx plugin install Cloud-Functions -r Bluemix
bx login --apikey ${AUTH}
bx target -o ${CF_ORG} -s ${CF_SPACE}
bx app push CF-API-Browser