#!/bin/bash

## "-DpushChanges=false -DlocalCheckout=true" to avoid https://issues.apache.org/jira/browse/MRELEASE-954 and we push manually after the release succeeds.
## "-Dmaven.wagon.http.ssl.insecure=true -Dmaven.wagon.http.ssl.allowall=true" to avoid HTTPs issues when deploying the artefacts
PARAMETERS="-Dmaven.wagon.http.ssl.insecure=true -Dmaven.wagon.http.ssl.allowall=true -DpushChanges=false -DlocalCheckout=true -DskipTests=true -Dxwiki.enforcer.skip=true"

mvn release:prepare -U ${PARAMETERS} -DautoVersionSubmodules=true -Darguments="${PARAMETERS}" || exit -2
mvn release:perform ${PARAMETERS} -Darguments="${PARAMETERS}" || exit -2

echo "Pushing changes to git once the release is one successfully..."
git push --tags 
