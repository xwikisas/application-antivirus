#!/bin/bash

# ---------------------------------------------------------------------------
# See the NOTICE file distributed with this work for additional
# information regarding copyright ownership.
#
# This is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this software; if not, write to the Free
# Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
# 02110-1301 USA, or see the FSF site: http://www.fsf.org.
# ---------------------------------------------------------------------------

## "-DpushChanges=false -DlocalCheckout=true" to avoid https://issues.apache.org/jira/browse/MRELEASE-954 and we push manually after the release succeeds.
## "-Dmaven.wagon.http.ssl.insecure=true -Dmaven.wagon.http.ssl.allowall=true" to avoid HTTPs issues when deploying the artefacts
PARAMETERS="-Dmaven.wagon.http.ssl.insecure=true -Dmaven.wagon.http.ssl.allowall=true -DpushChanges=false -DlocalCheckout=true -DskipTests=true -Dxwiki.enforcer.skip=true"

mvn release:prepare -U ${PARAMETERS} -DautoVersionSubmodules=true -Darguments="${PARAMETERS}" || exit -2
mvn release:perform ${PARAMETERS} -Darguments="${PARAMETERS}" || exit -2

echo "Pushing changes to git once the release is one successfully..."
git push --tags 
