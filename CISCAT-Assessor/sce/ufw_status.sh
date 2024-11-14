#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   12/11/19   Check ufw status (verbose)
# E. Pinnell   03/20/23   Modified to run in bash and use grep -P 
# E. Pinnell   10/11/23   Modified to check for command first

passing="" l_output2=""
if command -v ufw &>/dev/null; then
    ufw status verbose | grep -Pq -- "$XCCDF_VALUE_REGEX" && passing=true
else
    l_output2=" - command \"ufw status\" not available"
fi

# If the regex matched, output would be generated.  If so, we pass
if [ "$passing" = true ] ; then
    exit "${XCCDF_RESULT_PASS:-101}"
else
    # print the reason why we are failing
    echo "Missing ufw rule."
    [ -n "$l_output2" ] && echo "$l_output2"
    exit "${XCCDF_RESULT_FAIL:-102}"
fi