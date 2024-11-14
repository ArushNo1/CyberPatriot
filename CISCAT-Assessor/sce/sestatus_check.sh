#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   11/13/19   Check sestatus
# E. Pinnell   12/08/23   Modified to use bash and grep -P

sestatus | grep -Piq -- "$XCCDF_VALUE_REGEX" && passing=true

# If the regex matched, output would be generated.  If so, we pass
if [ "$passing" = true ] ; then
    exit "${XCCDF_RESULT_PASS:-101}"
else
    # print the reason why we are failing
    echo "SELinux status for \"$XCCDF_VALUE_REGEX\" not found"
    exit "${XCCDF_RESULT_FAIL:-102}"
fi