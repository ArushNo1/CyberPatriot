#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   02/01/21   Ensure password expiration is 365 days or less
# E. Pinnell   06/04/24   Modified to use bash and ignore accounts with no password set

# XCCDF_VALUE_REGEX="365" # <- Example XCCDF_VALUE_REGEX variable

a_output2=(); l_output=""

while IFS= read -r l_out; do
	[ -n "$l_out" ] && a_output2+=(" - $l_out")
done < <(awk -F: '($2~/^\$.+\$/) {if($5 > '"$XCCDF_VALUE_REGEX"' || $5 < 1)print "User: " $1 " PASS_MAX_DAYS: " $5}' /etc/shadow)

if [ "${#a_output2[@]}" -le 0 ]; then
	l_output=" - All local accounts with passwords have correctly set PASS_MAX_DAYS"
	printf '%s\n' "" "- Audit Result:" "  ** PASS **" "$l_output"
	exit "${XCCDF_RESULT_PASS:-101}"
else
	printf '%s\n' "" "- Audit Result:" "  ** FAIL **" "  * Reasons for audit failure *" "${a_output2[@]}" ""
	exit "${XCCDF_RESULT_FAIL:-102}"
fi