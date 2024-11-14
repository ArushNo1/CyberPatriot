#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   08/20/24   Check is FIPS mode is enabled on Fedora based distributions

a_output=() a_output2=() a_out=()
a_out+=("$(fips-mode-setup --check)")
if grep -Piq -- '\bFIPS\h+mode\h+is\h+enabled\b' <<< "${a_out[*]}"; then
   a_output+=("${a_out[@]}")
else
   a_output2+=("${a_out[@]}")
fi

if [ "${#a_output2[@]}" -le 0 ]; then
   printf '%s\n' "" "- Audit Result:" "  ** PASS **" "${a_output[@]}" ""
   exit "${XCCDF_RESULT_PASS:-101}"
else
   printf '%s\n' "" "- Audit Result:" "  ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]}"
   [ "${#a_output[@]}" -gt 0 ] && printf '%s\n' "" "- Correctly set:" "${a_output[@]}" ""
   exit "${XCCDF_RESULT_FAIL:-102}"
fi