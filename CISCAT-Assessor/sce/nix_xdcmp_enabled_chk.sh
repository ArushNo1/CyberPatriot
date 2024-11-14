#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   01/25/24   Check if xdcmp is enabled

l_output="" l_output2=""

while IFS= read -r l_file; do
   l_out2="$(awk '/\[xdmcp\]/{ f = 1;next } /\[/{ f = 0 } f {if (/^\s*Enable\s*=\s*true/) print "  - The file: \"'"$l_file"'\" includes: \"" $0 "\" in the \"[xdmcp]\" block"}' "$l_file")"
   [ -n "$l_out2" ] && l_output2="$l_output2\n$l_out2"
done < <(grep -Psil -- '^\h*\[xdmcp\]' /etc/{gdm3,gdm}/{custom,daemon}.conf)

# If l_output2 is empty, we pass
if [ -z "$l_output2" ]; then
   l_output=" - XDCMP is not enabled"
   echo -e "\n- Audit Result:\n  ** PASS **\n - * Correctly configured * :\n$l_output\n"
   exit "${XCCDF_RESULT_PASS:-101}"
else
   echo -e "\n- Audit Result:\n  ** FAIL **\n - * Reasons for audit failure * :\n$l_output2\n"
   [ -n "$l_output" ] && echo -e "- * Correctly configured * :\n$l_output\n"
   exit "${XCCDF_RESULT_FAIL:-102}"
fi