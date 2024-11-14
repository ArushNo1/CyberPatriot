#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# ------------------------------------------------------------
# E. Pinnell   10/12/23     Check rpm package version

#XCCDF_VALUE_REGEX="pam-1.3.1-26" # <- Example XCCDF_VALUE_REGEX
#l_system_output="1.3.1-25.el8" # <- Example system output

l_output="" l_output2=""

f_version()
{ 
   echo "$@" | awk -F. '{ printf("%d%03d%03d%03d\n", $1,$2,$3,$4); }'
}

while IFS="-" read -r l_package_name l_req_version l_req_sub_version; do
   l_system_output="$(rpm -qa --queryformat "%{VERSION}-%{RELEASE}" "$l_package_name")"
   while IFS="-" read -r l_out_version l_out_sub_version; do
      l_out_sub_version="$(cut -d. -f1 <<< "$l_out_sub_version")"
      if [ "$(f_version "$l_out_version")" -gt "$(f_version "$l_req_version")" ]; then
         l_output="$l_output\n - \"$l_package_name\" is version: \"$l_out_version-$l_out_sub_version\" which is newer than required version: \"$l_req_version-$l_req_sub_version\""
      elif [ "$(f_version "$l_out_version")" -lt "$(f_version "$l_req_version")" ]; then
         l_output2="$l_output2\n - \"$l_package_name\" is version: \"$l_out_version-$l_out_sub_version\" which is older than required version: \"$l_req_version-$l_req_sub_version\""
      else
         if [ "$(f_version $l_out_sub_version)" -ge "$(f_version "$l_req_sub_version")" ]; then
            l_output="$l_output\n - \"$l_package_name\" is version: \"$l_out_version-$l_out_sub_version\" which is newer or equal to required version: \"$l_req_version-$l_req_sub_version\""
         else
            l_output2="$l_output2\n - \"$l_package_name\" is version: \"$l_out_version-$l_out_sub_version\" which is older than required version: \"$l_req_version-$l_req_sub_version\""
         fi
      fi
   done <<< "$l_system_output"
done <<< "$XCCDF_VALUE_REGEX"

# CIS-CAT output
if [ -z "$l_output2" ]; then # If l_output2 is empty, we pass
   echo -e "\n- Audit Result:\n  ** PASS **\n$l_output\n"
	exit "${XCCDF_RESULT_PASS:-101}"
else
   echo -e "\n- Audit Result:\n  ** FAIL **\n - * Reasons for audit failure * :\n$l_output2\n"
	exit "${XCCDF_RESULT_FAIL:-102}"
fi