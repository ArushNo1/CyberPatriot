#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   01/25/24   Verify group GID (group and GID need to be separated by a ':' e.g. root:0) 

# XCCDF_VALUE_REGEX="root:0" # Example XCCDF_VALUE_REGEX

l_output="" l_output2="" l_out2=""

while IFS=: read -r l_group l_gid; do
   while IFS= read -r l_group_file_group; do
      if [ "$l_group_file_group" != "$l_group" ]; then
         l_out2="$l_out2\n  - Group \"$l_group_file_group\" GID is: \"$l_gid\""
      fi
   done < <(awk -F: '$3 == "'"$l_gid"'"{print $1}' /etc/group)
   if [ -n "$l_out2" ]; then
      l_output2="$l_output2\n$l_out2"
   else
      l_output="$l_output\n  - No unauthorized group's GID is: \"$l_gid\""
   fi
   l_out2=""
   while IFS= read -r l_passwd_file_uid; do
   if [ "$l_passwd_file_uid" != "$l_gid" ]; then
      l_out2="$l_out2\n  - Group \"$l_group\" GID is: \"$l_passwd_file_uid\" and should be: \"$l_gid\""
   fi
   done < <(awk -F: '$1=="'"$l_group"'"{print $3}' /etc/group)
   if [ -n "$l_out2" ]; then
      l_output2="$l_output2\n$l_out2"
   else
      l_output="$l_output\n  - Group \"$l_group\" GID is correctly set to: \"$l_gid\""
   fi
done <<< "$XCCDF_VALUE_REGEX"

# If the tests produce no failing output, we pass
if [ -z "$l_output2" ]; then
	echo -e "\n- Audit Result:\n  ** PASS **\n - * Correctly configured * :$l_output"
	exit "${XCCDF_RESULT_PASS:-101}"
else
	echo -e "\n- Audit Result:\n  ** FAIL **\n - * Reasons for audit failure * :$l_output2\n"
   [ -n "$l_output" ] && echo -e "\n - * Correctly configured * :\n$l_output\n"
	exit "${XCCDF_RESULT_FAIL:-102}"
fi