#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   09/05/23   Verify user GID (user and GID need to be separated by a ':' e.g. root:0)
# E. Pinnell   01/25/24   Modified to also find other users assigned the GID
# E. Pinnell   02/20/24   Modified to exclude users "sync,shutdown,halt, and operator"

# XCCDF_VALUE_REGEX="root:0" # Example XCCDF_VALUE_REGEX

l_output="" l_output2="" l_out2=""

while IFS=: read -r l_user l_gid; do
   while IFS= read -r l_passwd_file_user; do
      if [ "$l_passwd_file_user" != "$l_user" ]; then
         l_out2="$l_out2\n  - User \"$l_passwd_file_user\" GID is: \"$l_gid\""
      fi
   done < <(awk -F: '($1 !~ /^(sync|shutdown|halt|operator)/ && $4 == "'"$l_gid"'"){print $1}' /etc/passwd)
   if [ -n "$l_out2" ]; then
      l_output2="$l_output2\n$l_out2"
   else
      l_output="$l_output\n  - No unauthorized user's GID is: \"$l_gid\""
   fi
   l_out2=""
   while IFS= read -r l_passwd_file_gid; do
   if [ "$l_passwd_file_gid" != "$l_gid" ]; then
      l_out2="$l_out2\n  - User \"$l_user\" GID is: \"$l_passwd_file_gid\" and should be: \"$l_gid\""
   fi
   done < <(awk -F: '$1=="'"$l_user"'"{print $4}' /etc/passwd)
   if [ -n "$l_out2" ]; then
      l_output2="$l_output2\n$l_out2"
   else
      l_output="$l_output\n  - User \"$l_user\" GID is correctly set to: \"$l_gid\""
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