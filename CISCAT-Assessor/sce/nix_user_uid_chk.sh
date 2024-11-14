#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   01/24/24   Verify user UID (user and UID need to be separated by a ':' e.g. root:0) 

# XCCDF_VALUE_REGEX="root:0" # Example XCCDF_VALUE_REGEX

l_output="" l_output2="" l_out2=""

while IFS=: read -r l_user l_uid; do
   while IFS= read -r l_passwd_file_user; do
      if [ "$l_passwd_file_user" != "$l_user" ]; then
         l_out2="$l_out2\n  - User \"$l_passwd_file_user\" UID is: \"$l_uid\""
      fi
   done < <(awk -F: '$3 == "'"$l_uid"'"{print $1}' /etc/passwd)
   if [ -n "$l_out2" ]; then
      l_output2="$l_output2\n$l_out2"
   else
      l_output="$l_output\n  - No unauthorized user's UID is: \"$l_uid\""
   fi
   l_out2=""
   while IFS= read -r l_passwd_file_uid; do
   if [ "$l_passwd_file_uid" != "$l_uid" ]; then
      l_out2="$l_out2\n  - User \"$l_user\" UID is: \"$l_passwd_file_uid\" and should be: \"$l_uid\""
   fi
   done < <(awk -F: '$1=="'"$l_user"'"{print $3}' /etc/passwd)
   if [ -n "$l_out2" ]; then
      l_output2="$l_output2\n$l_out2"
   else
      l_output="$l_output\n  - User \"$l_user\" UID is correctly set to: \"$l_uid\""
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