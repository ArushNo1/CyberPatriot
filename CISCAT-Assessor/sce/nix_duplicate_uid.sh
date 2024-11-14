#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   02/02/21   Ensure no duplicate UIDs exist
# E. Pinnell   07/14/23   Modified to use bash, improve efficiency and assessment evidence output

l_output="" l_output2=""

while read -r l_count l_uid; do
   if [ "$l_count" -gt 1 ]; then
      l_output2="$l_output2\n  - Duplicate UID: \"$l_uid\" Users: \"$(awk -F: '($3 == n) { print $1 }' n=$l_uid /etc/passwd | xargs)\""
   fi
done < <(cut -f3 -d":" /etc/passwd | sort -n | uniq -c)

# CIS-CAT output
# If l_output is unset, we pass
if [ -z "$l_output2" ]; then
   l_output="  - No duplicate UIDs exist"
   echo -e "\n- Audit Result:\n  *** PASS ***\n- * Correctly configured * :\n$l_output\n"
   exit "${XCCDF_RESULT_PASS:-101}"
else
   echo -e "\n- Audit Result:\n  ** FAIL **\n - * Reasons for audit failure * :\n$l_output2\n"
   [ -n "$l_output" ] && echo -e " - * Correctly configured * :\n$l_output\n"
   exit "${XCCDF_RESULT_FAIL:-102}"
fi