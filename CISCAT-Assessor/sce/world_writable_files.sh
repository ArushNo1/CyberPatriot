#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
# 
# Name       Date       Description
# -------------------------------------------------------------------
# B. Munyan  7/13/16    Ensure no world-writable files exist
# B. Munyan  2/07/17    Eliminate /sys from this check as well
# B. Munyan  02/04/19   Unix line endings
# E. Pinnell 01/30/23   changed environment to bash, updated audit for better efficiency, improved output
# E. Pinnell 03/27/23   Changed approach, avoided limitation with xargs. Caped output size to help avoid potential heap memory issue
# 

l_output="" l_output2=""
l_limit="2" # Set report output limit
# Initialize arrays
a_file=()
# Populate array with files that fail the audit
while read -r l_mpname; do
   while IFS= read -r -d $'\0' l_file; do
      [ -e "$l_file" ] && a_file+=("$(readlink -f "$l_file")") # readlink faster than find -L
   done < <(find "$l_mpname" -xdev -not -path "/run/user/*" -type f -perm -0002 -print0)
done < <(findmnt -Derno target)
if ! (( ${#a_file[@]} > 0 )); then
    l_output="$l_output\n  - No world writable files exist on the local filesystem."
else
   l_output2="$l_output2\n - There are \"$(printf '%s' "${#a_file[@]}")\" World writable files on the system.\n   - List of World writable files:\n$(printf '%s\n' "${a_file[@]:0:$l_limit}")\n   - end of list\n"
fi
if (( ${#a_file[@]} > "$l_limit" )); then
   l_output2="\n    ** NOTE: **\n    More than \"$l_limit\" world writable files exist\n    only the first \"$l_limit\" will be listed\n$l_output2"
fi
# Remove array
unset a_file
# If l_output2 is empty, we pass
if [ -z "$l_output2" ]; then
   echo -e "\n- Audit Result:\n  ** PASS **\n - * Correctly configured * :\n$l_output\n"
   exit "${XCCDF_RESULT_PASS:-101}"
else
   echo -e "\n- Audit Result:\n  ** FAIL **\n - * Reasons for audit failure * :\n$l_output2"
   [ -n "$l_output" ] && echo -e "- * Correctly configured * :\n$l_output\n"
   exit "${XCCDF_RESULT_FAIL:-102}"
fi