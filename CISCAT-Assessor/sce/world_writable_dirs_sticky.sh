#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
# 
# Name       Date       Description
# -------------------------------------------------------------------
# B. Munyan  07/13/16   Sticky bit must be on all world-writable dirs
# B. Munyan  02/04/19   Unix line endings
# E. Pinnell 05/01/20   Modified to send std error to /dev/null
# E. Pinnell 03/28/23   Changed bash, changed approach, avoided limitation with xargs. Caped output size to help avoid potential heap memory issue
# 

l_output="" l_output2=""
l_limit="50" # Set report output limit
# Initialize array
a_dir=()
# Populate array with directories that fail the audit
while read -r l_mpname; do
   while IFS= read -r -d $'\0' l_dir; do
      [ -e "$l_dir" ] && a_dir+=("$(readlink -f "$l_dir")") # readlink faster than find -L
   done < <(find "$l_mpname" -xdev -not -path "/run/user/*" -type d \( -perm -0002 -a ! -perm -1000 \) -print0)
done < <(findmnt -Derno target)
# Generate output reports
if ! (( ${#a_dir[@]} > 0 )); then
   l_output="$l_output\n  - Sticky bit is set on world writable directories on the local filesystem."
else
   l_output2="$l_output2\n - There are \"$(printf '%s' "${#a_dir[@]}")\" World writable directories without the sticky bit on the system.\n   - List of World writable directories without the sticky bit:\n$(printf '%s\n' "${a_dir[@]:0:$l_limit}")\n   - end of list\n"
fi 
if (( ${#a_dir[@]} > "$l_limit" )); then
   l_output2="\n    ** NOTE: **\n    More than \"$l_limit\" world writable files and/or \n    World writable directories without the sticky bit exist\n    only the first \"$l_limit\" will be listed\n$l_output2"
fi
# Remove array
unset a_dir
# If l_output2 is empty, we pass
if [ -z "$l_output2" ]; then
   echo -e "\n- Audit Result:\n  ** PASS **\n - * Correctly configured * :\n$l_output\n"
   exit "${XCCDF_RESULT_PASS:-101}"
else
   echo -e "\n- Audit Result:\n  ** FAIL **\n - * Reasons for audit failure * :\n$l_output2"
   [ -n "$l_output" ] && echo -e "- * Correctly configured * :\n$l_output\n"
   exit "${XCCDF_RESULT_FAIL:-102}"
fi
