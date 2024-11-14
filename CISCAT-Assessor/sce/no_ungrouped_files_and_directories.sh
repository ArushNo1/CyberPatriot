#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
# 
# Name       Date       Description
# -------------------------------------------------------------------
# B. Munyan  7/13/16    Ensure no ungrouped files or directories exist
# B. Munyan  02/04/19   Unix line endings
# E. Pinnell 01/30/23   changed environment to bash, updated audit for better efficiency, improved output
# E. Pinnell 03/27/23   Changed approach, avoided limitation with xargs. Caped output size to help avoid potential heap memory issue
#

l_output="" l_output2=""
l_limit="50"
# Initialize array
a_nogroup=()
# Populate array with files that will fail
while read -r l_mpname; do
   while IFS= read -r -d $'\0' l_file; do
      [ -e "$l_file" ] && a_nogroup+=("$l_file")
   done < <(find "$l_mpname" -xdev -not -path "/run/user/*" \( -type f -o -type d \) -nogroup -print0)
done < <(findmnt -Derno target)
if ! (( ${#a_nogroup[@]} > 0 )); then
   l_output="$l_output\n  - No ungrouped files or directories exist on the local filesystem."
else
   l_output2="$l_output2\n  - There are \"$(printf '%s' "${#a_nogroup[@]}")\" ungrouped files or directories on the system.\n   - The following is a list of ungrouped files and/or directories:\n$(printf '%s\n' "${a_nogroup[@]:0:$l_limit}")\n   - end of list"
fi 
if (( ${#a_nogroup[@]} > "$l_limit" )); then
   l_output2="\n  ** Note: more than \"$l_limit\" ungrouped files and/or directories have been found **\n  ** only the first \"$l_limit\" will be listed **\n$l_output2"
fi
# Remove array
unset a_nogroup
# If l_output2 is empty, we pass
if [ -z "$l_output2" ]; then
   echo -e "\n- Audit Result:\n  ** PASS **\n - * Correctly configured * :\n$l_output\n"
   exit "${XCCDF_RESULT_PASS:-101}"
else
   echo -e "\n- Audit Result:\n  ** FAIL **\n - * Reasons for audit failure * :\n$l_output2"
   [ -n "$l_output" ] && echo -e "- * Correctly configured * :\n$l_output\n"
   exit "${XCCDF_RESULT_FAIL:-102}"
fi