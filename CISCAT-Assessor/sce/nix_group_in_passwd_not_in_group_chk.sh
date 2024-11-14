#!/usr/bin/env bash

# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   02/02/24   Check existence of /etc/passwd groups in /etc/group (deprecates: etc_group_chk.sh)
#

l_output="" l_output2=""

# Build array of GIDs in /etc/passwd
a_passwd_group_gid=("$(awk -F: '{print $4}' /etc/passwd | sort -u)")

# Build array of GIDs in /etc/group
a_group_gid=("$(awk -F: '{print $3}' /etc/group | sort -u)")

# Build array of GIDs that are different between /etc/passwd and /etc/group
a_passwd_group_diff=("$(printf '%s\n' "${a_group_gid[@]}" "${a_passwd_group_gid[@]}" | sort | uniq -u)")

while IFS= read -r l_gid; do
   l_output2="$l_output2\n$(awk -F: '($4 == '"$l_gid"') {print "  - User: \"" $1 "\" has GID: \"" $4 "\" which does not exist in /etc/group" }' /etc/passwd)"
done < <(printf '%s\n' "${a_passwd_group_gid[@]}" "${a_passwd_group_diff[@]}" | sort | uniq -D | uniq)

unset a_passwd_group_gid; unset a_group_gid; unset a_passwd_group_diff

# If the tests produce no failing output, we pass
if [ -z "$l_output2" ]; then
   l_output="  - No GIDs exist in /etc/passwd that do not exist in /etc/group"
	echo -e "\n- Audit Result:\n  ** PASS **\n - * Correctly configured * :\n$l_output"
	exit "${XCCDF_RESULT_PASS:-101}"
else
	echo -e "\n- Audit Result:\n  ** FAIL **\n - * Reasons for audit failure * :$l_output2\n"
   [ -n "$l_output" ] && echo -e "\n - * Correctly configured * :\n$l_output\n"
	exit "${XCCDF_RESULT_FAIL:-102}"
fi