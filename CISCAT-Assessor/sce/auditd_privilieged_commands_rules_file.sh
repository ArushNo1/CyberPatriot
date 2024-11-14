#!/usr/bin/env bash

# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   10/23/19   script to detects uid of the system (Some are 500 newer systems are 1000), finds privileged commands, and looks for corresponding entries in a auditd rules file
# E. Pinnell   02/10/20   Modified to allow for any key value
# E. Pinnell   03/11/22   Modified to account for correct entries in a different format and improve output
# E. Pinnell   02/23/24   Modified to fix fragile for loop over find, better align with Prose, improve output

# Set variables
l_output="" l_output2="" l_out2=""
a_option_check=("-a\h+(always,exit|exit,always)" "-F\h+perm=x" "-F\h+auid>=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)" "-F\h+auid!=(unset|-1|4294967295)")

# auditd rules check function
f_auditd_rules_chk()
{
  if [ -n "$l_check_line" ]; then
    for l_option_check in "${a_option_check[@]}"; do
      if ! grep -Pq -- "$l_option_check" <<< "$l_check_line"; then
        l_out2="$l_out2\n  - option: \"$l_option_check\" is missing"
      fi
    done
  else
    l_out2="$l_out2\n  - auditd rule doesn't exist in $l_check_type"
  fi
}

# Main check script
#Build privileged files path exclusion array
a_path=(! -path \"/run/user/*\")
while IFS= read -r l_exclude_path; do
  a_path+=( -a ! -path \""$l_exclude_path"/*\")
done < <(findmnt -krn | awk '/(noexec|nodev)/{print $1}')

# Check if rule exists for file
while IFS= read -r -d $'\0' l_file; do
  l_out2=""
  l_check_type="an auditd rules file"
  l_check_line="$(awk '/path='"${l_file//\//\\/}"'/{print}' /etc/audit/rules.d/*.rules 2>/dev/null)"
  f_auditd_rules_chk
  # Create output for file
  if [ -n "$l_out2" ]; then
    l_output2="$l_output2\n - Privileged file: \"$l_file\":$l_out2\n"
  else
    l_output="$l_output\n - Privileged file: \"$l_file\"\n  - auditd rule exists in a rules file\n"
  fi
done < <(find / \( "${a_path[@]}" \) \( -perm -4000 -o -perm -2000 \) -type f -print0 2> /dev/null)

# Send output to CIS-CAT and exit
if [ -z "$l_output2" ]; then
  echo -e "\n- Audit Result:\n  ** PASS **\n - * Correctly configured * :$l_output"
  exit "${XCCDF_RESULT_PASS:-101}"
else
  echo -e "\n- Audit Result:\n  ** FAIL **\n - * Reasons for audit failure * :$l_output2\n"
  [ -n "$l_output" ] && echo -e "\n - * Correctly configured * :\n$l_output\n"
  exit "${XCCDF_RESULT_FAIL:-102}"
fi