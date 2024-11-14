#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   02/24/24   Auditd privileged commands check (Replaces deprecated auditd_privileged_commands_rules_file.sh and auditd_privilieged_commands.sh)

# Set variables
l_output="" l_output2="" l_out2="" l_running_config=""
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

# Check for auditctl status
f_auditctl_chk()
{
   l_running_config=""
   if command -v auditctl &>/dev/null; then
      # Build array with auditd rules in the running config (run once instead of multiple times)
      a_auditd_rule=()
      while IFS= read -r l_auditd_rule; do
         [ -n "$l_auditd_rule" ] && a_auditd_rule+=("$l_auditd_rule")
      done < <(auditctl -l)
      if (( "${#a_auditd_rule[@]}" != 0 )); then
         l_running_config="Y"
      else
         l_running_config="  - No rules are loaded in the auditd running configuration"
      fi
   else
      l_running_config="  - auditctl command not found on the system"
   fi
}

# Main check script
#Build privileged files path exclusion array
a_path=(! -path \"/run/user/*\")
while IFS= read -r l_exclude_path; do
   a_path+=( -a ! -path \""$l_exclude_path"/*\")
done < <(findmnt -krn | awk '/(noexec|nodev)/{print $1}')
#printf '%s ' "${a_path[@]}"
# Check if rule exists for file
while IFS= read -r -d $'\0' l_file; do
   l_out2=""
   l_check_type="an auditd rules file"
   l_check_line="$(awk '/path='"${l_file//\//\\/}"'/{print}' /etc/audit/rules.d/*.rules 2>/dev/null)"
   f_auditd_rules_chk
   [ -z "$l_running_config" ] && f_auditctl_chk
   if [ "$l_running_config" = "Y" ]; then
      l_check_type="the auditd running configuration"
      l_check_line="$(awk '/path='"${l_file//\//\\/}"'/{print}' <<< "${a_auditd_rule[@]}" 2>/dev/null)"
      f_auditd_rules_chk
   else
      l_out2="$l_out2\n$l_running_config"
   fi
   # Create output for file
   if [ -n "$l_out2" ]; then
      l_output2="$l_output2\n - Privileged file: \"$l_file\":$l_out2\n"
   else
      l_output="$l_output\n - Privileged file: \"$l_file\" auditd rule:\n  - exists in a rules file\n  - exists in the running configuration\n"
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