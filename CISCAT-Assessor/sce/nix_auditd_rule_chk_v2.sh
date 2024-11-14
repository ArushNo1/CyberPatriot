#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   03/05/24   Check auditd running config and rules files for auditd rules

# Deprecates:
# auditd_auditctl_chk.sh, nix_auditd_file_chk.sh, arch32_chk.sh, arch64_chk.sh, auditd_sudo_logfile.sh, auditd_sudo_logfile_v2.sh, auditd_sudo_logfile_v3.sh, nix_auditd_rule_chk.sh, nix_auditd_syscall_rule_chk.sh

# NOTE! The XCCDF_VALUE_REGEX has a VERY specific colon separated format!
# Field 1 is what is being audited
# Field 2 is option the rule line can not include
# Field 3 and beyond is the options that should also be included on the rule line
# All fields MUST be "type" single white space "string" eg. "-F auid>=1000" or "-F auid!=(unset|-1|4294967295)"
# Observe that the "string" may be a regex pipe separated list
# The script will determine the systems UID MIN and update auid>={NUMBER} to the correct UID MIN number

# XCCDF_VALUE_REGEX variable Examples:

# XCCDF_VALUE_REGEX="path=/usr/bin/chon::-a (always,exit|exit,always):-F perm=x:-F auid>=1000:-F auid!=(unset|-1|4294967295)"
# XCCDF_VALUE_REGEX="path=/usr/bin/chcon::-a (always,exit|exit,always):-F perm=x:-F auid>=1000:-F auid!=(unset|-1|4294967295)"
# XCCDF_VALUE_REGEX="-S chmod,fchmod,fchmodat:-F arch=b32:-a always,exit:-F arch=b64:-F auid>=1000:-F auid!=(unset|-1|4294967295)"
# XCCDF_VALUE_REGEX="-S chmod,fchod,fchmodat:-F arch=b32:-a always,exit:-F arch=b64:-F auid>=1000:-F auid!=(unset|-1|4294967295)"
# XCCDF_VALUE_REGEX="-S chmod,fchmod,fchmodat:-F arch=b32:-a always,exit:-F arch=b64:-F auid>=1000:-F auid!=(unset|-1|4294967295)"
# XCCDF_VALUE_REGEX="-S chmod,fchod,fchmodat:-F arch=b32:-a (always,exit|exit,always):-F FAILTEST:-F arch=b64:-F auid>=1000:-F auid!=(unset|-1|4294967295)"
# XCCDF_VALUE_REGEX="-S open,truncate,ftruncate,creat,openat:-F (exit=-EPERM|arch=b32):-a always,exit:-F arch=b64:-F exit=-EACCES:-F auid>=1000:-F auid!=(unset|-1|4294967295)"
# XCCDF_VALUE_REGEX="SUDOLOGFILE::-p wa"
# XCCDF_VALUE_REGEX="-S creat,open,openat,truncate,ftruncate:-F (arch=b32|exit=-EPERM):-a always,exit:-F arch=b64:-F exit=-EACCES:-F auid>=1000:-F auid!=(unset|-1|4294967295)"

# Set variables
l_output="" l_output2="" l_out="" l_out2="" l_running_config=""

# Clean up for "pretty" output
f_variable_cleanup()
{
   l_cleaned_option_check="${l_option_check//\^/}"
   l_cleaned_option_check="${l_cleaned_option_check//\\[hs]\*/}"
   l_cleaned_option_check="${l_cleaned_option_check//\\[hs]\+/ }"
   l_cleaned_option_check="${l_cleaned_option_check//\|/ or }"
   l_cleaned_option_check="${l_cleaned_option_check//[()]/\"}"
}

# auditd rules check function
f_rule_option_chk()
{
   if [ -n "$l_check_line" ]; then
      l_out="$l_out\n - Auditd rule for: \"$l_search_item\" exists as:\n    Rule: \"$l_check_line\"\n     found in: \"$l_check_location\"\n"
      ! grep -Pq -- '^\h*-(w|e|a\h+(always,exit|exit,always))\h+' <<< "$l_check_line" && l_out2="$l_out2\n - Auditd rule for: \"$l_search_item\":\n    Rule: \"$l_check_line\"\n  - Rule start of line not correctly formatted"
      while IFS=' ' read -r l_option_type l_option_line; do
         if grep -Pqs -- "^\h*-S\h*$" <<< "$l_option_type"; then
            l_option_regex="$l_option_type\h+([^#\n\r]+,)?$l_option_line"
         else
            l_option_regex="$l_option_type\h+$l_option_line"
         fi
         if ! grep -Pq -- "^\h*([^#\n\r]+\h+)?$l_option_regex\b" <<< "$l_check_line"; then
            l_option_check="$l_option_line"
            f_variable_cleanup
            l_out2="$l_out2\n - Auditd rule for: \"$l_search_item\"\n    Rule: \"$l_check_line\"\n     option: \"$l_option_type $l_cleaned_option_check\" is missing"
         fi
      done < <(printf '%s\n' "${a_option_check[@]}")
   else
      l_out2="$l_out2\n  - auditd rule for: \"$l_search_item\" doesn't exist in $l_check_type"
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
      if (( "${#a_auditd_rule[@]}" > 0 )); then
         l_running_config="Y"
      else
         l_running_config="  - No rules are loaded in the auditd running configuration"
      fi
   else
      l_running_config="  - auditctl command not found on the system"
   fi
}

# Function to find rule in a auditd rule file
f_rule_file_chk()
{
   l_check_type="an auditd rules file"
   l_check_line_found=""
   while IFS=: read -r l_check_location l_check_line; do
      if ! grep -Pqs -- "$l_exclude_regex" <<< "$l_check_line"; then
         l_check_line_found="Y"
         f_rule_option_chk
      fi
   done < <(grep -PHso -- "^([^#\n\r]+(\h+|,))?${l_search_item//\//\\/}\b.*$" /etc/audit/rules.d/*.rules)
   [ "$l_check_line_found" != Y ] && l_out2="$l_out2\n - Auditd rule for: \"$l_search_item\" doesn't exist in $l_check_type"
}

# Function to find rule in the auditd running config
f_rule_config_chk()
{
   [ -z "$l_running_config" ] && f_auditctl_chk
   if [ "$l_running_config" = "Y" ]; then
      l_check_type="the auditd running configuration"
      l_check_location="$l_check_type"
      l_check_line_found=""
      for l_auditd_config_rule in "${a_auditd_rule[@]}"; do
         l_check_line="$(grep -Pso -- "^([^#\n\r]+(\h+|,))?${l_search_item//\//\\/}\b.*$" <<< "$l_auditd_config_rule")"
         if [ -n "$l_check_line" ] && ! grep -Pqs -- "$l_exclude_regex" <<< "$l_check_line"; then
            l_check_line_found="Y"
            f_rule_option_chk
         fi
      done
      [ "$l_check_line_found" != Y ] && l_out2="$l_out2\n - Auditd rule for: \"$l_search_item\" doesn't exist in $l_check_type"
   else
      l_out2="$l_out2\n$l_running_config"
   fi
}

# Function to find rule containing the item we are auditing
f_rule_line_chk()
{
   l_check_line="" l_out="" l_out2=""
   # Create regex for options that should not be included in the returned rule
   while IFS=' ' read -r l_exclude_type l_exclude_line; do
      if [ -n "$l_exclude_line" ]; then
         l_exclude_regex="$l_exclude_type\h+$l_exclude_line\b"
      else
         l_exclude_regex="^$"
      fi
   done <<< "$l_exclude_option"
   # Check if rule exists in a rules file
   f_rule_file_chk
   # Check if rule exists in the running configuration
   f_rule_config_chk
   if [ -n "$l_out2" ]; then
      l_output2="$l_output2$l_out2"
   else
      [ -n "$l_out" ] && l_output="$l_output$l_out"
   fi
}

# Main check script

# Create the array of additional options we need the rule to include
a_option_check=()
l_rule_options="$(cut -d: -f3- <<< "$XCCDF_VALUE_REGEX")"

while IFS= read -r l_option; do
   if [ -n "$l_option" ]; then
      grep -Pq -- '\bauid>=\H+' <<< "$l_option" && l_option="-F auid>=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"
      a_option_check+=("$l_option")
   fi
done < <(echo -e "${l_rule_options//:/\\n}")

# Look for item we need the auditd rule for
l_option_check="$(cut -d: -f1 <<< "$XCCDF_VALUE_REGEX")"
l_exclude_option="$(cut -d: -f2 <<< "$XCCDF_VALUE_REGEX")"

f_variable_cleanup
if grep -Psq -- '^\h*-S\h+\H+' <<< "$l_cleaned_option_check"; then
   l_var="${l_cleaned_option_check//-S /}"
   for l_search_item in ${l_var//,/ }; do
      f_rule_line_chk
   done
elif grep -Pqs -- '\bSUDOLOGFILE\b' <<< "$l_option_check"; then
   l_logfile=""
   if grep -Piq -- '^\h*defaults\h+([^#\n\r]+\h+)?logfile\h*=\h*\H+' /etc/sudoers; then
      l_logfile="$(grep -- logfile /etc/sudoers | sed -e 's/.*logfile\s*=\s*//;s/,? .*//' | tr -d \")"
   else
      # Last file wins...
      while IFS= read -r l_svar; do
         l_logfile="$(grep -- logfile "$l_svar" | sed -e 's/.*logfile\s*=\s*//;s/,? .*//' | tr -d \")"
      done < <(grep -Pil -- '^\h*defaults\h+([^#\n\r]+\h+)?logfile\h*=\h*\H+' /etc/sudoers.d/* | sort -d)
   fi
   if [ -n "$l_logfile" ]; then
      l_search_item="-w $l_logfile"
      f_rule_line_chk
   else
      l_output2="$l_output2\n - Sudo logfile setting not found in a sudo configuration file\n  ** Please refer to Recommendation: \"Ensure sudo log file exists\" **"
   fi
elif grep -Pqs -- '^\h*-e\h+2\b' <<< "$l_option_check"; then
   l_immutable_chk="$(grep -Phs -- '^\h*-e\h+2\b' /etc/audit/rules.d/*.rules | tail -1)"
   [ -n "$l_immutable_chk" ] && l_immutable_file="$(grep -Pl '^\h*-e\h+2\b' /etc/audit/rules.d/*.rules)"
   if [ -n "$l_immutable_file" ]; then
      l_output="$l_output\n - Auditd Immutable flag: \"-e 2\" found in rule file: \"$l_immutable_file\""
   else
      l_output2="$l_output2\n - Auditd Immutable flag: \"-e 2\" not found in a rule file"
   fi
else
   l_search_item="$l_option_check"
   f_rule_line_chk
fi

# Clear arrays
unset a_option_check
unset a_auditd_rule
# Send output to CIS-CAT and exit
if [ -z "$l_output2" ]; then
  echo -e "\n- Audit Result:\n  ** PASS **\n - * Correctly configured * :$l_output"
  exit "${XCCDF_RESULT_PASS:-101}"
else
  echo -e "\n- Audit Result:\n  ** FAIL **\n - * Reasons for audit failure * :$l_output2\n"
  [ -n "$l_output" ] && echo -e "\n - * Correctly configured * :\n$l_output\n"
  exit "${XCCDF_RESULT_FAIL:-102}"
fi