#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   06/25/24   check crontab is restricted

# XCCDF_VALUE_REGEX='0137' #<- Example XCCDF_VALUE_REGEX

a_output=(); a_output2=()

f_crontab_auth_chk()
{
   while IFS=: read -r l_mode l_file_owner l_file_group; do
      if [ $(( $l_mode & $l_mask )) -gt 0 ]; then
         a_output2+=("  - \"$l_file\" is mode: \"$l_mode\" (should be mode: \"$l_maxperm\" or more restrictive)")
      else
         a_output+=("  - \"$l_file\" is correctly set to mode: \"$l_mode\"")
      fi
      if [ "$l_file_owner" != "root" ]; then
         a_output2+=("  - \"$l_file\" is owned by user \"$l_file_owner\" (should be owned by \"root\")")
      else
         a_output+=("  - \"$l_file\" is correctly owned by user: \"$l_file_owner\"")
      fi
      if [[ ! $l_file_group =~ ^\s*$l_auth_group\s*$ ]]; then
         a_output2+=("  - \"$l_file\" is owned by group: \"$l_file_group\" (should be owned by group: \"${l_auth_group//|/ or }\")")
      else
         a_output+=("  - \"$l_file\" is correctly owned by group: \"$l_file_group\"")
      fi
   done < <(stat -Lc '%#a:%U:%G' "$l_file")
}

l_mask="$XCCDF_VALUE_REGEX"
l_maxperm="$( printf '%o' $(( 0777 & ~$l_mask)) )"

if grep -Pq -- '^\h*crontab\:' /etc/group; then
   l_auth_group='(root|crontab)'
else
   l_auth_group='root'
fi

if [ -e /etc/cron.allow ]; then
   l_file='/etc/cron.allow'
   f_crontab_auth_chk
else
   a_output2+=("  - File: \"/etc/cron.allow\" does not exist")
fi

if [ -e /etc/cron.deny ]; then
   l_file='/etc/cron.deny'
   f_crontab_auth_chk
else
   a_output+=("  - File: \"/etc/cron.deny\" does not exist")
fi

# Send test results and output to CIS-CAT report
if [ "${#a_output2[@]}" -le 0 ]; then
   printf '%s\n' "" "- Audit Result:" "  ** PASS **" "${a_output[@]}"
   exit "${XCCDF_RESULT_PASS:-101}"
else
   printf '%s\n' "" "- Audit Result:" "  ** FAIL **" "  * Reasons for audit failure *" "${a_output2[@]}"
   [ "${#a_output[@]}" -gt 0 ] && printf '%s\n' "" " * Correctly configured: *" "${a_output[@]}"
   exit "${XCCDF_RESULT_FAIL:-102}"
fi