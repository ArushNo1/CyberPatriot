#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   06/09/21   Check that audit log files directory in 0750 or more restrictive
# E. Pinnell   02/28/24   Modified to rune in bash, add checks for existence, improve reliability and output

# **Note:** This check is deprecated. Replaced by nix_auditd_logfile_directory_mode_chk.sh

# Set variables
l_output="" l_output2=""
l_perm_mask="0027"

if [ -e "/etc/audit/auditd.conf" ]; then
   l_audit_log_directory="$(dirname "$(awk -F= '/^\s*log_file\s*/{print $2}' /etc/audit/auditd.conf | xargs)")"
   if [ -d "$l_audit_log_directory" ]; then
      l_maxperm="$(printf '%o' $(( 0777 & ~$l_perm_mask )) )"
      l_directory_mode="$(stat -Lc '%#a' "$l_audit_log_directory")"
      if [ $(( $l_directory_mode & $l_perm_mask )) -gt 0 ]; then
         l_output2="$l_output2\n  - Directory: \"$l_audit_log_directory\" is mode: \"($l_directory_mode)\"\n     (should be mode: \"($l_maxperm)\" or more restrictive)\n"
      else
         l_output="$l_output\n  - Directory: \"$l_audit_log_directory\" is mode: \"($l_directory_mode)\"\n     (should be mode: \"($l_maxperm)\" or more restrictive)\n"
      fi        
   else
      l_output2="$l_output2\n  - Log file directory not set in \"/etc/audit/auditd.conf\" please set log file directory"
   fi
else
   l_output2="$l_output2\n  - File: \"/etc/audit/auditd.conf\" not found\n  - ** Verify auditd is installed **"
fi

# Send output to CIS-CAT and exit
if [ -z "$l_output2" ]; then
   echo -e "\n- Audit Result:\n  ** PASS **\n - * Correctly configured * :$l_output"
   exit "${XCCDF_RESULT_PASS:-101}"
else
   echo -e "\n- Audit Result:\n  ** FAIL **\n - * Reasons for audit failure * :$l_output2\n"
   [ -n "$l_output" ] && echo -e "\n - * Correctly configured * :\n$l_output\n"
   exit "${XCCDF_RESULT_FAIL:-102}"
fi