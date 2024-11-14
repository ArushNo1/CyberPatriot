#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   02/27/24   Check audit log file mode (supersedes deprecated  nix_stig_logfile_0600_chk.sh)

# XCCDF_VALUE_REGEX="0177" #<- example XCCDF_VALUE_REGEX variable

# Set variables
l_output="" l_output2=""
l_perm_mask="$XCCDF_VALUE_REGEX"

# Function to convert octal mode to symbolic mode
f_convert_octal_to_symbolic()
{
   [ "$l_var_in" = "0" ] && l_var_out="---"
   [ "$l_var_in" = "1" ] && l_var_out="--x"
   [ "$l_var_in" = "2" ] && l_var_out="-w-"
   [ "$l_var_in" = "3" ] && l_var_out="-wx"
   [ "$l_var_in" = "4" ] && l_var_out="r--"
   [ "$l_var_in" = "5" ] && l_var_out="r-x"
   [ "$l_var_in" = "6" ] && l_var_out="rw-"
   [ "$l_var_in" = "7" ] && l_var_out="rwx"
}

if [ -e "/etc/audit/auditd.conf" ]; then
   l_audit_log_directory="$(dirname "$(awk -F= '/^\s*log_file\s*/{print $2}' /etc/audit/auditd.conf | xargs)")"
   if [ -d "$l_audit_log_directory" ]; then
      l_maxperm="$(printf '%o' $(( 0777 & ~$l_perm_mask )) )"

      # Create symbolic mode for output
      l_hr_maxperm="-"
      a_maxperm=()
      for ((i = 0; i < ${#l_maxperm}; i++)); do
         a_maxperm+=("${l_maxperm:$i:1}")
      done
      for l_var_in in "${a_maxperm[@]}"; do
         f_convert_octal_to_symbolic
         l_hr_maxperm="$l_hr_maxperm$l_var_out"
      done

      while IFS= read -r -d $'\0' l_file; do
         while IFS=: read -r l_file_mode l_hr_file_mode; do
            l_output2="$l_output2\n  - File: \"$l_file\" is mode: \"($l_file_mode/$l_hr_file_mode)\"\n     (should be mode: \"($l_maxperm/$l_hr_maxperm)\" or more restrictive)\n"
         done <<< "$(stat -Lc '%#a:%A' "$l_file")"
      done < <(find "$l_audit_log_directory" -maxdepth 1 -type f -perm /"$l_perm_mask" -print0)
      
      [ -z "$l_output2" ] &&  l_output="$l_output\n  - All files in \"$l_audit_log_directory\" are mode: \"($l_maxperm/$l_hr_maxperm)\" or more restrictive"
   else
      l_output2="$l_output2\n  - Log file directory not set in \"/etc/audit/auditd.conf\" please set log file directory"
   fi
else
   l_output2="$l_output2\n  - File: \"/etc/audit/auditd.conf\" not found.\n  - ** Verify auditd is installed **"
fi

# Remove arrays
unset a_maxperm

# Send output to CIS-CAT and exit
if [ -z "$l_output2" ]; then
   echo -e "\n- Audit Result:\n  ** PASS **\n - * Correctly configured * :$l_output"
   exit "${XCCDF_RESULT_PASS:-101}"
else
   echo -e "\n- Audit Result:\n  ** FAIL **\n - * Reasons for audit failure * :$l_output2\n"
   [ -n "$l_output" ] && echo -e "\n - * Correctly configured * :\n$l_output\n"
   exit "${XCCDF_RESULT_FAIL:-102}"
fi