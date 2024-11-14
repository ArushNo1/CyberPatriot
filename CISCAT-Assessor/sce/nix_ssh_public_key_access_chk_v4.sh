#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   07/31/24   Check openSSH public key file(s) access 
#                         

# ** This will only work on newer systems. **
# Note:
# version 4 (supersedes nix_ssh_private_key_perm_chk_v2 and nix_ssh_private_key_perm_chk_v3)
# Requires updated file command, but is an improved check where the newer command is available 
# needs to be validated for Fedora 28+ based distributions (Not applicable for Fedora 19)

a_output=(); a_output2=()
l_pmask="0133"; l_maxperm="$( printf '%o' $(( 0777 & ~$l_pmask )) )"
f_file_chk()
{
   while IFS=: read -r l_file_mode l_file_owner l_file_group; do
      a_out2=()
      if [ $(( $l_file_mode & $l_pmask )) -gt 0 ]; then
         a_out2+=("    Mode: \"$l_file_mode\" should be mode: \"$l_maxperm\" or more restrictive")
      fi
      if [ "$l_file_owner" != "root" ]; then
         a_out2+=("    Owned by: \"$l_file_owner\" should be owned by: \"root\"")
      fi
      if [ "$l_file_group" != "root" ]; then
         a_out2+=("    Owned by group \"$l_file_group\" should be group owned by group: \"root\"")
      fi
      if [ "${#a_out2[@]}" -gt "0" ]; then
         a_output2+=("  - File: \"$l_file\"" "${a_out2[@]}")
      else
         a_output+=("  - File: \"$l_file\"" \
         "    Correct: mode: \"$l_file_mode\", owner: \"$l_file_owner\" and group owner: \"$l_file_group\" configured")
      fi
   done < <(stat -Lc '%#a:%U:%G' "$l_file")
}

# Loop to find public openSSH key files (Note: this requires the newer file command)
while IFS= read -r -d $'\0' l_file; do 
   if ssh-keygen -lf &>/dev/null "$l_file"; then 
      file "$l_file" | grep -Piq -- '\bopenssh\h+([^#\n\r]+\h+)?public\h+key\b' && f_file_chk
   fi
done < <(find -L /etc/ssh -xdev -type f -print0 2>/dev/null)

# Send test results and assessment evidence to CIS-CAT
if [ "${#a_output2[@]}" -le 0 ]; then
   [ "${#a_output[@]}" -le 0 ] && a_output+=("  - No openSSH public keys found")
   printf '%s\n' "" "- Audit Result:" "  ** PASS **" "${a_output[@]}" ""
   exit "${XCCDF_RESULT_PASS:-101}"
else
   printf '%s\n' "" "- Audit Result:" "  ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]}"
   [ "${#a_output[@]}" -gt 0 ] && printf '%s\n' "" "- Correctly set:" "${a_output[@]}" ""
   exit "${XCCDF_RESULT_FAIL:-102}"
fi