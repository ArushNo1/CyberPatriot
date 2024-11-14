#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   06/05/24   Ensure TMOUT is set and readonly

# Supersedes deprecated "tmout_chk.sh"
# XCCDF_VALUE_REGEX="900" #<- Sample XCCDF_VALUE_REGEX

a_output=(); a_output2=() # Initialize output arrays

# Function to check if TMOUT is read only and exported
f_tmout_read_chk()
{
   a_out=(); a_out2=()
   l_tmout_readonly="$(grep -P -- '^\h*(typeset\h\-xr\hTMOUT=\d+|([^#\n\r]+)?\breadonly\h+TMOUT\b)' "$l_file")"
   l_tmout_export="$(grep -P -- '^\h*(typeset\h\-xr\hTMOUT=\d+|([^#\n\r]+)?\bexport\b([^#\n\r]+\b)?TMOUT\b)' "$l_file")"
   if [ -n "$l_tmout_readonly" ]; then
      a_out+=("  - Readonly is set as: \"$l_tmout_readonly\" in: \"$l_file\"")
   else
      a_out2+=("  - Readonly is not set in: \"$l_file\"")
   fi
   if [ -n "$l_tmout_export" ]; then
      a_out+=("  - Export is set as: \"$l_tmout_export\" in: \"$l_file\"")
   else
      a_out2+=("  - Export is not set in: \"$l_file\"")
   fi   
}

# Loop to find files containing TMOUT
while IFS= read -r l_file; do
   l_tmout_value="$(grep -Po -- '^([^#\n\r]+)?\bTMOUT=\d+\b' "$l_file" | awk -F= '{print $2}')"
   f_tmout_read_chk
   if [ -n "$l_tmout_value" ]; then
      if [[ "$l_tmout_value" -le "$XCCDF_VALUE_REGEX" && "$l_tmout_value" -gt "0" ]]; then
         a_output+=(" - TMOUT is set to: \"$l_tmout_value\" in: \"$l_file\"")
         [ "${#a_out[@]}" -gt 0 ] && a_output+=("${a_out[@]}")
         [ "${#a_out2[@]}" -gt 0 ] && a_output2+=("${a_out[@]}")
      fi
      if [[ "$l_tmout_value" -gt "$XCCDF_VALUE_REGEX" || "$l_tmout_value" -le "0" ]]; then
         a_output2+=(" - TMOUT is incorrectly set to: \"$l_tmout_value\" in: \"$l_file\"")
         [ "${#a_out[@]}" -gt 0 ] && a_output2+=("  ** Incorrect TMOUT value **" "${a_out[@]}")
         [ "${#a_out2[@]}" -gt 0 ] && a_output2+=("${a_out2[@]}")
      fi
   else
      [ "${#a_out[@]}" -gt 0 ] &&  a_output2+=(" - TMOUT is not set" "${a_out[@]}")
      [ "${#a_out2[@]}" -gt 0 ] &&  a_output2+=(" - TMOUT is not set" "${a_out2[@]}")
   fi
done < <(grep -Pls -- '^([^#\n\r]+)?\bTMOUT\b' /etc/*bashrc /etc/profile /etc/profile.d/*.sh)

# Check for PASS/FAIL status and product output report
[[ "${#a_output[@]}" -le 0 && "${#a_output2[@]}" -le 0 ]] && a_output2+=(" - TMOUT is not configured")
if [ "${#a_output2[@]}" -le 0 ]; then
	printf '%s\n' "" "- Audit Result:" "  ** PASS **" "${a_output[@]}"
   exit "${XCCDF_RESULT_PASS:-101}"
else
	printf '%s\n' "" "- Audit Result:" "  ** FAIL **" "  * Reasons for audit failure *" "${a_output2[@]}" ""
	[ "${#a_output[@]}" -gt 0 ] && printf '%s\n' "- Correctly set:" "${a_output[@]}"
   exit "${XCCDF_RESULT_FAIL:-102}"
fi