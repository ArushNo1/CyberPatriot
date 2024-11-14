#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   08/12/24   Check root account access is controlled
# E. Pinnell   08/28/24   Modified to work with Fedora based distributions and improve evidence output

a_output=() a_output2=() a_output3=() l_user="root"

f_report_hash()
{
   l_found_value="$(awk -F: '($1=="'"$l_user"'") {split($2,a,"$"); print a[2]}' /etc/shadow)"
   case "${l_found_value,,}" in
      1 )
         l_hash="MD5" ;;
      2a )
         l_hash="blowfish" ;;
      5 )
         l_hash="SHA-256" ;;
      6 )
         l_hash="SHA-512" ;;
      y )
         l_hash="yescrypt" ;;
      * )
         l_hash="DES" ;;
   esac
}

l_account_status="$(passwd -S "$l_user" | awk '{print $2}')"
if [ -n "$l_account_status" ]; then
   case "$l_account_status" in
      NP )
         a_output2+=("  - User account: \"$l_user\" has no password and is not locked" \
         "    Please set a password or lock the account") ;;
      L|LK )
         a_output+=("  - User account: \"$l_user\" is locked") ;;
      P|PS )
         f_report_hash
         ! grep -Psq -- '(SHA-512|yescrypt)' <<< "$l_hash" && a_output3+=("  ** WARNING **" \
         "  User account: \"$l_user\" password" \
         "  is using the \"$l_hash\" hashing algorithm")
         a_output+=("  - User account: \"$l_user\" password has been set" \
         "    using the \"$l_hash\" hashing algorithm") ;;
   esac
else
   a_output2+=("  - User account: \"$l_user\" has no password" \
   "    Please set a password or lock the account")
fi

# Send test results and assessment evidence to CIS-CAT
[ "${#a_output3[@]}" ] && printf '%s\n' "" "${a_output3[@]}"
if [ "${#a_output2[@]}" -le 0 ]; then
   printf '%s\n' "" "- Audit Result:" "  ** PASS **" "${a_output[@]}" ""
   exit "${XCCDF_RESULT_PASS:-101}"
else
   printf '%s\n' "" "- Audit Result:" "  ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]}"
   [ "${#a_output[@]}" -gt 0 ] && printf '%s\n' "" "- Correctly set:" "${a_output[@]}" ""
   exit "${XCCDF_RESULT_FAIL:-102}"
fi