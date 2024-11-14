#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   10/16/23   Check that bootloader password is set version 2 (Replaces nix_bootloader_password_chk.sh) on newer "19+" Fedora based releases
# E. Pinnell   11/07/23   Modified awk statement to accept either GRUB2_PASSWORD or GRUB_PASSWORD to account for older systems that have been upgraded

l_output="" l_output2=""

if [ -z "$(sudo -n true)" ]; then
	l_grub_password_file="$(find /boot -type f -name 'user.cfg' ! -empty)"
   if [ -f "$l_grub_password_file" ]; then
      if [ -n "$(awk -F. '/^\s*GRUB2?_PASSWORD=\S+/ {print $1"."$2"."$3}' "$l_grub_password_file")" ]; then
         l_output=" - Grub bootloader password is set in: \"$l_grub_password_file\""
      else
         l_output2=" - Grub bootloader password is not set"
      fi
   else
      l_output2=" - File \"user.cfg\" does not exist. Grub bootloader password is not set"
   fi
else
   l_output2="$l_output2\n - No root privileges available without additional password entry. Manual assessment will be required"
fi

# CIS-CAT output
if [ -z "$l_output2" ]; then # If l_output2 is empty, we pass
   echo -e "\n- Audit Result:\n  ** PASS **\n$l_output\n"
	exit "${XCCDF_RESULT_PASS:-101}"
else
   echo -e "\n- Audit Result:\n  ** FAIL **\n - * Reasons for audit failure * :\n$l_output2\n"
	exit "${XCCDF_RESULT_FAIL:-102}"
fi