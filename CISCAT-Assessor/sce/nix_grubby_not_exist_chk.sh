#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   11/07/22   Check if grub parameter exists with grubby (nix_grubby_not_exist_chk.sh)
# E. Pinnell   09/15/23   Modified to correct for possible bad output in Fed 28 based distributions 
# E. Pinnell   09/26/23   Modified to force sudo to prevent error when executing the grubby command
# E. Pinnell   10/18/23   Modified to improve check and output

# XCCDF_VALUE_REGEX="audit=1" # Example XCCDF_VALUE_REGEX variable

l_output="" l_output2=""
if [ -z "$(sudo -n true)" ]; then
   l_grub_option="$XCCDF_VALUE_REGEX"
#   l_grub_chk="^\h*args\h*=\h*\"?([^#\"\n\r]+\h+)?$l_grub_option\b"
   if command -v grubby &>/dev/null; then
      l_grub_config="$(sudo grubby --info=ALL 2>/dev/null)"
      l_grubby_options="$(grep -P -- '^\h*args\h*=\h*\"?.*\"?' <<< "$l_grub_config")"
      l_grub_parameter_out="$(grep -P -- "$l_grub_option" <<< "$l_grubby_options")"
      if [ -z "$l_grub_parameter_out" ]; then
         l_output=" - Grub parameter: \"$l_grub_option\" is not set\n\n*** Lines from grub config: ***\n$l_grubby_options\n*** END ***\n"
      else
         l_output2="  - Grub parameter: \"$l_grub_option\" is set\n\n*** Lines from grub config: ***\n$l_grub_parameter_out\n*** END ***\n"
      fi
   else
      l_output2="  - grubby command not available"
   fi
else
   l_output2="$l_output2\n - No root privileges available without additional password entry. Manual assessment will be required"
fi
# If l_output2 is not set, we pass
if [ -z "$l_output2" ]; then
   echo -e "\n- Audit Result:\n  ** PASS **\n$l_output"
	exit "${XCCDF_RESULT_PASS:-101}"
else
   # print the reason why we are failing
   echo -e "\n- Audit Result:\n  ** FAIL **\n$l_output2"
	exit "${XCCDF_RESULT_FAIL:-102}"
fi