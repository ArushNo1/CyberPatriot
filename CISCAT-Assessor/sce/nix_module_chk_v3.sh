#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Variable Example: XCCDF_VALUE_REGEX="cramfs:fs"
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   05/21/24   Check modules for loadable, loaded, and deny list (XCCDF is `:` separated)
# E. Pinnell   07/05/24   Modified to accept either /bin or /usr/bin to account for unified filesystem on newer versions of the OS
# E. Pinnell   08/09/24   Modified to correct error with checking all loaded kernels in module directory and module name are different

# Note: Deprecates: nix_module_chk.sh and nix_module_chk_v2.sh

# XCCDF_VALUE_REGEX="overlayfs:fs" # <- Example XCCDF_VALUE_REGEX variable

# initialize arrays, clear variables, set variables
a_output=() a_output2=() a_output3=(); l_dl=""

# Function to check kernel module status
f_module_chk()
{
   l_dl="y" # Set to ignore duplicate checks
   a_showconfig=() # Create array with modprobe output
   while IFS= read -r l_showconfig; do
      a_showconfig+=("$l_showconfig")
   done < <(modprobe --showconfig | grep -P -- '\b(install|blacklist)\h+'"${l_mod_chk_name//-/_}"'\b')
   if ! lsmod | grep "$l_mod_chk_name" &> /dev/null; then # Check if the module is currently loaded
      a_output+=("  - kernel module: \"$l_mod_name\" is not loaded")
   else
      a_output2+=("  - kernel module: \"$l_mod_name\" is loaded")
   fi
   if grep -Pq -- '\binstall\h+'"${l_mod_chk_name//-/_}"'\h+(\/usr)?\/bin\/(true|false)\b' <<< "${a_showconfig[*]}"; then
      a_output+=("  - kernel module: \"$l_mod_name\" is not loadable")
   else
      a_output2+=("  - kernel module: \"$l_mod_name\" is loadable")
   fi
   if grep -Pq -- '\bblacklist\h+'"${l_mod_chk_name//-/_}"'\b' <<< "${a_showconfig[*]}"; then
      a_output+=("  - kernel module: \"$l_mod_name\" is deny listed")
   else
      a_output2+=("  - kernel module: \"$l_mod_name\" is not deny listed")
   fi
}

# Split XCCDF_VALUE_REGEX variable and assign parts to required variables
while IFS=: read -r l_mod_name l_mod_type; do
   l_mod_path="$(readlink -f /lib/modules/**/kernel/"$l_mod_type" | sort -u)"
   # Check if the module exists on the system and run check if needed
   for l_mod_base_directory in $l_mod_path; do
      if [ -d "$l_mod_base_directory/${l_mod_name/-/\/}" ] && [ -n "$(ls -A "$l_mod_base_directory/${l_mod_name/-/\/}")" ]; then
         a_output3+=("  - \"$l_mod_base_directory\"")
         l_mod_chk_name="$l_mod_name"
         [[ "$l_mod_name" =~ overlay ]] && l_mod_chk_name="${l_mod_name::-2}"
         [ "$l_dl" != "y" ] && f_module_chk
      else
         a_output+=(" - kernel module: \"$l_mod_name\" doesn't exist in:" "   \"$l_mod_base_directory\"")
      fi
   done
done <<< "$XCCDF_VALUE_REGEX"

# Send test results and assessment evidence to CIS-CAT
[ "${#a_output3[@]}" -gt 0 ] && printf '%s\n' "" " -- INFO --" " - module: \"$l_mod_name\" exists in:" "${a_output3[@]}"
if [ "${#a_output2[@]}" -le 0 ]; then
   printf '%s\n' "" "- Audit Result:" "  ** PASS **" "${a_output[@]}"
   exit "${XCCDF_RESULT_PASS:-101}"
else
   printf '%s\n' "" "- Audit Result:" "  ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]}"
   [ "${#a_output[@]}" -gt 0 ] && printf '%s\n' "- Correctly set:" "${a_output[@]}"
   exit "${XCCDF_RESULT_FAIL:-102}"
fi