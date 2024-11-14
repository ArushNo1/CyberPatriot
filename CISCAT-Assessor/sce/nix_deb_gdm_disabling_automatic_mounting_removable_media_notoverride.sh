#!/usr/bin/env bash
#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# R. Bejar     01/22/24   GDM disabling automatic mounting of removable media is not overridden
{
   # Check if GNOME Desktop Manager is installed.
   l_pkgoutput=""
   if command -v dpkg-query > /dev/null 2>&1; then
      l_pq="dpkg-query -W"
   elif command -v rpm > /dev/null 2>&1; then
      l_pq="rpm -q"
   fi

   l_pcl="gdm gdm3" # space-separated list of packages to check
   for l_pn in $l_pcl; do
      $l_pq "$l_pn" > /dev/null 2>&1 && l_pkgoutput="$l_pkgoutput\n - Package: \"$l_pn\" exists on the system\n - Checking configuration"
   done

   # Check for GDM configuration (If applicable)
   if [ -n "$l_pkgoutput" ]; then
      l_output="" 
      l_output2=""
      
      # Search /etc/dconf/db/local.d/ for automount settings
      l_automount_setting=$(grep -Psir -- '^\h*automount=false\b' /etc/dconf/db/local.d/*)
      l_automount_open_setting=$(grep -Psir -- '^\h*automount-open=false\b' /etc/dconf/db/local.d/*)

      # Check for automount and automount-open settings
      if [[ -n "$l_automount_setting" ]]; then
         l_output="$l_output\n - \"automount\" setting found"
      else
         l_output2="$l_output2\n - \"automount\" setting not found"
      fi

      if [[ -n "$l_automount_open_setting" ]]; then
         l_output="$l_output\n - \"automount-open\" setting found"
      else
         l_output2="$l_output2\n - \"automount-open\" setting not found"
      fi
   else
      l_output="$l_output\n - GNOME Desktop Manager package is not installed on the system\n  - Recommendation is not applicable"
   fi

   # Report results. If no failures in l_output2, we pass
   [ -n "$l_pkgoutput" ] && echo -e "\n$l_pkgoutput"
   if [ -z "$l_output2" ]; then
      echo -e "\n- Audit Result:\n  ** PASS **\n$l_output\n"
      exit "${XCCDF_RESULT_PASS:-101}"
   else
      echo -e "\n- Audit Result:\n  ** FAIL **\n - Reason(s) for audit failure:\n$l_output2\n"
      [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
      exit "${XCCDF_RESULT_FAIL:-102}"
   fi
}
