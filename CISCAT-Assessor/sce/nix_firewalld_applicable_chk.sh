#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   04/05/21   Check if firewalld is applicable (either nftables or iptables is being used)
# E. Pinnell   12/05/23   Modified to use bash, modernize, and fix potential false returns

l_output="" l_output2="" l_firewall_utility=""

if rpm -q firewalld &>/dev/null; then
   if systemctl is-enabled firewalld.service | grep -Pq -- '^enabled' || is-active firewalld.service | grep '^active'; then
      if [ -z "$l_firewall_utility" ]; then
         l_firewall_utility="firewalld"
      else
         l_firewall_utility="$l_firewall_utility and firewalld"
      fi
   fi
fi

if rpm -q nftables &> /dev/null; then
   if systemctl is-enabled nftables.service | grep -Pq -- '^enabled'; then
      if [ -z "$l_firewall_utility" ]; then
         l_firewall_utility="nftables"
      else
         l_firewall_utility="$l_firewall_utility and nftables"
      fi
   fi
fi

if rpm -q iptables-services &>/dev/null; then
   if systemctl is-enabled iptables.service ip6tables.service | grep -Pq -- '^enabled'; then
      if [ -z "$l_firewall_utility" ]; then
         l_firewall_utility="iptables"
      else
         l_firewall_utility="$l_firewall_utility and iptables"
      fi
   fi
fi

if [[ -n "$l_firewall_utility" ]] && [[ ! "$l_firewall_utility" =~ firewalld ]]; then
   l_output=" - Firewall is: \"$l_firewall_utility\""
elif [ -z "$l_firewall_utility" ]; then
   l_output2=" - No firewall is enabled"
else
   l_output2=" - Firewall is: \"$l_firewall_utility\""
fi

# If l_output2 is empty, we pass
if [ -z "$l_output2" ]; then
   echo -e "\n- Audit Result:\n  ** PASS **\n - * Correctly configured * :\n$l_output\n"
   exit "${XCCDF_RESULT_PASS:-101}"
else
   echo -e "\n- Audit Result:\n  ** FAIL **\n - * Reasons for audit failure * :\n$l_output2"
   [ -n "$l_output" ] && echo -e "- * Correctly configured * :\n$l_output\n"
   exit "${XCCDF_RESULT_FAIL:-102}"
fi