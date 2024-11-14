#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name       Date       Description
# -------------------------------------------------------------------
# E. Pinnell 12/01/23   Check for only one firewall utility running

l_output="" l_output2="" l_firewall_utility=""

if rpm -q firewalld &>/dev/null; then
   if systemctl is-enabled firewalld.service | grep -Pq -- '^enabled'; then
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
   if [ -n "$(systemctl is-enabled iptables.service | grep -P -- '^enabled')" ] || [[ -n "$(grep -Ps '^\h*0\b' /sys/module/ipv6/parameters/disable)" && -n "$(systemctl is-enabled ip6tables.service | grep -P -- '^enabled')" ]]; then
      if [ -z "$l_firewall_utility" ]; then
         l_firewall_utility="iptables"
      else
         l_firewall_utility="$l_firewall_utility and iptables"
      fi
   fi
fi

if [ -n "$l_firewall_utility" ] && [[ ! "$l_firewall_utility" =~ and ]]; then
   l_output=" - Firewall utility is: \"$l_firewall_utility\""
elif [ -z "$l_firewall_utility" ]; then
   l_output2=" - No firewall utility is enabled"
else
   l_output2=" - Multiple firewall utilities: \"$l_firewall_utility\" are enabled"
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