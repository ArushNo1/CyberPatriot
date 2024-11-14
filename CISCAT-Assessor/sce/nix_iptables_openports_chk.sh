#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   03/10/21   Check iptables firewall rules exist for all open ports
# E. Pinnell   04/04/24   Modified to check for command availability and improve output

l_output="" l_output2=""

if command -v iptables &>/dev/null; then
	l_iptrules=$(iptables -L INPUT -v -n)
	while IFS= read -r l_open_port; do
		if [ -n "$l_open_port" ]; then
			if grep -Pq -- ":$l_open_port\b" <<< "$l_iptrules"; then
				l_output="$l_output\n  - iptables rule exists for open port: \"$l_open_port\""
			else
				l_output2="$l_output2\n  - iptables rule does not exist for open port: \"$l_open_port\""
			fi
		fi
	done < <(ss -4tuln | awk '($5!~/%lo:/ && $5!~/127.0.0.1:/) {split($5, a, ":"); print a[2]}')
else
	l_output2="$l_output2\n  - command \"iptables\" not found\n   verify iptables is installed if iptables is in use on the system"
fi

if [ -z "$l_output2" ]; then
	echo -e "\n- Audit Result:\n  ** PASS **\n - * Correctly configured * :\n$l_output\n"
	exit "${XCCDF_RESULT_PASS:-101}"
else
	echo -e "\n- Audit Result:\n  ** FAIL **\n - * Reasons for audit failure * :\n$l_output2"
	[ -n "$l_output" ] && echo -e "- * Correctly configured * :\n$l_output\n"
	exit "${XCCDF_RESULT_FAIL:-102}"
fi