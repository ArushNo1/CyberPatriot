#!/usr/bin/env bash
#
#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# R. Bejar     07/16/24   Debian - Ensure a single firewall configuration utility is in use
#

{
    active_firewall=()
    firewalls=("ufw" "nftables" "iptables")
    # Check for each firewall
    for firewall in "${firewalls[@]}"; do
        case $firewall in
            nftables)
                cmd="nft"
                ;;
            *)
                cmd=$firewall
                ;;
            esac          
        if command -v "$cmd" &> /dev/null && systemctl is-enabled --quiet "$firewall" && systemctl is-active --quiet "$firewall"; then
            active_firewall+=("$firewall")
        fi
    done
    # Display audit results
    if [ ${#active_firewall[@]} -eq 1 ]; then
        echo -e "\n Audit Results:\n ** PASS **\n - A single firewall is in use follow the recommendation in ${active_firewall[0]} subsection ONLY"
        exit "${XCCDF_RESULT_PASS:-101}"
    elif [ ${#active_firewall[@]} -eq 0 ]; then
        echo -e "\n Audit Results:\n ** FAIL **\n - No firewall in use or unable to determine firewall status"
        exit "${XCCDF_RESULT_FAIL:-102}"
    else
        echo -e "\n Audit Results:\n ** FAIL ** \n - Multiple firewalls are in use: ${active_firewall[*]}"
        exit "${XCCDF_RESULT_FAIL:-102}"
    fi  
}   