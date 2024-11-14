#!/usr/bin/env bash

# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# R. Bejar     08/01/24   Ensure GDM autorun-never is not overridden
#

{
    # Function to check and report if a specific setting is locked and set to false
    check_setting() {
        grep -Psrilq -- "^\h*$1\h*=\h*true\b" /etc/dconf/db/local.d/locks/* 2> /dev/null && echo "- \"$3\" is locked and set to false" || echo "- \"$3\" is not locked or not set to false" 
    }
    # Array of settings to check
    declare -A settings=(
        ["autorun-never"]="org/gnome/desktop/media-handling"
        
    )
    # Check GNOME Desktop Manager configurations
    l_output=() l_output2=()
    for setting in "${!settings[@]}"; do
        result=$(check_setting "$setting" "${settings[$setting]}" "$setting")
        l_output+=("$result")
        if [[ $result == *"is not locked"* || $result == *"not set to true"* ]]; then
            l_output2+=("$result")
        fi
    done
    # Report results
    if [ ${#l_output2[@]} -ne 0 ]; then
        printf '%s\n' "- Audit Result:" "  ** FAIL **"
        printf '%s\n' "- Reason(s) for audit failure:"
        for msg in "${l_output2[@]}"; do
            printf '%s\n' "$msg"
            exit "${XCCDF_RESULT_FAIL:-102}"
        done
    else
        printf '%s\n' "- Audit Result:" "  ** PASS **"
        exit "${XCCDF_RESULT_PASS:-101}"
    fi
}