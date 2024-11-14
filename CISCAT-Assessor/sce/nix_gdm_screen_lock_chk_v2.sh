#!/usr/bin/env bash
#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# R. Bejar     01/23/24   SCE Ensure GDM screen locks when the user is idle
#
{
    # Get the current values of the GSettings keys
    l_lock_delay=$(gsettings get org.gnome.desktop.screensaver lock-delay | awk '{print $2}')
    l_idle_delay=$(gsettings get org.gnome.desktop.session idle-delay | awk '{print $2}')

    # Function to check if a value is less than or equal to a specified limit
    check_limit() {
        local value=$1
        local limit=$2
        if [ "$value" -le "$limit" ]; then
            return 0  # Value is within the limit
        else
            return 1  # Value exceeds the limit
        fi
    }

    # Check lock-delay
    l_lock_delayLimit=5
    if check_limit "$l_lock_delay" "$l_lock_delayLimit"; then
        # Check idle-delay
        l_idle_delayLimit=900
        if [ "$l_idle_delay" -gt 0 ] && check_limit "$l_idle_delay" "$l_idle_delayLimit"; then
            echo -e "Audit Results:\n ** PASS **\n org.gnome.desktop.session $l_lock_delay & $l_idle_delay seconds are within the limit and not disabled."
            exit "${XCCDF_RESULT_PASS:-101}"
        else
            echo -e "Audit Results:\n ** FAIL **\n org.gnome.desktop.session idle-delay should be 900 seconds or less and not disabled (0)."
            exit "${XCCDF_RESULT_FAIL:-102}"
        fi
    else
        echo -e "Audit Results:\n ** FAIL **\n org.gnome.desktop.screensaver lock-delay should be $l_lock_delayLimit seconds or less."
        exit "${XCCDF_RESULT_FAIL:-102}"
    fi
}

