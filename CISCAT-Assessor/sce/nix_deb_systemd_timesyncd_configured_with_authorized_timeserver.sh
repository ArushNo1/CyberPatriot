#!/usr/bin/env bash
#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# R. Bejar     01/18/24   new sce for systemd-timesyncd configure with authorized timeserver

{
    l_output=""
    l_output2=""
    a_parlist=("^\h*(NTP|FallbackNTP)=\H+")
    l_systemd_config_file="/etc/systemd/timesyncd.conf" # Main systemd configuration file

    config_file_parameter_chk() {
        unset A_out
        declare -A A_out

        while read -r l_out; do
            if [ -n "$l_out" ]; then
                if [[ $l_out =~ ^\s*# ]]; then
                    l_file="${l_out//# /}"
                else
                    l_systemd_parameter="$(awk -F= '{print $1}' <<< "$l_out" | xargs)"
                    [ "${l_systemd_parameter^^}" = "${l_systemd_parameter_name^^}" ] && A_out+=(["$l_systemd_parameter"]="$l_file")
                fi
            fi
        done < <(/usr/bin/systemd-analyze cat-config "$l_systemd_config_file" | grep -Pio '^\h*([^#\n\r]+|#\h*\/[^#\n\r\h]+\.conf\b)')

        if (( ${#A_out[@]} > 0 )); then
            while IFS="=" read -r l_systemd_file_parameter_name l_systemd_file_parameter_value; do
                l_systemd_file_parameter_name="${l_systemd_file_parameter_name// /}"
                l_systemd_file_parameter_value="${l_systemd_file_parameter_value// /}"
                if [ "${l_systemd_file_parameter_value^^}" = "${l_systemd_parameter_value^^}" ]; then
                    l_output="$l_output\n - \"$l_systemd_parameter_name\" is correctly set to \"$l_systemd_file_parameter_value\" in \"$(printf '%s' "${A_out[@]}")\"\n"
                else
                    l_output2="$l_output2\n - \"$l_systemd_parameter_name\" is incorrectly set to \"$l_systemd_file_parameter_value\" in \"$(printf '%s' "${A_out[@]}")\" and should have a value of: \"$l_systemd_parameter_value\"\n"
                fi
            done < <(grep -Pio -- "^\h*$l_systemd_parameter_name\h*=\h*\H+" "${A_out[@]}")
        else
            l_output2="$l_output2\n - \"$l_systemd_parameter_name\" is not set in an included file\n   ** Note: \"$l_systemd_parameter_name\" May be set in a file that's ignored by load procedure **\n"
        fi
    }

    while IFS="=" read -r l_systemd_parameter_name l_systemd_parameter_value; do
        l_systemd_parameter_name="${l_systemd_parameter_name// /}"
        l_systemd_parameter_value="${l_systemd_parameter_value// /}"
        config_file_parameter_chk
    done < <(printf '%s\n' "${a_parlist[@]}")

    if [ -z "$l_output2" ]; then
        echo -e "\n- Audit Result:\n  ** PASS **\n$l_output\n"
        exit "${XCCDF_RESULT_PASS:-101}"
    else
        echo -e "\n- Audit Result:\n  ** FAIL **\n - Reason(s) for audit failure:\n$l_output2\n"
        [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
        exit "${XCCDF_RESULT_FAIL:-102}"
    fi
}

