#!/usr/bin/env sh
#
# CIS-LBK Recommendation Function
# ~/CIS-LBK/functions/recommendations/nix_fed_ensure_selinux_state_enforcing.sh
# 
# Name                Date       Description
# ------------------------------------------------------------------------------------------------
# Eric Pinnell       09/30/20    Recommendation "Ensure the SELinux state is enforcing"
# 
fed_ensure_selinux_state_enforcing()
{
	echo "- $(date +%d-%b-%Y' '%T) - Starting $RNA" | tee -a "$LOG" 2>> "$ELOG"
	test=""
	if grep -Eqs '^\s*SELINUX=enforcing\b' /etc/selinux/config; then
		test=passed
	else
		if grep -Eqs '^\s*(#\s*)?SELINUX=\S+\b' /etc/selinux/config; then
			sed -ri 's/^\s*(#\s*)?(SELINUX=)(\S+\b)(.*)$/\2enforcing \4/' /etc/selinux/config
		else
			echo "SELINUX=enforcing" >> /etc/selinux/config
		fi
		grep -Eqs '^\s*SELINUX=enforcing\b' /etc/selinux/config && test=remediated
	fi
	# Set return code and return
	case "$test" in
		passed)
			echo "Recommendation \"$RNA\" No remediation required" | tee -a "$LOG" 2>> "$ELOG"
			return "${XCCDF_RESULT_PASS:-101}"
			;;
		remediated)
			echo "Recommendation \"$RNA\" successfully remediated" | tee -a "$LOG" 2>> "$ELOG"
			return "${XCCDF_RESULT_PASS:-103}"
			;;
		manual)
			echo "Recommendation \"$RNA\" requires manual remediation" | tee -a "$LOG" 2>> "$ELOG"
			return "${XCCDF_RESULT_FAIL:-106}"
			;;
		*)
			echo "Recommendation \"$RNA\" remediation failed" | tee -a "$LOG" 2>> "$ELOG"
			return "${XCCDF_RESULT_FAIL:-102}"
			;;
	esac
}