#!/usr/bin/env sh
#
# CIS-LBK Recommendation Function
# ~/CIS-LBK/functions/recommendations/nix_fed_ensure_xinetd_not_installed.sh
# 
# Name                Date       Description
# ------------------------------------------------------------------------------------------------
# Eric Pinnell       11/03/20    Recommendation "Ensure xinetd is not installed"
#
fed_ensure_xinetd_not_installed()
{
	echo "- $(date +%d-%b-%Y' '%T) - Starting $RNA" | tee -a "$LOG" 2>> "$ELOG"
	test=""
	if [ -z "$PQ" ] || [ -z "$PM" ] || [ -z "$PR" ]; then
		nix_package_manager_set
	fi
	if ! $PQ xinetd >/dev/null; then
		test=passed
	else
		$PR xinetd
		! $PQ xinetd >/dev/null && test=remediated
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
		NA)
			echo "Recommendation \"$RNA\" Something went wrong - Recommendation is non applicable" | tee -a "$LOG" 2>> "$ELOG"
			return "${XCCDF_RESULT_PASS:-104}"
			;;
		*)
			echo "Recommendation \"$RNA\" remediation failed" | tee -a "$LOG" 2>> "$ELOG"
			return "${XCCDF_RESULT_FAIL:-102}"
			;;
	esac
}