#!/usr/bin/env sh
#
# CIS-LBK Recommendation Function
# ~/CIS-LBK/functions/recommendations/nix_fed_ensure_password_creation_requirements_configured.sh
# 
# Name                Date       Description
# ------------------------------------------------------------------------------------------------
# Eric Pinnell       11/05/20    Recommendation "Ensure password creation requirements are configured"
# 
fed_ensure_password_creation_requirements_configured()
{
	echo "- $(date +%d-%b-%Y' '%T) - Starting $RNA" | tee -a "$LOG" 2>> "$ELOG"
	test=""	test1="" test2="" test3=""
	# Check password length
	if grep -Eqs '^\s*minlen\s*=\s*(1[4-9]|[2-9][0-9]|[1-9][0-9][0-9]+)\b' /etc/security/pwquality.conf; then
		test1=passed
	else
		grep -Eqs 'minlen\s*=' /etc/security/pwquality.conf && sed -ri 's/^(\s*#\s*)?(\s*minlen\s*=\s*)(\S+)(\s*#.*)?$/\214 \4/' /etc/security/pwquality.conf || echo "minlen = 14" >> /etc/security/pwquality.conf
		grep -Eqs '^\s*minlen\s*=\s*(1[4-9]|[2-9][0-9]|[1-9][0-9][0-9]+)\b' /etc/security/pwquality.conf && test1=remediated
	fi
	# Check password complexity
	if grep -Eqs '^\s*dcredit\s*=\s*-[1-9]\b' /etc/security/pwquality.conf && grep -Eqs '^\s*ucredit\s*=\s*-[1-9]\b' /etc/security/pwquality.conf && grep -Eqs '^\s*ocredit\s*=\s*-[1-9]\b' /etc/security/pwquality.conf && grep -Eqs '^\s*lcredit\s*=\s*-[1-9]\b' /etc/security/pwquality.conf; then
		test2=passed
	elif grep -Eqs '^\s*minclass\s*=\s*4\b' /etc/security/pwquality.conf; then
		test2=passed
	else
		grep -Eqs '^\s*dcredit\s*=' /etc/security/pwquality.conf && sed -i 's/^\s*dcredit\s*=/# &/' /etc/security/pwquality.conf
		grep -Eqs '^\s*ucredit\s*=' /etc/security/pwquality.conf && sed -i 's/^\s*ucredit\s*=/# &/' /etc/security/pwquality.conf
		grep -Eqs '^\s*ocredit\s*=' /etc/security/pwquality.conf && sed -i 's/^\s*ocredit\s*=/# &/' /etc/security/pwquality.conf
		grep -Eqs '^\s*lcredit\s*=' /etc/security/pwquality.conf && sed -i 's/^\s*lcredit\s*=/# &/' /etc/security/pwquality.conf
		grep -qs 'minclass\s*=' /etc/security/pwquality.conf && sed -ri 's/^(\s*#\s*)?(\s*minclass\s*=\s*)(\S+)(\s*#.*)?$/\24\4/' /etc/security/pwquality.conf || echo "minclass = 4" >> /etc/security/pwquality.conf
		if grep -Eqs '^\s*dcredit\s*=\s*-[1-9]\b' /etc/security/pwquality.conf && grep -Eqs '^\s*ucredit\s*=\s*-[1-9]\b' /etc/security/pwquality.conf && grep -Eqs '^\s*ocredit\s*=\s*-[1-9]\b' /etc/security/pwquality.conf && grep -Eqs '^\s*lcredit\s*=\s*-[1-9]\b' /etc/security/pwquality.conf; then
			test2=remediated
		elif grep -Eqs '^\s*minclass\s*=\s*4\b' /etc/security/pwquality.conf; then
			test2=remediated
		fi
	fi
	for file in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
		if grep -Eq '^\s*password\s+(requisite|required)\s+pam_pwquality.so\s+([^#]+\s+)?(retry=[1-3]\b)' "$file"; then
			[ -z "$test3" ] && test3=passed
		else
			if grep -qs 'retry=' "$file"; then
				sed -ri 's/(^\s*#\s*)?(password\s+(requisite|required)\s+pam_pwquality\.so)(\s+[^#]+\s+)?(retry=)(\S+)?(\s+[^#]+)?$/\2\4\53 \7/' "$file"
			elif grep -Eqs 'password\s+(requisite|required)\s+pam_pwquality\.so' "$file"; then
				sed -ri 's/^\s*(#\s*)?(password\s+(requisite|required)\s+pam_pwquality\.so)(\s+[^#]+)?(#.*)?$/\2\4 retry=3 \5/' "$file"
			else
				if grep -Eqs 'password\s+(S+)\s+pam_pwhistory\.so\b' "$file"; then
					sed -ri '/^\s*password\s+(requisite|required|sufficient)\s+(pam_pwhistory\.so)\b.*$/i password    requisite     pam_pwquality.so local_users_only retry=3 ' "$file"
				else
					sed -ri '/^\s*password\s+(requisite|required|sufficient)\s+(pam_unix\.so)\b.*$/i password    requisite     pam_pwquality.so local_users_only retry=3 ' "$file"
				fi
			fi
			if grep -Eq '^\s*password\s+(requisite|required)\s+pam_pwquality.so\s+([^#]+\s+)?(retry=[1-3]\b)' "$file" && [ "$test3" != failed ]; then
				test3=remediated
			else
				test3=failed
			fi
		fi
	done
	[ "$test3" = failed ] && test3=""
	if [ -n "$test1" ] && [ -n "$test2" ] && [ -n "$test3" ]; then
		if [ "$test1" = passed ] && [ "$test2" = passed ] && [ "$test3" = passed ]; then
			test=passed
		else
			test=remediated
		fi
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