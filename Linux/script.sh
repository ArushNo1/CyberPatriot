#!/bin/bash

# ========================================
#      Linux Mint 21 Setup Script
# ========================================

LOGFILE="setup_log.txt"

# Function to log messages with timestamps
log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOGFILE"
}

# Display header
clear
echo "========================================"
echo "     Linux Mint 21 Setup Script"
echo "========================================"
echo

# Display actions
echo "Select an action to perform:"
echo "1) Update and upgrade system (programs + services)"
echo "2) Manage authorized users and admin privileges"
echo "3) Enable and configure firewall (UFW)"
echo "4) Disable root login and restrict su command"
echo "5) Harden local password policy (pwquality)"
echo

read -rp "Enter the number of the action you want to perform (1-5): " action
echo

case $action in
  1)
    log "Running Action #1: Updating programs and services."
    sudo apt update -y | tee -a "$LOGFILE"
    sudo apt upgrade -y | tee -a "$LOGFILE"
    sudo apt full-upgrade -y | tee -a "$LOGFILE"
    sudo apt autoremove -y | tee -a "$LOGFILE"
    sudo apt autoclean -y | tee -a "$LOGFILE"
    sudo apt --fix-broken install -y | tee -a "$LOGFILE"

    if command -v needrestart >/dev/null 2>&1; then
      log "Restarting updated services..."
      sudo needrestart -r a | tee -a "$LOGFILE"
    else
      log "'needrestart' not found. Installing..."
      sudo apt install -y needrestart | tee -a "$LOGFILE"
      sudo needrestart -r a | tee -a "$LOGFILE"
    fi
    log "✅ Action #1 complete: All programs and services updated successfully."
    ;;

  2)
    log "Running Action #2: User and admin privilege management started."
    echo
    users=$(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd)

    for user in $users; do
      read -rp "Is user '$user' authorized to be on this system? (y/n): " auth
      if [[ "$auth" =~ ^[Nn]$ ]]; then
        log "User '$user' marked unauthorized. Removing account (keeping files)."
        sudo deluser "$user" | tee -a "$LOGFILE"
        log "User '$user' removed; home directory preserved."
      else
        log "User '$user' confirmed authorized."
      fi
      echo
    done

    echo "----------------------------------------"
    echo "Checking users with admin (sudo) privileges..."
    echo "----------------------------------------"

    admins_raw=$(getent group sudo | awk -F: '{print $4}' || true)
    IFS=',' read -r -a admin_array <<< "$admins_raw"

    for admin in "${admin_array[@]}"; do
      admin=$(echo "$admin" | xargs)
      if [ -z "$admin" ]; then continue; fi

      read -rp "Should '$admin' keep admin privileges? (y/n): " keep
      if [[ "$keep" =~ ^[Nn]$ ]]; then
        log "Admin '$admin' marked unauthorized. Removing from sudo group."
        sudo deluser "$admin" sudo | tee -a "$LOGFILE"
        log "User '$admin' demoted to regular user."
      else
        log "Admin '$admin' retains admin privileges."
      fi
      echo
    done

    log "Action #2 complete: User and privilege management finished."
    ;;

  3)
    log "Running Action #3: Enabling and configuring firewall (UFW)."
    sudo ufw --force enable | tee -a "$LOGFILE"
    sudo ufw default reject incoming | tee -a "$LOGFILE"
    sudo ufw default allow outgoing | tee -a "$LOGFILE"
    log "Firewall (UFW) enabled with secure defaults."
    ;;

  4)
    log "Running Action #4: Disable root login and restrict su command."
    if sudo grep -q "^PermitRootLogin" /etc/ssh/sshd_config; then
      sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    else
      echo "PermitRootLogin no" | sudo tee -a /etc/ssh/sshd_config >/dev/null
    fi
    log "SSH root login disabled."

    sudo passwd -l root | tee -a "$LOGFILE"
    log "Root account password locked."
    sudo dpkg-statoverride --update --add root sudo 4750 /bin/su | tee -a "$LOGFILE"
    log "Restricted /bin/su access to 'sudo' group members."
    sudo systemctl restart ssh
    log "SSH service restarted to apply changes."
    log "Action #4 complete: Root login disabled and su restricted."
    ;;

  5)
    log "Running Action #5: Harden local password policy."

    # ---- Install libpam-pwquality ----
    log "Installing libpam-pwquality..."
    sudo apt update -y | tee -a "$LOGFILE"
    sudo apt install -y libpam-pwquality | tee -a "$LOGFILE"

    # ---- Update /etc/pam.d/common-password ----
    if [ ! -f /etc/pam.d/common-password ]; then
      log "ERROR: /etc/pam.d/common-password not found. Aborting."
      exit 1
    fi
    BACKUP="/etc/pam.d/common-password.bak-$(date +%s)"
    sudo cp /etc/pam.d/common-password "$BACKUP"
    log "Backed up /etc/pam.d/common-password to ${BACKUP}."

    sudo bash -c 'cat > /etc/pam.d/common-password <<'"'"'EOF
# /etc/pam.d/common-password
# Enforce password quality and history using pam_pwquality
password requisite pam_pwquality.so retry=3
password required pam_unix.so [success=2 default=ignore] sha512 shadow remember=5
EOF
'"'"''
    log "Updated /etc/pam.d/common-password."

    # ---- Update /etc/security/pwquality.conf ----
    if [ ! -f /etc/security/pwquality.conf ]; then
      log "File /etc/security/pwquality.conf not found — creating it."
      sudo touch /etc/security/pwquality.conf
    fi
    PWQ_BACKUP="/etc/security/pwquality.conf.bak-$(date +%s)"
    sudo cp /etc/security/pwquality.conf "$PWQ_BACKUP"
    log "Backed up /etc/security/pwquality.conf to ${PWQ_BACKUP}."

    sudo bash -c 'cat > /etc/security/pwquality.conf <<'"'"'EOF
# /etc/security/pwquality.conf
# Enforce strong password policy
minlen = 12
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
EOF
'"'"''
    log "Updated /etc/security/pwquality.conf with strong password policy."

    # ---- Verify configuration ----
    log "Verifying PAM and pwquality configuration:"
    sudo grep pam_pwquality /etc/pam.d/common-password | tee -a "$LOGFILE"
    sudo grep -E "minlen|credit" /etc/security/pwquality.conf | tee -a "$LOGFILE"

    log "✅ Action #5 complete: PAM and pwquality policies hardened."
    ;;

  *)
    echo "Invalid selection. Exiting."
    ;;
esac
