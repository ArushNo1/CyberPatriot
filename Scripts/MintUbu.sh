#!/bin/bash

#############################################
# CyberPatriot Security Hardening Script
# For Ubuntu 24 / Linux Mint 21
#############################################

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Log file
LOG_FILE="/var/log/cyberpatriot_audit_$(date +%Y%m%d_%H%M%S).log"

# Secure password for admins
SECURE_ADMIN_PASSWORD=""

#############################################
# Utility Functions
#############################################

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

print_header() {
    echo -e "${CYAN}${BOLD}"
    echo "════════════════════════════════════════════════════════════"
    echo "$1"
    echo "════════════════════════════════════════════════════════════"
    echo -e "${NC}"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
    log_message "SUCCESS: $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
    log_message "ERROR: $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
    log_message "WARNING: $1"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
    log_message "INFO: $1"
}

confirm_action() {
    echo -e -n "${YELLOW}$1 (y/n): ${NC}"
    read -r response
    [[ "$response" =~ ^[Yy]$ ]]
}

press_enter() {
    echo -e "\n${CYAN}Press Enter to continue...${NC}"
    read -r
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

#############################################
# ASCII Art / Splash Screen
#############################################

show_splash() {
    clear
    echo -e "${CYAN}${BOLD}"
    cat << "EOF"
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║    ██████╗ ██████╗ ██████╗      ██████╗ ███╗   ██╗███████╗
    ║   ██╔═══██╗██╔══██╗██╔══██╗    ██╔═══██╗████╗  ██║██╔════╝
    ║   ██║   ██║██║  ██║██║  ██║    ██║   ██║██╔██╗ ██║█████╗  
    ║   ██║   ██║██║  ██║██║  ██║    ██║   ██║██║╚██╗██║██╔══╝  
    ║   ╚██████╔╝██████╔╝██████╔╝    ╚██████╔╝██║ ╚████║███████╗
    ║    ╚═════╝ ╚═════╝ ╚═════╝      ╚═════╝ ╚═╝  ╚═══╝╚══════╝
    ║                                                           ║
    ║            ██████╗ ██╗   ██╗████████╗                    ║
    ║           ██╔═══██╗██║   ██║╚══██╔══╝                    ║
    ║           ██║   ██║██║   ██║   ██║                       ║
    ║           ██║   ██║██║   ██║   ██║                       ║
    ║           ╚██████╔╝╚██████╔╝   ██║                       ║
    ║            ╚═════╝  ╚═════╝    ╚═╝                       ║
    ║                                                           ║
    ║           Security Hardening & Audit Tool                ║
    ║              CyberPatriot Competition                    ║
    ║                   Ubuntu 24 / Mint 21                    ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    echo -e "${YELLOW}                    System: $(hostname)${NC}"
    echo -e "${YELLOW}                    Date: $(date)${NC}"
    echo ""
    sleep 1
}

#############################################
# Task 1: User Auditing
#############################################

user_auditing() {
    print_header "USER AUDITING MODULE"
    
    # Get main username
    echo -e "${CYAN}Enter the main username (currently logged in user):${NC}"
    read -r MAIN_USER
    
    if ! id "$MAIN_USER" &>/dev/null; then
        print_error "User $MAIN_USER does not exist!"
        press_enter
        return 1
    fi
    
    print_success "Main user set to: $MAIN_USER"
    
    # Get secure admin password
    echo -e "\n${CYAN}Enter the secure password for admin accounts:${NC}"
    read -r SECURE_ADMIN_PASSWORD
    echo
    echo -e "${CYAN}Confirm secure password:${NC}"
    read -r SECURE_ADMIN_PASSWORD_CONFIRM
    echo
    
    if [[ "$SECURE_ADMIN_PASSWORD" != "$SECURE_ADMIN_PASSWORD_CONFIRM" ]]; then
        print_error "Passwords do not match!"
        press_enter
        return 1
    fi
    
    print_success "Secure admin password set"
    
    # Get list of authorized admins
    echo -e "\n${CYAN}Enter authorized admin users and their passwords${NC}"
    echo -e "${YELLOW}Format: username (press Enter)${NC}"
    echo -e "${YELLOW}Enter 'done' when finished${NC}\n"
    
    declare -A AUTHORIZED_ADMINS
    while true; do
        echo -e -n "${CYAN}Admin username (or 'done'): ${NC}"
        read -r admin_user
        [[ "$admin_user" == "done" ]] && break
        [[ -z "$admin_user" ]] && continue
        
        echo -e -n "${CYAN}Password for $admin_user: ${NC}"
        read -r admin_pass
        echo
        
        AUTHORIZED_ADMINS["$admin_user"]="$admin_pass"
        print_success "Added admin: $admin_user"
    done
    
    # Get list of authorized regular users
    echo -e "\n${CYAN}Enter authorized regular (non-admin) users${NC}"
    echo -e "${YELLOW}Enter one username per line, 'done' when finished${NC}\n"
    
    AUTHORIZED_USERS=()
    while true; do
        echo -e -n "${CYAN}Username (or 'done'): ${NC}"
        read -r user
        [[ "$user" == "done" ]] && break
        [[ -z "$user" ]] && continue
        
        AUTHORIZED_USERS+=("$user")
        print_success "Added authorized user: $user"
    done
    
    echo ""
    print_header "AUDIT RESULTS"
    
    # Get all human users on the system (UID >= 1000 and < 65534)
    SYSTEM_USERS=()
    while IFS=: read -r username _ uid _ _ home shell; do
        # Skip system users and nobody
        if [[ $uid -ge 1000 && $uid -lt 65534 && "$shell" != "/usr/sbin/nologin" && "$shell" != "/bin/false" ]]; then
            SYSTEM_USERS+=("$username")
        fi
    done < /etc/passwd
    
    print_info "Found ${#SYSTEM_USERS[@]} human users on the system"
    
    # Check for hidden users (UID 500-999 or users with valid shells in unusual ranges)
    echo -e "\n${BOLD}Checking for hidden users...${NC}"
    HIDDEN_USERS=()
    while IFS=: read -r username _ uid _ _ home shell; do
        # Check for users in the 500-999 range with valid shells
        if [[ $uid -ge 500 && $uid -lt 1000 && "$shell" != "/usr/sbin/nologin" && "$shell" != "/bin/false" && "$shell" != "" ]]; then
            # Common system users to ignore
            if [[ "$username" != "sync" && "$username" != "games" && "$username" != "man" && "$username" != "lp" ]]; then
                HIDDEN_USERS+=("$username:$uid")
                print_warning "POTENTIAL HIDDEN USER: $username (UID: $uid, Shell: $shell)"
            fi
        fi
        
        # Check for users with UID < 500 but with bash/sh shells (suspicious)
        if [[ $uid -lt 500 && "$uid" != "0" ]]; then
            if [[ "$shell" == "/bin/bash" || "$shell" == "/bin/sh" || "$shell" == "/bin/zsh" ]]; then
                HIDDEN_USERS+=("$username:$uid")
                print_warning "SUSPICIOUS SYSTEM USER WITH SHELL: $username (UID: $uid, Shell: $shell)"
            fi
        fi
    done < /etc/passwd
    
    if [[ ${#HIDDEN_USERS[@]} -gt 0 ]]; then
        echo -e "\n${RED}${BOLD}Found ${#HIDDEN_USERS[@]} potential hidden user(s)${NC}"
        print_info "These users have UIDs in unusual ranges or suspicious shell access"
        
        if confirm_action "Review and potentially remove these hidden users?"; then
            for hidden_entry in "${HIDDEN_USERS[@]}"; do
                hidden_user="${hidden_entry%%:*}"
                hidden_uid="${hidden_entry##*:}"
                
                echo -e "\n${YELLOW}User: $hidden_user (UID: $hidden_uid)${NC}"
                groups "$hidden_user"
                
                if confirm_action "Remove hidden user $hidden_user?"; then
                    userdel -r "$hidden_user" 2>/dev/null
                    if [[ $? -eq 0 ]]; then
                        print_success "Removed hidden user: $hidden_user"
                    else
                        print_error "Failed to remove user: $hidden_user"
                    fi
                else
                    print_info "Keeping user: $hidden_user"
                fi
            done
        fi
    else
        print_success "No hidden users detected"
    fi
    
    # Disable guest account
    echo -e "\n${BOLD}Checking guest account...${NC}"
    
    # LightDM guest account (Ubuntu/Mint with LightDM)
    local lightdm_conf="/etc/lightdm/lightdm.conf"
    local lightdm_conf_d="/etc/lightdm/lightdm.conf.d"
    
    if [[ -f "$lightdm_conf" ]] || [[ -d "$lightdm_conf_d" ]]; then
        if confirm_action "Disable LightDM guest account?"; then
            # Create lightdm config directory if it doesn't exist
            mkdir -p "$lightdm_conf_d"
            
            # Create/update guest disable config
            cat > "$lightdm_conf_d/50-no-guest.conf" << 'EOF'
[Seat:*]
allow-guest=false
EOF
            print_success "Disabled LightDM guest account"
            changes_made=true
        fi
    fi
    
    # GDM guest account (GNOME Display Manager)
    local gdm_custom="/etc/gdm3/custom.conf"
    if [[ -f "$gdm_custom" ]]; then
        if confirm_action "Disable GDM3 guest account?"; then
            if ! grep -q "TimedLoginEnable=false" "$gdm_custom"; then
                sed -i '/\[daemon\]/a TimedLoginEnable=false' "$gdm_custom"
            fi
            if ! grep -q "AutomaticLoginEnable=false" "$gdm_custom"; then
                sed -i '/\[daemon\]/a AutomaticLoginEnable=false' "$gdm_custom"
            fi
            print_success "Disabled GDM3 automatic/guest login"
            changes_made=true
        fi
    fi
    
    # Disable guest user account if it exists
    if id "guest" &>/dev/null 2>&1; then
        if confirm_action "Lock guest user account?"; then
            passwd -l guest 2>/dev/null
            usermod -s /usr/sbin/nologin guest 2>/dev/null
            print_success "Locked guest account"
            changes_made=true
        fi
    else
        print_success "No guest user account found"
    fi
    
    # Check for unauthorized users
    echo -e "\n${BOLD}Checking for unauthorized users...${NC}"
    UNAUTHORIZED_USERS=()
    
    for sys_user in "${SYSTEM_USERS[@]}"; do
        is_authorized=false
        
        # Check if user is the main user
        if [[ "$sys_user" == "$MAIN_USER" ]]; then
            is_authorized=true
        fi
        
        # Check if user is in admin list
        for admin in "${!AUTHORIZED_ADMINS[@]}"; do
            if [[ "$sys_user" == "$admin" ]]; then
                is_authorized=true
                break
            fi
        done
        
        # Check if user is in regular users list
        for user in "${AUTHORIZED_USERS[@]}"; do
            if [[ "$sys_user" == "$user" ]]; then
                is_authorized=true
                break
            fi
        done
        
        if [[ "$is_authorized" == false ]]; then
            UNAUTHORIZED_USERS+=("$sys_user")
            print_warning "UNAUTHORIZED USER FOUND: $sys_user"
        fi
    done
    
    # Handle unauthorized users
    if [[ ${#UNAUTHORIZED_USERS[@]} -gt 0 ]]; then
        echo -e "\n${RED}${BOLD}Found ${#UNAUTHORIZED_USERS[@]} unauthorized user(s)${NC}"
        if confirm_action "Do you want to remove these unauthorized users?"; then
            for unauth_user in "${UNAUTHORIZED_USERS[@]}"; do
                if confirm_action "Remove user $unauth_user?"; then
                    userdel "$unauth_user" 2>/dev/null
                    if [[ $? -eq 0 ]]; then
                        print_success "Removed user: $unauth_user"
                    else
                        print_error "Failed to remove user: $unauth_user"
                    fi
                fi
            done
        fi
    else
        print_success "No unauthorized users found"
    fi
    
    # Check admin privileges
    echo -e "\n${BOLD}Checking admin privileges...${NC}"
    
    for admin in "${!AUTHORIZED_ADMINS[@]}"; do
        if id "$admin" &>/dev/null; then
            # Check if user is in sudo group
            if groups "$admin" | grep -qw "sudo\|wheel\|admin"; then
                print_success "$admin has admin privileges"
                
                # Update admin password to secure password
                if confirm_action "Update $admin password to the secure password?"; then
                    echo "$admin:$SECURE_ADMIN_PASSWORD" | chpasswd
                    if [[ $? -eq 0 ]]; then
                        print_success "Updated password for $admin"
                        # Force password change on next login (optional)
                        # passwd -e "$admin"
                    else
                        print_error "Failed to update password for $admin"
                    fi
                fi
            else
                print_warning "$admin does NOT have admin privileges"
                if confirm_action "Grant admin privileges to $admin?"; then
                    usermod -aG sudo "$admin"
                    print_success "Granted admin privileges to $admin"
                    
                    # Set secure password
                    echo "$admin:$SECURE_ADMIN_PASSWORD" | chpasswd
                    print_success "Set secure password for $admin"
                fi
            fi
        else
            print_warning "$admin does not exist on the system"
            if confirm_action "Create user $admin with admin privileges?"; then
                useradd -m -s /bin/bash "$admin"
                usermod -aG sudo "$admin"
                echo "$admin:$SECURE_ADMIN_PASSWORD" | chpasswd
                print_success "Created admin user: $admin"
            fi
        fi
    done
    
    # Check for weak/insecure passwords
    echo -e "\n${BOLD}Checking for weak passwords...${NC}"
    print_info "Testing common weak passwords for all users"
    
    local weak_passwords=("password" "123456" "admin" "welcome" "letmein" "Password1" "qwerty" "abc123" "")
    local users_with_weak_passwords=()
    
    for user in "${SYSTEM_USERS[@]}"; do
        # Skip system users that are locked
        if passwd -S "$user" 2>/dev/null | grep -q "L\|NP"; then
            continue
        fi
        
        # Test weak passwords (this is a simplified check)
        # In production, you'd use a more sophisticated method
        local username_as_password=false
        
        # Check if username might be the password (common mistake)
        if echo "$user:$user" | chpasswd --test 2>/dev/null; then
            username_as_password=true
        fi
        
        # Flag users for password review
        if [[ "$username_as_password" == true ]]; then
            users_with_weak_passwords+=("$user")
            print_warning "User $user may have weak password (username as password)"
        fi
    done
    
    if [[ ${#users_with_weak_passwords[@]} -gt 0 ]]; then
        echo -e "\n${YELLOW}Found ${#users_with_weak_passwords[@]} user(s) with potentially weak passwords${NC}"
        
        for user in "${users_with_weak_passwords[@]}"; do
            if confirm_action "Force password change for $user on next login?"; then
                passwd -e "$user"
                print_success "Set password expiry for $user - must change on next login"
            fi
        done
    else
        print_info "Password strength check complete"
    fi
    
    # Check regular users don't have admin privileges
    echo -e "\n${BOLD}Checking regular users for incorrect admin privileges...${NC}"
    
    for user in "${AUTHORIZED_USERS[@]}"; do
        if id "$user" &>/dev/null; then
            if groups "$user" | grep -qw "sudo\|wheel\|admin"; then
                print_warning "$user has admin privileges but should NOT"
                if confirm_action "Remove admin privileges from $user?"; then
                    gpasswd -d "$user" sudo 2>/dev/null
                    gpasswd -d "$user" wheel 2>/dev/null
                    gpasswd -d "$user" admin 2>/dev/null
                    print_success "Removed admin privileges from $user"
                fi
            else
                print_success "$user correctly has no admin privileges"
            fi
        else
            print_warning "$user does not exist on the system"
            if confirm_action "Create user $user?"; then
                useradd -m -s /bin/bash "$user"
                # Set a default password or force change
                echo "$user:ChangeMe123!" | chpasswd
                passwd -e "$user"
                print_success "Created user: $user (must change password on first login)"
            fi
        fi
    done
    
    # Check main user
    echo -e "\n${BOLD}Checking main user...${NC}"
    if groups "$MAIN_USER" | grep -qw "sudo\|wheel\|admin"; then
        print_success "$MAIN_USER has admin privileges"
    else
        print_warning "$MAIN_USER does NOT have admin privileges"
        if confirm_action "Grant admin privileges to $MAIN_USER?"; then
            usermod -aG sudo "$MAIN_USER"
            print_success "Granted admin privileges to $MAIN_USER"
        fi
    fi
    
    print_header "USER AUDIT COMPLETE"
    press_enter
}

#############################################
# Task 2: Disable Root Login
#############################################

disable_root_login() {
    print_header "DISABLE ROOT LOGIN"
    print_info "This module will disable root login for security"
    
    local changes_made=false
    local ssh_config="/etc/ssh/sshd_config"
    local ssh_config_backup="${ssh_config}.bak.$(date +%Y%m%d_%H%M%S)"
    
    # 1. Disable root login via SSH
    echo -e "\n${BOLD}Configuring SSH to disable root login...${NC}"
    
    if [[ -f "$ssh_config" ]]; then
        # Create backup
        cp "$ssh_config" "$ssh_config_backup"
        print_success "Created backup: $ssh_config_backup"
        
        # Check current PermitRootLogin setting
        if grep -q "^PermitRootLogin" "$ssh_config"; then
            # Setting exists, modify it
            sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' "$ssh_config"
            print_success "Modified PermitRootLogin to 'no' in $ssh_config"
            changes_made=true
        elif grep -q "^#PermitRootLogin" "$ssh_config"; then
            # Setting is commented, uncomment and set to no
            sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' "$ssh_config"
            print_success "Uncommented and set PermitRootLogin to 'no' in $ssh_config"
            changes_made=true
        else
            # Setting doesn't exist, add it
            echo "PermitRootLogin no" >> "$ssh_config"
            print_success "Added 'PermitRootLogin no' to $ssh_config"
            changes_made=true
        fi
        
        # Verify the change
        if grep -q "^PermitRootLogin no" "$ssh_config"; then
            print_success "Verified: PermitRootLogin is set to 'no'"
        else
            print_error "Failed to set PermitRootLogin to 'no'"
        fi
        
        # Restart SSH service to apply changes
        if confirm_action "Restart SSH service to apply changes?"; then
            if systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null; then
                print_success "SSH service restarted successfully"
            else
                print_error "Failed to restart SSH service"
            fi
        fi
    else
        print_warning "SSH config file not found at $ssh_config"
    fi
    
    # 2. Lock the root password
    echo -e "\n${BOLD}Locking root password...${NC}"
    
    # Check if root password is already locked
    if passwd -S root 2>/dev/null | grep -q "L"; then
        print_info "Root password is already locked"
    else
        if confirm_action "Lock the root password?"; then
            passwd -l root 2>/dev/null
            if [[ $? -eq 0 ]]; then
                print_success "Root password locked successfully"
                changes_made=true
                
                # Verify the lock
                if passwd -S root 2>/dev/null | grep -q "L"; then
                    print_success "Verified: Root password is locked"
                else
                    print_warning "Could not verify root password lock status"
                fi
            else
                print_error "Failed to lock root password"
            fi
        fi
    fi
    
    # 3. Restrict 'su' command to admin group only
    echo -e "\n${BOLD}Restricting 'su' command to admin group...${NC}"
    
    # Determine the admin group (sudo or wheel)
    local admin_group="sudo"
    if ! getent group sudo >/dev/null 2>&1; then
        if getent group wheel >/dev/null 2>&1; then
            admin_group="wheel"
        else
            print_warning "Neither 'sudo' nor 'wheel' group found"
            admin_group="sudo"
        fi
    fi
    
    print_info "Using admin group: $admin_group"
    
    if [[ -f "/bin/su" ]]; then
        # Get current permissions
        local current_perms=$(stat -c "%a" /bin/su 2>/dev/null)
        local current_group=$(stat -c "%G" /bin/su 2>/dev/null)
        
        print_info "Current /bin/su permissions: $current_perms, group: $current_group"
        
        if confirm_action "Restrict /bin/su to root:$admin_group with 4750 permissions?"; then
            # Change ownership and permissions
            chown root:$admin_group /bin/su
            chmod 4750 /bin/su
            
            # Use dpkg-statoverride to make the change permanent
            # First remove any existing override
            dpkg-statoverride --remove /bin/su 2>/dev/null
            
            # Add the new override
            dpkg-statoverride --update --add root $admin_group 4750 /bin/su
            
            if [[ $? -eq 0 ]]; then
                print_success "Restricted /bin/su to root:$admin_group with 4750 permissions"
                print_success "Override registered with dpkg-statoverride"
                changes_made=true
                
                # Verify the change
                local new_perms=$(stat -c "%a" /bin/su 2>/dev/null)
                local new_group=$(stat -c "%G" /bin/su 2>/dev/null)
                print_success "Verified: /bin/su permissions: $new_perms, group: $new_group"
            else
                print_error "Failed to restrict /bin/su"
            fi
        fi
    else
        print_warning "/bin/su not found, checking /usr/bin/su..."
        
        if [[ -f "/usr/bin/su" ]]; then
            if confirm_action "Restrict /usr/bin/su to root:$admin_group with 4750 permissions?"; then
                chown root:$admin_group /usr/bin/su
                chmod 4750 /usr/bin/su
                dpkg-statoverride --remove /usr/bin/su 2>/dev/null
                dpkg-statoverride --update --add root $admin_group 4750 /usr/bin/su
                
                if [[ $? -eq 0 ]]; then
                    print_success "Restricted /usr/bin/su to root:$admin_group with 4750 permissions"
                    changes_made=true
                else
                    print_error "Failed to restrict /usr/bin/su"
                fi
            fi
        else
            print_error "Could not find 'su' binary"
        fi
    fi
    
    # Summary
    echo -e "\n${BOLD}Summary of Root Login Restrictions:${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    # Check SSH
    if grep -q "^PermitRootLogin no" "$ssh_config" 2>/dev/null; then
        echo -e "${GREEN}✓${NC} SSH root login: DISABLED"
    else
        echo -e "${RED}✗${NC} SSH root login: NOT DISABLED"
    fi
    
    # Check root password
    if passwd -S root 2>/dev/null | grep -q "L"; then
        echo -e "${GREEN}✓${NC} Root password: LOCKED"
    else
        echo -e "${RED}✗${NC} Root password: NOT LOCKED"
    fi
    
    # Check su permissions
    if [[ -f "/bin/su" ]]; then
        local su_perms=$(stat -c "%a" /bin/su 2>/dev/null)
        if [[ "$su_perms" == "4750" ]]; then
            echo -e "${GREEN}✓${NC} /bin/su permissions: RESTRICTED ($su_perms)"
        else
            echo -e "${YELLOW}!${NC} /bin/su permissions: $su_perms"
        fi
    elif [[ -f "/usr/bin/su" ]]; then
        local su_perms=$(stat -c "%a" /usr/bin/su 2>/dev/null)
        if [[ "$su_perms" == "4750" ]]; then
            echo -e "${GREEN}✓${NC} /usr/bin/su permissions: RESTRICTED ($su_perms)"
        else
            echo -e "${YELLOW}!${NC} /usr/bin/su permissions: $su_perms"
        fi
    fi
    
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    if [[ "$changes_made" == true ]]; then
        print_success "Root login has been successfully disabled"
    else
        print_info "No changes were made"
    fi
    
    print_header "ROOT LOGIN DISABLE COMPLETE"
    press_enter
}

#############################################
# Task 3: Firewall Configuration
#############################################

configure_firewall() {
    print_header "FIREWALL CONFIGURATION (UFW)"
    print_info "This module will configure UFW firewall with secure defaults"
    
    local changes_made=false
    
    # 1. Check if UFW is installed
    echo -e "\n${BOLD}Checking UFW installation...${NC}"
    
    if ! command -v ufw &> /dev/null; then
        print_warning "UFW is not installed"
        if confirm_action "Install UFW?"; then
            apt update
            apt install -y ufw
            if [[ $? -eq 0 ]]; then
                print_success "UFW installed successfully"
                changes_made=true
            else
                print_error "Failed to install UFW"
                press_enter
                return 1
            fi
        else
            print_error "UFW is required for this module"
            press_enter
            return 1
        fi
    else
        print_success "UFW is already installed"
    fi
    
    # 2. Check current UFW status
    echo -e "\n${BOLD}Current UFW Status:${NC}"
    ufw status verbose
    echo ""
    
    # 3. Configure default policies
    echo -e "${BOLD}Configuring default firewall policies...${NC}"
    
    if confirm_action "Set default policy to REJECT incoming connections?"; then
        ufw default reject incoming
        print_success "Default incoming policy set to REJECT"
        changes_made=true
    fi
    
    if confirm_action "Set default policy to ALLOW outgoing connections?"; then
        ufw default allow outgoing
        print_success "Default outgoing policy set to ALLOW"
        changes_made=true
    fi
    
    # 4. Allow essential services
    echo -e "\n${BOLD}Configuring essential services...${NC}"
    
    # SSH
    if confirm_action "Allow SSH (port 22) through the firewall?"; then
        ufw allow ssh
        print_success "SSH allowed through firewall"
        changes_made=true
    else
        print_warning "SSH not allowed - you may lose remote access!"
    fi
    
    # HTTPS
    if confirm_action "Allow HTTPS (port 443) through the firewall?"; then
        ufw allow https
        print_success "HTTPS allowed through firewall"
        changes_made=true
    fi
    
    # 6. Review rules before enabling
    echo -e "\n${BOLD}Current Firewall Rules:${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    ufw show added
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    # 7. Enable UFW
    echo -e "\n${BOLD}Enabling UFW...${NC}"
    
    # Check if already enabled
    if ufw status | grep -q "Status: active"; then
        print_info "UFW is already active"
        if [[ "$changes_made" == true ]]; then
            if confirm_action "Reload UFW to apply changes?"; then
                ufw reload
                print_success "UFW reloaded with new rules"
            fi
        fi
    else
        if confirm_action "Enable UFW firewall now?"; then
            # Enable UFW (with --force to avoid interactive prompt)
            ufw --force enable
            if [[ $? -eq 0 ]]; then
                print_success "UFW enabled successfully"
                changes_made=true
            else
                print_error "Failed to enable UFW"
            fi
        else
            print_warning "UFW is configured but NOT enabled"
            print_info "Run 'sudo ufw enable' manually to activate the firewall"
        fi
    fi
    
    # 8. Display final status
    echo -e "\n${BOLD}Final UFW Status:${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    ufw status verbose
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    # 9. Summary
    echo -e "\n${BOLD}Firewall Configuration Summary:${NC}"
    
    if ufw status | grep -q "Status: active"; then
        echo -e "${GREEN}✓${NC} UFW Status: ACTIVE"
    else
        echo -e "${RED}✗${NC} UFW Status: INACTIVE"
    fi
    
    if ufw status verbose | grep -q "Default: reject (incoming)"; then
        echo -e "${GREEN}✓${NC} Default Incoming: REJECT"
    else
        echo -e "${YELLOW}!${NC} Default Incoming: NOT SET TO REJECT"
    fi
    
    if ufw status verbose | grep -q "Default: allow (outgoing)"; then
        echo -e "${GREEN}✓${NC} Default Outgoing: ALLOW"
    else
        echo -e "${YELLOW}!${NC} Default Outgoing: NOT SET TO ALLOW"
    fi
    
    # Count rules
    local rule_count=$(ufw status numbered | grep -c "^\[")
    echo -e "${BLUE}[i]${NC} Total firewall rules: $rule_count"
    
    if [[ "$changes_made" == true ]]; then
        print_success "Firewall configuration completed successfully"
    else
        print_info "No changes were made to the firewall"
    fi
    
    print_header "FIREWALL CONFIGURATION COMPLETE"
    press_enter
}

#############################################
# Task 4: Password Policy Configuration
#############################################

configure_password_policy() {
    print_header "PASSWORD POLICY CONFIGURATION (SYSTEM-WIDE)"
    print_info "Configuring system-wide password policies for ALL users"
    print_warning "These settings apply to existing AND future users"
    
    local changes_made=false
    
    # Get MAIN_USER if not set from user auditing
    if [[ -z "$MAIN_USER" ]]; then
        echo -e "${CYAN}Enter the main username to protect from lockout:${NC}"
        read -r MAIN_USER
        
        if ! id "$MAIN_USER" &>/dev/null; then
            print_error "User $MAIN_USER does not exist!"
            press_enter
            return 1
        fi
    fi
    
    print_success "Protected user: $MAIN_USER (exempt from aging/lockout)"
    echo ""
    
    # 1. Configure system-wide password aging in /etc/login.defs
    echo -e "${BOLD}Configuring system-wide password aging policies...${NC}"
    print_info "Affects ALL users except protected MAIN_USER"
    
    local login_defs="/etc/login.defs"
    
    if [[ -f "$login_defs" ]]; then
        if confirm_action "Configure password aging (Max 90d, Min 7d, Warn 14d)?"; then
            cp "$login_defs" "${login_defs}.bak.$(date +%Y%m%d_%H%M%S)"
            print_success "Created backup of login.defs"
            
            # Update or add PASS_MAX_DAYS
            if grep -q "^PASS_MAX_DAYS" "$login_defs"; then
                sed -i "s/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t90/" "$login_defs"
            elif grep -q "^#PASS_MAX_DAYS" "$login_defs"; then
                sed -i "s/^#PASS_MAX_DAYS.*/PASS_MAX_DAYS\t90/" "$login_defs"
            else
                echo -e "PASS_MAX_DAYS\t90" >> "$login_defs"
            fi
            
            # Update or add PASS_MIN_DAYS
            if grep -q "^PASS_MIN_DAYS" "$login_defs"; then
                sed -i "s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t7/" "$login_defs"
            elif grep -q "^#PASS_MIN_DAYS" "$login_defs"; then
                sed -i "s/^#PASS_MIN_DAYS.*/PASS_MIN_DAYS\t7/" "$login_defs"
            else
                echo -e "PASS_MIN_DAYS\t7" >> "$login_defs"
            fi
            
            # Update or add PASS_WARN_AGE
            if grep -q "^PASS_WARN_AGE" "$login_defs"; then
                sed -i "s/^PASS_WARN_AGE.*/PASS_WARN_AGE\t14/" "$login_defs"
            elif grep -q "^#PASS_WARN_AGE" "$login_defs"; then
                sed -i "s/^#PASS_WARN_AGE.*/PASS_WARN_AGE\t14/" "$login_defs"
            else
                echo -e "PASS_WARN_AGE\t14" >> "$login_defs"
            fi
            
            print_success "System-wide password aging configured"
            print_info "  - Maximum password age: 90 days"
            print_info "  - Minimum password age: 7 days"
            print_info "  - Warning period: 14 days"
            changes_made=true
            
            # Apply to existing users too (except MAIN_USER)
            echo -e "\n${BOLD}Applying to existing users...${NC}"
            local aged_count=0
            local skipped_count=0
            
            while IFS=: read -r username _ uid _ _ home shell; do
                if [[ $uid -ge 1000 && $uid -lt 65534 ]]; then
                    if [[ "$shell" != "/usr/sbin/nologin" && "$shell" != "/bin/false" ]]; then
                        # CRITICAL: Skip MAIN_USER to prevent lockout
                        if [[ "$username" == "$MAIN_USER" ]]; then
                            print_info "Skipped protected user: $MAIN_USER"
                            ((skipped_count++))
                        else
                            chage -M 90 -m 7 -W 14 "$username" 2>/dev/null
                            if [[ $? -eq 0 ]]; then
                                ((aged_count++))
                            fi
                        fi
                    fi
                fi
            done < /etc/passwd
            
            print_success "Applied to $aged_count users, skipped $skipped_count protected user(s)"
        fi
        
        # Configure login security policies
        if confirm_action "Configure login security (timeouts, retries, logging)?"; then
            # LOGIN_TIMEOUT
            if grep -q "^LOGIN_TIMEOUT" "$login_defs"; then
                sed -i "s/^LOGIN_TIMEOUT.*/LOGIN_TIMEOUT\t60/" "$login_defs"
            else
                echo -e "LOGIN_TIMEOUT\t60" >> "$login_defs"
            fi
            
            # LOGIN_RETRIES
            if grep -q "^LOGIN_RETRIES" "$login_defs"; then
                sed -i "s/^LOGIN_RETRIES.*/LOGIN_RETRIES\t5/" "$login_defs"
            else
                echo -e "LOGIN_RETRIES\t5" >> "$login_defs"
            fi
            
            # Enable logging
            if grep -q "^FAILLOG_ENAB" "$login_defs"; then
                sed -i "s/^FAILLOG_ENAB.*/FAILLOG_ENAB\t\tyes/" "$login_defs"
            else
                echo -e "FAILLOG_ENAB\t\tyes" >> "$login_defs"
            fi
            
            if grep -q "^LOG_UNKFAIL_ENAB" "$login_defs"; then
                sed -i "s/^LOG_UNKFAIL_ENAB.*/LOG_UNKFAIL_ENAB\tyes/" "$login_defs"
            else
                echo -e "LOG_UNKFAIL_ENAB\tyes" >> "$login_defs"
            fi
            
            if grep -q "^SYSLOG_SU_ENAB" "$login_defs"; then
                sed -i "s/^SYSLOG_SU_ENAB.*/SYSLOG_SU_ENAB\t\tyes/" "$login_defs"
            else
                echo -e "SYSLOG_SU_ENAB\t\tyes" >> "$login_defs"
            fi
            
            if grep -q "^SYSLOG_SG_ENAB" "$login_defs"; then
                sed -i "s/^SYSLOG_SG_ENAB.*/SYSLOG_SG_ENAB\t\tyes/" "$login_defs"
            else
                echo -e "SYSLOG_SG_ENAB\t\tyes" >> "$login_defs"
            fi
            
            print_success "Login security policies configured"
            print_info "  - Login timeout: 60 seconds"
            print_info "  - Login retries: 5 attempts"
            print_info "  - Failed login logging: Enabled"
            print_info "  - Su/sg logging: Enabled"
            changes_made=true
        fi
    else
        print_error "/etc/login.defs not found"
    fi
    
    # NOTE: PAM password configuration removed to prevent lockouts
    # The following features are configured via /etc/security/pwquality.conf ONLY
    # (does not modify PAM which can cause lockouts)
    
    # 2. Configure password complexity via pwquality.conf (SAFE - no PAM modification)
    echo -e "\n${BOLD}Configuring password complexity requirements...${NC}"
    print_info "Using /etc/security/pwquality.conf (safer than PAM modification)"
    
    local pwquality_conf="/etc/security/pwquality.conf"
    
    if [[ -f "$pwquality_conf" ]]; then
        if confirm_action "Configure password complexity (Min 8 chars, 1 digit, 1 upper, 1 lower, 1 special)?"; then
            cp "$pwquality_conf" "${pwquality_conf}.bak.$(date +%Y%m%d_%H%M%S)"
            print_success "Created backup of pwquality.conf"
            
            # Remove old settings and add new ones at the end
            {
                echo ""
                echo "# CyberPatriot Password Complexity - $(date +%Y-%m-%d)"
                echo "minlen = 8"
                echo "dcredit = -1"
                echo "ucredit = -1"
                echo "lcredit = -1"
                echo "ocredit = -1"
            } >> "$pwquality_conf"
            
            print_success "Password complexity configured"
            print_info "  - Minimum length: 8 characters"
            print_info "  - At least 1 digit required"
            print_info "  - At least 1 uppercase letter required"
            print_info "  - At least 1 lowercase letter required"
            print_info "  - At least 1 special character required"
            print_warning "  - NOTE: PAM not modified to prevent lockouts"
            changes_made=true
        fi
    else
        print_warning "$pwquality_conf not found - password complexity not configured"
    fi
    
    # 4. Configure account lockout policy (system-wide)
    echo -e "\n${BOLD}Configuring system-wide account lockout...${NC}"
    print_info "Locks accounts after repeated failed login attempts"
    print_warning "NOTE: Faillock affects all users - MAIN_USER cannot be exempted from PAM"
    print_info "Make sure you know the password for: $MAIN_USER"
    
    # Check which lockout mechanism is available
    if command -v faillock &>/dev/null || [[ -f "/usr/sbin/faillock" ]]; then
        print_info "System uses 'faillock' for account lockout"
        
        if confirm_action "Configure comprehensive account lockout with PAM?"; then
            local faillock_conf="/etc/security/faillock.conf"
            local common_auth="/etc/pam.d/common-auth"
            local gdm_password="/etc/pam.d/gdm-password"
            local sshd_pam="/etc/pam.d/sshd"
            
            # Step 1: Configure /etc/security/faillock.conf
            echo -e "${BOLD}Step 1: Configuring faillock.conf...${NC}"
            if [[ ! -f "$faillock_conf" ]]; then
                # Create new faillock.conf
                cat > "$faillock_conf" << 'EOF'
# CyberPatriot Account Lockout Configuration
# Lock account after 5 failed attempts for 15 minutes (900 seconds)
# WARNING: This affects ALL users including admins
deny = 5
unlock_time = 900
audit
silent
EOF
                print_success "Created faillock.conf with lockout policy"
                changes_made=true
            else
                # Update existing file
                cp "$faillock_conf" "${faillock_conf}.bak.$(date +%Y%m%d_%H%M%S)"
                
                # Ensure deny and unlock_time are set
                if grep -q "^deny" "$faillock_conf"; then
                    sed -i "s/^deny.*/deny = 5/" "$faillock_conf"
                else
                    echo "deny = 5" >> "$faillock_conf"
                fi
                
                if grep -q "^unlock_time" "$faillock_conf"; then
                    sed -i "s/^unlock_time.*/unlock_time = 900/" "$faillock_conf"
                else
                    echo "unlock_time = 900" >> "$faillock_conf"
                fi
                
                # Add audit if not present
                if ! grep -q "^audit" "$faillock_conf"; then
                    echo "audit" >> "$faillock_conf"
                fi
                
                # Add silent if not present
                if ! grep -q "^silent" "$faillock_conf"; then
                    echo "silent" >> "$faillock_conf"
                fi
                
                print_success "Updated faillock configuration"
                changes_made=true
            fi
            
            # Step 2: Configure PAM common-auth (CAREFUL - this is critical)
            echo -e "\n${BOLD}Step 2: Configuring PAM common-auth...${NC}"
            print_warning "CRITICAL: Modifying PAM auth can lock you out if done incorrectly!"
            print_info "A backup will be created before any changes"
            
            if [[ -f "$common_auth" ]]; then
                if confirm_action "Add faillock to PAM common-auth (SAFE method)?"; then
                    cp "$common_auth" "${common_auth}.bak.$(date +%Y%m%d_%H%M%S)"
                    print_success "Created backup of common-auth"
                    
                    # Check if faillock is already configured
                    if ! grep -q "pam_faillock.so preauth" "$common_auth"; then
                        # Add preauth line BEFORE pam_unix.so
                        sed -i '/pam_unix.so/i auth required pam_faillock.so preauth' "$common_auth"
                        print_success "Added faillock preauth to common-auth"
                        changes_made=true
                    else
                        print_info "Faillock preauth already configured"
                    fi
                    
                    if ! grep -q "pam_faillock.so authfail" "$common_auth"; then
                        # Add authfail line AFTER pam_unix.so
                        sed -i '/pam_unix.so/a auth [default=die] pam_faillock.so authfail' "$common_auth"
                        print_success "Added faillock authfail to common-auth"
                        changes_made=true
                    else
                        print_info "Faillock authfail already configured"
                    fi
                    
                    print_success "PAM common-auth configured for faillock"
                fi
            else
                print_error "$common_auth not found"
            fi
            
            # Step 3: Configure GDM password (prevents root GUI login)
            echo -e "\n${BOLD}Step 3: Configuring GDM to prevent root login...${NC}"
            print_info "This prevents root from logging in via GUI"
            
            if [[ -f "$gdm_password" ]]; then
                if confirm_action "Prevent root from using GUI login (GDM)?"; then
                    cp "$gdm_password" "${gdm_password}.bak.$(date +%Y%m%d_%H%M%S)"
                    print_success "Created backup of gdm-password"
                    
                    # Check if the line already exists
                    if ! grep -q "pam_succeed_if.so user != root" "$gdm_password"; then
                        # Add the line at the beginning of auth section
                        sed -i '/@include common-auth/i auth required pam_succeed_if.so user != root' "$gdm_password"
                        print_success "Added root restriction to GDM"
                        changes_made=true
                    else
                        print_info "GDM root restriction already configured"
                    fi
                fi
            else
                print_warning "$gdm_password not found (GDM may not be installed)"
            fi
            
            # Step 4: Configure SSH with pam_shells (requires valid shell)
            echo -e "\n${BOLD}Step 4: Configuring SSH to require valid shells...${NC}"
            print_info "This prevents users without valid shells from SSH login"
            
            if [[ -f "$sshd_pam" ]]; then
                if confirm_action "Add shell validation to SSH PAM?"; then
                    cp "$sshd_pam" "${sshd_pam}.bak.$(date +%Y%m%d_%H%M%S)"
                    print_success "Created backup of sshd PAM config"
                    
                    # Check if pam_shells is already configured
                    if ! grep -q "pam_shells.so" "$sshd_pam"; then
                        # Add pam_shells at the beginning of auth section
                        sed -i '/@include common-auth/i auth required pam_shells.so' "$sshd_pam"
                        print_success "Added shell validation to SSH"
                        changes_made=true
                    else
                        print_info "SSH shell validation already configured"
                    fi
                fi
            else
                print_warning "$sshd_pam not found"
            fi
            
            # Step 5: Create PAM configuration profiles (ADVANCED - optional)
            echo -e "\n${BOLD}Step 5: Creating PAM configuration profiles...${NC}"
            print_info "These enable advanced faillock features via pam-auth-update"
            print_warning "OPTIONAL: Skip if you're unsure"
            
            if confirm_action "Create PAM configuration profiles for faillock?"; then
                local faillock_config="/usr/share/pam-configs/faillock"
                local faillock_notify_config="/usr/share/pam-configs/faillock_notify"
                
                # Create /usr/share/pam-configs/faillock
                if [[ ! -f "$faillock_config" ]]; then
                    cat > "$faillock_config" << 'EOF'
Name: Enforce failed login attempt counter
Default: no
Priority: 0
Auth-Type: Primary
Auth:
	[default=die] pam_faillock.so authfail
	sufficient pam_faillock.so authsucc
EOF
                    print_success "Created PAM faillock config profile"
                    changes_made=true
                else
                    print_info "PAM faillock config already exists"
                fi
                
                # Create /usr/share/pam-configs/faillock_notify
                if [[ ! -f "$faillock_notify_config" ]]; then
                    cat > "$faillock_notify_config" << 'EOF'
Name: Notify on failed login attempts
Default: no
Priority: 1024
Auth-Type: Primary
Auth:
	requisite pam_faillock.so preauth
EOF
                    print_success "Created PAM faillock notify config profile"
                    changes_made=true
                else
                    print_info "PAM faillock notify config already exists"
                fi
                
                # Prompt to run pam-auth-update
                print_info "PAM profiles created"
                print_warning "You should run 'sudo pam-auth-update' to enable these profiles"
                print_info "Select both options when prompted:"
                print_info "  [*] Notify on failed login attempts"
                print_info "  [*] Enforce failed login attempt counter"
                
                if confirm_action "Run pam-auth-update now (interactive)?"; then
                    print_warning "Use SPACE to select, ENTER to confirm"
                    pam-auth-update
                fi
            fi
            
            # Summary
            print_info "  - Lock after: 5 failed attempts"
            print_info "  - Lockout duration: 15 minutes (auto-unlock)"
            print_info "  - Applies to: ALL users (cannot exempt specific users)"
            print_warning "  - Admin can unlock with: faillock --user <username> --reset"
            print_info "  - PAM common-auth: faillock enabled"
            print_info "  - GDM: root login disabled"
            print_info "  - SSH: shell validation enabled"
        fi
    else
        print_warning "Faillock not found - account lockout not configured"
        print_info "Consider installing faillock or configuring pam_tally2 manually"
    fi
    
    # 5. Summary and verification
    echo -e "\n${BOLD}System-Wide Password Policy Summary:${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    # Check /etc/login.defs settings
    if [[ -f "/etc/login.defs" ]]; then
        local max_days=$(grep "^PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
        local min_days=$(grep "^PASS_MIN_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
        local warn_age=$(grep "^PASS_WARN_AGE" /etc/login.defs 2>/dev/null | awk '{print $2}')
        
        if [[ "$max_days" == "90" ]]; then
            echo -e "${GREEN}✓${NC} Password max age: 90 days"
        else
            echo -e "${YELLOW}!${NC} Password max age: ${max_days:-Not set}"
        fi
        
        if [[ "$min_days" == "7" ]]; then
            echo -e "${GREEN}✓${NC} Password min age: 7 days"
        else
            echo -e "${YELLOW}!${NC} Password min age: ${min_days:-Not set}"
        fi
        
        if [[ "$warn_age" == "14" ]]; then
            echo -e "${GREEN}✓${NC} Password warning: 14 days"
        else
            echo -e "${YELLOW}!${NC} Password warning: ${warn_age:-Not set}"
        fi
    fi
    
    # Check password quality
    if [[ -f "/etc/security/pwquality.conf" ]] && grep -q "^minlen" /etc/security/pwquality.conf 2>/dev/null; then
        local minlen=$(grep "^minlen" /etc/security/pwquality.conf | tail -1 | awk '{print $3}')
        echo -e "${GREEN}✓${NC} Password complexity: CONFIGURED (min length: $minlen)"
    else
        echo -e "${YELLOW}!${NC} Password complexity: NOT CONFIGURED"
    fi
    
    # Check account lockout
    if [[ -f "/etc/security/faillock.conf" ]]; then
        if grep -q "^deny" /etc/security/faillock.conf 2>/dev/null; then
            local deny=$(grep "^deny" /etc/security/faillock.conf | awk '{print $3}')
            echo -e "${GREEN}✓${NC} Account lockout: ENABLED (${deny} attempts)"
        else
            echo -e "${YELLOW}!${NC} Account lockout: CONFIGURED but deny not set"
        fi
    else
        echo -e "${YELLOW}!${NC} Account lockout: NOT CONFIGURED"
    fi
    
    # Check PAM configurations
    if [[ -f "/etc/pam.d/common-auth" ]]; then
        if grep -q "pam_faillock.so preauth" /etc/pam.d/common-auth 2>/dev/null; then
            echo -e "${GREEN}✓${NC} PAM faillock: ENABLED in common-auth"
        else
            echo -e "${YELLOW}!${NC} PAM faillock: NOT ENABLED in common-auth"
        fi
    fi
    
    if [[ -f "/etc/pam.d/gdm-password" ]] && grep -q "pam_succeed_if.so user != root" /etc/pam.d/gdm-password 2>/dev/null; then
        echo -e "${GREEN}✓${NC} GDM root login: DISABLED"
    fi
    
    if [[ -f "/etc/pam.d/sshd" ]] && grep -q "pam_shells.so" /etc/pam.d/sshd 2>/dev/null; then
        echo -e "${GREEN}✓${NC} SSH shell validation: ENABLED"
    fi
    
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    print_warning "IMPORTANT: Policies are SYSTEM-WIDE and affect most users"
    print_success "Protected user: $MAIN_USER (exempt from password aging)"
    print_info "Settings apply to existing users AND future new users"
    print_info "Existing passwords remain valid until changed"
    
    if [[ "$changes_made" == true ]]; then
        print_success "Password policies configured successfully"
    else
        print_info "No changes were made"
    fi
    
    print_header "PASSWORD POLICY CONFIGURATION COMPLETE"
    press_enter
}

#############################################
# Task 5: Service Audit & Prohibited Software Removal
#############################################

audit_services() {
    print_header "SERVICE AUDIT & PROHIBITED SOFTWARE REMOVAL"
    print_info "This module will remove prohibited packages and disable unauthorized services"
    
    local changes_made=false
    local packages_removed=0
    local services_disabled=0
    
    # Define prohibited packages
    local prohibited_packages=(
        "aircrack-ng"
        "apache2"
        "dnsutils"
        "ettercap-text-only"
        "ettercap-graphical"
        "ettercap-common"
        "ftp"
        "hping3"
        "hydra"
        "john"
        "kismet"
        "nessus"
        "netcat"
        "netcat-traditional"
        "netcat-openbsd"
        "nikto"
        "nmap"
        "ophcrack"
        "rsh-client"
        "rsh-server"
        "samba"
        "snort"
        "tcpdump"
        "telnet"
        "telnetd"
        "wireshark"
        "wireshark-qt"
        "wireshark-common"
    )
    
    # Define prohibited services
    local prohibited_services=(
        "apache2"
        "apache"
        "nginx"
        "lighttpd"
        "jetty"
        "httpd"
        "vsftpd"
        "ftpd"
        "telnet"
        "telnetd"
        "samba"
        "smbd"
        "nmbd"
        "snmpd"
        "nis"
        "nfs-common"
        "nfs-kernel-server"
        "rpcbind"
    )
    
    # Check if SSH should be kept
    echo -e "\n${CYAN}SSH Configuration Check${NC}"
    local keep_ssh=false
    if confirm_action "Is SSH/OpenSSH required for this system (check README)?"; then
        keep_ssh=true
        print_info "SSH will be kept and secured"
    else
        print_warning "SSH will be considered for removal"
        prohibited_packages+=("openssh-server" "ssh")
        prohibited_services+=("ssh" "sshd")
    fi
    
    # Part 1: Remove Prohibited Packages (confirm per-package)
    echo -e "\n${BOLD}Step 1: Scanning for prohibited packages...${NC}"
    print_info "Checking for hacking tools, unnecessary servers, and prohibited software"
    
    declare -a found_packages=()
    
    for pkg in "${prohibited_packages[@]}"; do
        if dpkg -l | grep -q "^ii.*$pkg"; then
            found_packages+=("$pkg")
        fi
    done
    
    if [[ ${#found_packages[@]} -eq 0 ]]; then
        print_success "No prohibited packages found!"
    else
        print_warning "Found ${#found_packages[@]} prohibited package(s):"
        for pkg in "${found_packages[@]}"; do
            echo -e "  ${YELLOW}•${NC} $pkg"
        done
        
        # Confirm and remove each package individually
        for pkg in "${found_packages[@]}"; do
            if confirm_action "Remove package: $pkg?"; then
                echo -e "\n${CYAN}Removing: $pkg${NC}"
                
                # Try purge first (removes package and config files)
                if apt purge -y "$pkg" 2>/dev/null; then
                    print_success "Purged: $pkg"
                    ((packages_removed++))
                    changes_made=true
                    log_message "REMOVED PACKAGE: $pkg"
                elif apt remove --purge -y "$pkg" 2>/dev/null; then
                    print_success "Removed: $pkg"
                    ((packages_removed++))
                    changes_made=true
                    log_message "REMOVED PACKAGE: $pkg"
                else
                    print_warning "Could not remove: $pkg (may not be installed or removal failed)"
                fi
            else
                print_info "Skipped removal of: $pkg"
            fi
        done
        
        # Check for netcat in /etc
        echo -e "\n${BOLD}Checking for netcat references in /etc...${NC}"
        if grep -r "netcat" /etc 2>/dev/null | head -5; then
            print_warning "Found netcat references in /etc (shown above)"
            if confirm_action "Review and manually clean netcat references?"; then
                print_info "Use: sudo grep -r netcat /etc"
                print_info "Then manually edit the files to remove references"
            fi
        else
            print_success "No netcat references found in /etc"
        fi
        
        # Remove unwanted Chrome extensions and hacking tools
        echo -e "\n${BOLD}Removing Chrome extensions and security tools...${NC}"
        local unwanted_extra=("chrome-extension" "sqlmap" "wapiti")
        
        if confirm_action "Remove Chrome extensions and SQL injection tools?"; then
            for pkg in "${unwanted_extra[@]}"; do
                if dpkg -l | grep -q "$pkg"; then
                    apt remove -y "$pkg" 2>/dev/null
                    if [[ $? -eq 0 ]]; then
                        print_success "Removed $pkg"
                        ((packages_removed++))
                        changes_made=true
                        log_message "REMOVED PACKAGE: $pkg"
                    fi
                fi
            done
        fi
        
        # Run autoremove to clean up dependencies
        echo -e "\n${BOLD}Cleaning up unused dependencies...${NC}"
        if confirm_action "Run apt autoremove to clean up?"; then
            apt autoremove -y
            print_success "Cleaned up unused dependencies"
        fi
    fi
    
    # Part 2: Audit and Disable Prohibited Services (confirm per-service)
    echo -e "\n${BOLD}Step 2: Scanning for prohibited services...${NC}"
    print_info "Checking active services that should be disabled"
    
    declare -a found_services=()
    
    # Get list of active or enabled prohibited services
    for service in "${prohibited_services[@]}"; do
        # Check if service exists and is active
        if systemctl list-units --type=service --state=active 2>/dev/null | grep -q "$service"; then
            found_services+=("$service")
        elif systemctl is-enabled "$service" 2>/dev/null | grep -q "enabled"; then
            found_services+=("$service")
        fi
    done
    
    if [[ ${#found_services[@]} -eq 0 ]]; then
        print_success "No prohibited services found running!"
    else
        print_warning "Found ${#found_services[@]} service(s) that may need disabling:"
        
        for svc in "${found_services[@]}"; do
            # Get service status
            local status=$(systemctl is-active "$svc" 2>/dev/null || echo "inactive")
            local enabled=$(systemctl is-enabled "$svc" 2>/dev/null || echo "disabled")
            echo -e "  ${YELLOW}•${NC} $svc (status: $status, enabled: $enabled)"
        done
        
        # Confirm and disable/stop each service individually
        for svc in "${found_services[@]}"; do
            local status=$(systemctl is-active "$svc" 2>/dev/null || echo "inactive")
            local enabled=$(systemctl is-enabled "$svc" 2>/dev/null || echo "disabled")
            echo -e "\n${CYAN}Service: $svc (status: $status, enabled: $enabled)${NC}"
            
            if confirm_action "Disable and stop service: $svc?"; then
                echo -e "${CYAN}Disabling service: $svc${NC}"
                
                # Unmask if masked
                systemctl unmask "$svc" 2>/dev/null
                
                # Stop the service
                if systemctl stop "$svc" 2>/dev/null; then
                    print_success "Stopped: $svc"
                fi
                
                # Disable the service
                if systemctl disable "$svc" 2>/dev/null; then
                    print_success "Disabled: $svc"
                    ((services_disabled++))
                    changes_made=true
                    log_message "DISABLED SERVICE: $svc"
                else
                    print_warning "Could not disable: $svc (may not exist or already disabled)"
                fi
                
                # Verify it's stopped
                if systemctl is-active "$svc" 2>/dev/null | grep -q "inactive"; then
                    print_success "Verified: $svc is inactive"
                fi
            else
                print_info "Skipped disabling: $svc"
            fi
        done
    fi
    
    # Part 3: Show all active services for manual review
    echo -e "\n${BOLD}Step 3: Active Services Review${NC}"
    if confirm_action "Display all currently active services for review?"; then
        echo -e "\n${CYAN}Currently Active Services:${NC}"
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        systemctl list-units --type=service --state=active --no-pager | grep -v "^UNIT" | head -20
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        
        echo -e "\n${YELLOW}To check a specific service:${NC}"
        echo -e "  sudo systemctl status <service-name>"
        echo -e "${YELLOW}To disable a service manually:${NC}"
        echo -e "  sudo systemctl disable --now <service-name>"
    fi
    
    # Part 4: Security recommendations
    echo -e "\n${BOLD}Security Recommendations:${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    # Check for web servers
    if systemctl is-active apache2 &>/dev/null || systemctl is-active nginx &>/dev/null; then
        echo -e "${YELLOW}!${NC} Web server detected - disable if not needed"
    else
        echo -e "${GREEN}✓${NC} No active web servers"
    fi
    
    # Check for FTP
    if systemctl is-active vsftpd &>/dev/null || systemctl is-active ftpd &>/dev/null; then
        echo -e "${YELLOW}!${NC} FTP server detected - FTP is insecure, use SFTP instead"
    else
        echo -e "${GREEN}✓${NC} No FTP servers active"
    fi
    
    # Check for Telnet
    if systemctl is-active telnet &>/dev/null || dpkg -l | grep -q "^ii.*telnet"; then
        echo -e "${RED}!${NC} Telnet detected - CRITICAL: Remove immediately (unencrypted)"
    else
        echo -e "${GREEN}✓${NC} No Telnet found"
    fi
    
    # Check for Samba
    if systemctl is-active smbd &>/dev/null || systemctl is-active nmbd &>/dev/null; then
        echo -e "${YELLOW}!${NC} Samba detected - disable if file sharing not needed"
    else
        echo -e "${GREEN}✓${NC} Samba not active"
    fi
    
    # Check for SSH
    if systemctl is-active sshd &>/dev/null || systemctl is-active ssh &>/dev/null; then
        if [[ "$keep_ssh" == true ]]; then
            echo -e "${GREEN}✓${NC} SSH active (required per configuration)"
        else
            echo -e "${YELLOW}!${NC} SSH active - consider disabling if not needed"
        fi
    else
        echo -e "${GREEN}✓${NC} SSH not active"
    fi
    
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    # Part 5: Enable Security Services
    echo -e "\n${BOLD}Step 4: Security Services${NC}"
    print_info "Enabling critical security services"
    
    # Enable AppArmor
    echo -e "\n${BOLD}Checking AppArmor...${NC}"
    if ! systemctl is-active apparmor &>/dev/null; then
        if confirm_action "Enable and start AppArmor?"; then
            systemctl enable apparmor 2>/dev/null
            systemctl start apparmor 2>/dev/null
            if [[ $? -eq 0 ]]; then
                print_success "AppArmor enabled and started"
                changes_made=true
            else
                print_error "Failed to enable AppArmor (may not be installed)"
            fi
        fi
    else
        print_success "AppArmor already running"
    fi
    
    # Enable rsyslog
    echo -e "\n${BOLD}Checking rsyslog...${NC}"
    if ! systemctl is-active rsyslog &>/dev/null; then
        if confirm_action "Enable and start rsyslog (system logging)?"; then
            systemctl enable rsyslog 2>/dev/null
            systemctl start rsyslog 2>/dev/null
            if [[ $? -eq 0 ]]; then
                print_success "rsyslog enabled and started"
                changes_made=true
            else
                print_error "Failed to enable rsyslog"
            fi
        fi
    else
        print_success "rsyslog already running"
    fi
    
    # Part 6: Check for Unauthorized Repositories
    echo -e "\n${BOLD}Step 5: Unauthorized Repository Check${NC}"
    print_info "Checking package sources for unauthorized repositories"
    
    if confirm_action "Scan for potentially unauthorized repositories?"; then
        local suspicious_repos=()
        
        # Check /etc/apt/sources.list
        echo -e "\n${CYAN}Checking /etc/apt/sources.list...${NC}"
        
        # Look for non-standard repositories
        while IFS= read -r line; do
            # Skip comments and empty lines
            [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
            
            # Check for suspicious/non-official repositories
            if ! echo "$line" | grep -q "ubuntu.com\|canonical.com\|linuxmint.com"; then
                # Not an official repo
                suspicious_repos+=("$line")
            fi
        done < /etc/apt/sources.list
        
        # Check /etc/apt/sources.list.d/
        if [[ -d "/etc/apt/sources.list.d" ]]; then
            echo -e "\n${CYAN}Checking /etc/apt/sources.list.d/...${NC}"
            
            for repo_file in /etc/apt/sources.list.d/*.list; do
                if [[ -f "$repo_file" ]]; then
                    while IFS= read -r line; do
                        [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
                        
                        if ! echo "$line" | grep -q "ubuntu.com\|canonical.com\|linuxmint.com\|google.com\|microsoft.com"; then
                            suspicious_repos+=("$(basename "$repo_file"): $line")
                        fi
                    done < "$repo_file"
                fi
            done
        fi
        
        if [[ ${#suspicious_repos[@]} -gt 0 ]]; then
            print_warning "Found ${#suspicious_repos[@]} potentially unauthorized repository entry/entries"
            
            echo -e "\n${YELLOW}Suspicious repositories:${NC}"
            for repo in "${suspicious_repos[@]}"; do
                echo -e "  ${RED}!${NC} $repo"
            done
            
            if confirm_action "Review and remove unauthorized repositories?"; then
                echo -e "\n${YELLOW}Opening repository configuration...${NC}"
                print_info "Review the file and remove any unauthorized entries"
                print_info "Press Ctrl+X to exit nano, then Y to save"
                
                if confirm_action "Edit /etc/apt/sources.list?"; then
                    cp /etc/apt/sources.list /etc/apt/sources.list.bak.$(date +%Y%m%d_%H%M%S)
                    nano /etc/apt/sources.list
                    print_success "Repository file backed up and edited"
                    changes_made=true
                fi
                
                if [[ -d "/etc/apt/sources.list.d" ]]; then
                    if confirm_action "Review /etc/apt/sources.list.d/ files?"; then
                        ls -lh /etc/apt/sources.list.d/
                        
                        for repo_file in /etc/apt/sources.list.d/*.list; do
                            if [[ -f "$repo_file" ]]; then
                                echo -e "\n${BOLD}File: $(basename "$repo_file")${NC}"
                                cat "$repo_file"
                                
                                if confirm_action "Edit this file?"; then
                                    cp "$repo_file" "${repo_file}.bak.$(date +%Y%m%d_%H%M%S)"
                                    nano "$repo_file"
                                    changes_made=true
                                fi
                                
                                if confirm_action "Delete this repository file entirely?"; then
                                    rm -f "$repo_file"
                                    print_success "Removed: $(basename "$repo_file")"
                                    changes_made=true
                                    log_message "REMOVED UNAUTHORIZED REPOSITORY: $(basename "$repo_file")"
                                fi
                            fi
                        done
                    fi
                fi
                
                if [[ "$changes_made" == true ]]; then
                    print_info "Updating package lists after repository changes..."
                    apt update
                fi
            fi
        else
            print_success "All repositories appear to be from official sources"
        fi
    fi
    
    # Final Summary
    echo -e "\n${BOLD}Service Audit Summary:${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}[i]${NC} Prohibited packages removed: $packages_removed"
    echo -e "${BLUE}[i]${NC} Services disabled: $services_disabled"
    
    if [[ "$keep_ssh" == true ]]; then
        echo -e "${GREEN}✓${NC} SSH retained (as required)"
    fi
    
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    if [[ "$changes_made" == true ]]; then
        print_success "Service audit and cleanup completed"
        print_warning "IMPORTANT: Review the README for required services"
        print_info "Removed packages are logged to: $LOG_FILE"
    else
        print_info "No changes were made"
    fi
    
    print_header "SERVICE AUDIT COMPLETE"
    press_enter
}


#############################################
# Task 6: File Permissions Audit
#############################################

audit_file_permissions() {
    print_header "FILE PERMISSIONS AUDIT"
    print_info "This module will secure critical system file permissions"
    
    local changes_made=false
    
    # 1. Secure /etc/shadow permissions
    echo -e "\n${BOLD}Checking /etc/shadow permissions...${NC}"
    
    if [[ -f "/etc/shadow" ]]; then
        local current_perms=$(stat -c "%a" /etc/shadow 2>/dev/null)
        print_info "Current /etc/shadow permissions: $current_perms"
        
        if [[ "$current_perms" != "640" ]]; then
            if confirm_action "Set /etc/shadow permissions to 640 (root:shadow rw-r-----)?"; then
                chmod 640 /etc/shadow
                if [[ $? -eq 0 ]]; then
                    print_success "Set /etc/shadow permissions to 640"
                    changes_made=true
                else
                    print_error "Failed to change /etc/shadow permissions"
                fi
            fi
        else
            print_success "/etc/shadow already has secure permissions (640)"
        fi
    else
        print_error "/etc/shadow not found"
    fi
    
    # 2. Configure sudoers file
    echo -e "\n${BOLD}Configuring sudoers file...${NC}"
    print_info "This will open visudo to verify secure sudo configuration"
    print_warning "Recommended settings:"
    echo -e "  ${CYAN}Defaults authenticate${NC}"
    echo -e "  ${CYAN}root ALL=(ALL:ALL) ALL${NC}"
    echo -e "  ${CYAN}%admin ALL=(ALL) ALL${NC}"
    echo -e "  ${CYAN}%sudo ALL=(ALL:ALL) ALL${NC}"
    
    if confirm_action "Open visudo to review/edit sudoers file?"; then
        print_warning "Remove unauthorized entries, keep @includedir and Defaults lines"
        visudo
        print_success "Finished editing sudoers"
        changes_made=true
    fi
    
    # 3. Secure /proc with hidepid
    echo -e "\n${BOLD}Securing /proc filesystem (hidepid)...${NC}"
    print_info "This prevents users from seeing other users' processes"
    
    if ! grep -q "proc /proc proc defaults,hidepid=2" /etc/fstab; then
        if confirm_action "Add hidepid=2 to /proc in /etc/fstab?"; then
            cp /etc/fstab /etc/fstab.bak.$(date +%Y%m%d_%H%M%S)
            print_success "Created backup of /etc/fstab"
            
            # Check if proc entry exists
            if grep -q "^proc /proc" /etc/fstab; then
                # Modify existing entry
                sed -i 's|^proc /proc proc.*|proc /proc proc defaults,hidepid=2 0 0|' /etc/fstab
            else
                # Add new entry
                echo "proc /proc proc defaults,hidepid=2 0 0" >> /etc/fstab
            fi
            
            print_success "Added hidepid=2 to /etc/fstab"
            
            if confirm_action "Remount /proc now to apply changes?"; then
                mount -o remount /proc
                print_success "Remounted /proc with hidepid=2"
            fi
            
            changes_made=true
        fi
    else
        print_success "/proc already configured with hidepid=2"
    fi
    
    # 4. Secure /tmp with noexec, nodev, nosuid
    echo -e "\n${BOLD}Securing /tmp filesystem...${NC}"
    print_info "This prevents execution of binaries from /tmp"
    
    if ! grep -q "tmpfs /tmp tmpfs defaults,noexec,nodev,nosuid" /etc/fstab; then
        if confirm_action "Configure /tmp with noexec,nodev,nosuid in /etc/fstab?"; then
            if [[ ! -f "/etc/fstab.bak.$(date +%Y%m%d)" ]]; then
                cp /etc/fstab /etc/fstab.bak.$(date +%Y%m%d_%H%M%S)
            fi
            
            # Check if /tmp entry exists
            if grep -q "^tmpfs /tmp" /etc/fstab; then
                # Modify existing entry
                sed -i 's|^tmpfs /tmp tmpfs.*|tmpfs /tmp tmpfs defaults,noexec,nodev,nosuid 0 0|' /etc/fstab
            else
                # Add new entry
                echo "tmpfs /tmp tmpfs defaults,noexec,nodev,nosuid 0 0" >> /etc/fstab
            fi
            
            print_success "Added secure /tmp mount to /etc/fstab"
            
            if confirm_action "Remount /tmp now to apply changes?"; then
                mount -o remount /tmp
                print_success "Remounted /tmp with noexec,nodev,nosuid"
            fi
            
            changes_made=true
        fi
    else
        print_success "/tmp already configured securely"
    fi
    
    # 5. Configure /etc/host.conf
    echo -e "\n${BOLD}Configuring /etc/host.conf...${NC}"
    print_info "This configures hostname resolution order"
    
    if [[ -f "/etc/host.conf" ]]; then
        cp /etc/host.conf /etc/host.conf.bak.$(date +%Y%m%d_%H%M%S)
        
        local needs_update=false
        if ! grep -q "^order hosts, bind" /etc/host.conf; then
            needs_update=true
        fi
        if ! grep -q "^multi on" /etc/host.conf; then
            needs_update=true
        fi
        
        if [[ "$needs_update" == true ]]; then
            if confirm_action "Configure /etc/host.conf with secure settings?"; then
                cat > /etc/host.conf << 'EOF'
# /etc/host.conf - CyberPatriot Secure Configuration
order hosts, bind
multi on
EOF
                print_success "Configured /etc/host.conf"
                changes_made=true
            fi
        else
            print_success "/etc/host.conf already configured"
        fi
    else
        if confirm_action "Create /etc/host.conf with secure settings?"; then
            cat > /etc/host.conf << 'EOF'
# /etc/host.conf - CyberPatriot Secure Configuration
order hosts, bind
multi on
EOF
            print_success "Created /etc/host.conf"
            changes_made=true
        fi
    fi
    
    # Summary
    echo -e "\n${BOLD}File Permissions Audit Summary:${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    if [[ -f "/etc/shadow" ]]; then
        local shadow_perms=$(stat -c "%a" /etc/shadow 2>/dev/null)
        if [[ "$shadow_perms" == "640" ]]; then
            echo -e "${GREEN}✓${NC} /etc/shadow permissions: 640 (secure)"
        else
            echo -e "${YELLOW}!${NC} /etc/shadow permissions: $shadow_perms"
        fi
    fi
    
    if grep -q "proc /proc proc defaults,hidepid=2" /etc/fstab; then
        echo -e "${GREEN}✓${NC} /proc hidepid: Configured"
    else
        echo -e "${YELLOW}!${NC} /proc hidepid: Not configured"
    fi
    
    if grep -q "tmpfs /tmp tmpfs defaults,noexec,nodev,nosuid" /etc/fstab; then
        echo -e "${GREEN}✓${NC} /tmp security: Configured"
    else
        echo -e "${YELLOW}!${NC} /tmp security: Not configured"
    fi
    
    if [[ -f "/etc/host.conf" ]] && grep -q "^order hosts, bind" /etc/host.conf; then
        echo -e "${GREEN}✓${NC} /etc/host.conf: Configured"
    else
        echo -e "${YELLOW}!${NC} /etc/host.conf: Not configured"
    fi
    
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    if [[ "$changes_made" == true ]]; then
        print_success "File permissions audit completed successfully"
    else
        print_info "No changes were made"
    fi
    
    print_header "FILE PERMISSIONS AUDIT COMPLETE"
    press_enter
}

#############################################
# Task 7: Update System
#############################################

update_system() {
    print_header "SYSTEM UPDATE"
    print_info "This module will update the system and configure automatic updates"
    
    local changes_made=false
    
    # 1. Configure automatic updates (FAST)
    echo -e "\n${BOLD}Step 1: Configure Automatic Security Updates${NC}"
    print_info "Configuring unattended-upgrades for automatic security updates"
    
    if confirm_action "Enable automatic security updates?"; then
        # Install unattended-upgrades if not present
        if ! dpkg -l | grep -q "^ii.*unattended-upgrades"; then
            print_info "Installing unattended-upgrades..."
            apt install -y unattended-upgrades apt-listchanges 2>/dev/null
        fi
        
        # Configure automatic update intervals
        local auto_upgrades="/etc/apt/apt.conf.d/20auto-upgrades"
        cat > "$auto_upgrades" << 'EOF'
APT::Periodic::Enable "1";
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
        print_success "Configured automatic update intervals (daily)"
        changes_made=true
        
        # Enable and start the service
        systemctl enable unattended-upgrades 2>/dev/null
        systemctl start unattended-upgrades 2>/dev/null
        print_success "Enabled automatic security updates service"
    fi
    
    # 2. Update package lists (REQUIRED)
    echo -e "\n${BOLD}Step 2: Update Package Lists${NC}"
    if confirm_action "Update apt package lists?"; then
        apt update
        if [[ $? -eq 0 ]]; then
            print_success "Package lists updated"
            changes_made=true
        else
            print_error "Failed to update package lists"
        fi
    fi
    
    # 3. Upgrade packages (COMBINED for speed)
    echo -e "\n${BOLD}Step 3: Upgrade Packages${NC}"
    if confirm_action "Perform full system upgrade (apt upgrade + dist-upgrade)?"; then
        print_info "Running combined upgrade (this may take a few minutes)..."
        apt upgrade -y && apt dist-upgrade -y
        if [[ $? -eq 0 ]]; then
            print_success "System upgraded successfully"
            changes_made=true
        else
            print_error "Upgrade encountered errors"
        fi
    fi
    
    # 4. Cleanup (FAST)
    echo -e "\n${BOLD}Step 4: Cleanup${NC}"
    if confirm_action "Remove unused packages and clean cache?"; then
        apt autoremove -y && apt autoclean
        print_success "Cleanup completed"
        changes_made=true
    fi
    
    # 5. Reboot check
    echo -e "\n${BOLD}Step 5: Reboot Check${NC}"
    if [[ -f /var/run/reboot-required ]]; then
        echo -e "${RED}!${NC} System reboot is required"
        if [[ -f /var/run/reboot-required.pkgs ]]; then
            echo -e "${YELLOW}Packages requiring reboot:${NC}"
            cat /var/run/reboot-required.pkgs | sed 's/^/  - /'
        fi
        print_info "Please reboot the system when convenient"
    else
        print_success "No reboot required"
    fi
    
    # Summary
    echo -e "\n${BOLD}System Update Summary:${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    if [[ "$changes_made" == true ]]; then
        echo -e "${GREEN}✓${NC} System has been updated"
        echo -e "${GREEN}✓${NC} Automatic security updates configured"
        echo -e "${GREEN}✓${NC} Update check interval: Daily"
        echo -e "${GREEN}✓${NC} Security updates: Download and install automatically"
    else
        echo -e "${BLUE}[i]${NC} No updates were performed"
    fi
    
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    print_header "SYSTEM UPDATE COMPLETE"
    press_enter
}

#############################################
# Task 8: Remove Prohibited Software
#############################################

remove_prohibited_software() {
    print_header "REMOVE PROHIBITED SOFTWARE & MEDIA FILES"
    print_info "This module will scan for unauthorized media files"
    
    local changes_made=false
    local files_removed=0
    local files_kept=0
    
    # Define media file extensions to search for
    local media_extensions=(
        "mp3" "mp4" "avi" "mov" "wmv" "flv" "mkv"     # Video/Audio
        "wav" "flac" "aac" "ogg" "m4a"                 # Audio
        "jpg" "jpeg" "png" "gif" "bmp" "tiff" "webp"  # Images
        "iso" "img" "dmg"                              # Disk images
        "exe" "msi" "apk"                              # Executables (suspicious)
        "txt"                                          #leftover messages / files
    )
    
    # Directories to search (user home directories)
    echo -e "\n${BOLD}Scanning for media files in user directories...${NC}"
    print_warning "This will search /home for potentially unauthorized media files"
    
    if ! confirm_action "Start scanning for media files?"; then
        print_info "Media file scan cancelled"
        press_enter
        return
    fi
    
    # Create array to store found files
    declare -a found_files=()
    
    # Search for each extension
    echo -e "\n${CYAN}Searching for media files...${NC}"
    for ext in "${media_extensions[@]}"; do
        echo -e "${BLUE}[i]${NC} Scanning for .$ext files..."
        
        # Find files with this extension in /home (excluding hidden directories)
        while IFS= read -r -d '' file; do
            # Skip files in .cache, .local, .config, etc.
            if [[ ! "$file" =~ /\.[^/]+/ ]]; then
                found_files+=("$file")
            fi
        done < <(find /home -type f -iname "*.${ext}" ! -path "*/.*/*" -print0 2>/dev/null)
    done
    
    # Display results
    echo -e "\n${BOLD}Scan Results:${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    if [[ ${#found_files[@]} -eq 0 ]]; then
        print_success "No media files found!"
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        press_enter
        return
    fi
    
    print_warning "Found ${#found_files[@]} media file(s)"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    # Ask if user wants to review files
    if ! confirm_action "Review and delete media files?"; then
        print_info "Media file removal cancelled"
        press_enter
        return
    fi
    
    # Review each file
    echo -e "\n${BOLD}Reviewing media files...${NC}"
    echo -e "${YELLOW}You will be prompted for each file${NC}\n"
    
    for file in "${found_files[@]}"; do
        # Get file info
        local file_size=$(du -h "$file" 2>/dev/null | cut -f1)
        local file_owner=$(stat -c "%U" "$file" 2>/dev/null)
        local file_modified=$(stat -c "%y" "$file" 2>/dev/null | cut -d' ' -f1)
        
        # Display file info
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${BOLD}File:${NC} $file"
        echo -e "${BOLD}Size:${NC} $file_size"
        echo -e "${BOLD}Owner:${NC} $file_owner"
        echo -e "${BOLD}Modified:${NC} $file_modified"
        
        # Show file type (if available)
        if command -v file &>/dev/null; then
            local file_type=$(file -b "$file" 2>/dev/null)
            echo -e "${BOLD}Type:${NC} $file_type"
        fi
        
        # Prompt to delete
        if confirm_action "Delete this file?"; then
            if rm -f "$file" 2>/dev/null; then
                print_success "Deleted: $file"
                ((files_removed++))
                changes_made=true
                
                # Log to audit log
                log_message "REMOVED MEDIA FILE: $file (size: $file_size, owner: $file_owner)"
            else
                print_error "Failed to delete: $file (check permissions)"
            fi
        else
            print_info "Kept: $file"
            ((files_kept++))
        fi
        
        echo ""
    done
    
    # Final summary
    echo -e "${BOLD}Media File Removal Summary:${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}[i]${NC} Total files found: ${#found_files[@]}"
    echo -e "${GREEN}✓${NC} Files removed: $files_removed"
    echo -e "${YELLOW}!${NC} Files kept: $files_kept"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    if [[ "$changes_made" == true ]]; then
        print_success "Media file cleanup completed"
        print_info "Removed files are permanently deleted"
    else
        print_info "No files were removed"
    fi
    
    # Part 4.5: Backdoor Detection
    echo -e "\n${BOLD}Step 3.5: Backdoor Detection${NC}"
    print_info "Scanning for common backdoors and suspicious scripts"
    
    if confirm_action "Scan for backdoors?"; then
        local backdoors_found=0
        
        # Check for netcat backdoors (listening netcat processes)
        echo -e "\n${CYAN}Checking for netcat backdoors...${NC}"
        if pgrep -f "nc.*-l" &>/dev/null || pgrep -f "ncat.*-l" &>/dev/null; then
            print_warning "Found listening netcat process - potential backdoor!"
            ps aux | grep -E "nc.*-l|ncat.*-l" | grep -v grep
            
            if confirm_action "Kill netcat listening processes?"; then
                pkill -f "nc.*-l"
                pkill -f "ncat.*-l"
                print_success "Killed netcat processes"
                changes_made=true
                ((backdoors_found++))
            fi
        else
            print_success "No netcat backdoors detected"
        fi
        
        # Check for python backdoors (reverse shells, suspicious listening scripts)
        echo -e "\n${CYAN}Checking for Python backdoors...${NC}"
        
        # Search for suspicious Python scripts in common locations
        local suspicious_python_scripts=()
        
        # Check for python scripts with socket/subprocess usage (common in backdoors)
        while IFS= read -r -d '' file; do
            if grep -l "socket\|subprocess\|os.system\|eval\|exec" "$file" &>/dev/null; then
                # Further check for suspicious patterns
                if grep -q "socket.*connect\|socket.*bind\|subprocess.*shell=True\|os.system.*bash" "$file"; then
                    suspicious_python_scripts+=("$file")
                fi
            fi
        done < <(find /home /tmp /var/tmp -type f -name "*.py" -print0 2>/dev/null)
        
        if [[ ${#suspicious_python_scripts[@]} -gt 0 ]]; then
            print_warning "Found ${#suspicious_python_scripts[@]} suspicious Python script(s)"
            
            for script in "${suspicious_python_scripts[@]}"; do
                echo -e "\n${YELLOW}Suspicious script: $script${NC}"
                echo -e "${BOLD}Owner:${NC} $(stat -c "%U" "$script" 2>/dev/null)"
                echo -e "${BOLD}Modified:${NC} $(stat -c "%y" "$script" 2>/dev/null | cut -d' ' -f1)"
                
                if confirm_action "View this script?"; then
                    head -20 "$script"
                    echo "..."
                fi
                
                if confirm_action "Remove this Python script?"; then
                    rm -f "$script"
                    print_success "Removed: $script"
                    changes_made=true
                    ((backdoors_found++))
                    log_message "REMOVED PYTHON BACKDOOR: $script"
                fi
            done
        else
            print_success "No suspicious Python scripts detected"
        fi
        
        # Check for unauthorized SSH keys
        echo -e "\n${CYAN}Checking for unauthorized SSH keys...${NC}"
        
        for home_dir in /home/*; do
            if [[ -d "$home_dir/.ssh" ]]; then
                local username=$(basename "$home_dir")
                
                if [[ -f "$home_dir/.ssh/authorized_keys" ]]; then
                    local key_count=$(wc -l < "$home_dir/.ssh/authorized_keys")
                    
                    if [[ $key_count -gt 0 ]]; then
                        echo -e "\n${YELLOW}User $username has $key_count SSH key(s)${NC}"
                        
                        if confirm_action "Review SSH keys for $username?"; then
                            cat "$home_dir/.ssh/authorized_keys"
                            
                            if confirm_action "Remove ALL SSH keys for $username?"; then
                                rm -f "$home_dir/.ssh/authorized_keys"
                                print_success "Removed SSH keys for $username"
                                changes_made=true
                                ((backdoors_found++))
                            fi
                        fi
                    fi
                fi
            fi
        done
        
        # Check for suspicious listening ports
        echo -e "\n${CYAN}Checking for suspicious listening ports...${NC}"
        print_info "Common backdoor ports: 1337, 31337, 4444, 5555, 6666, 8888"
        
        local suspicious_ports=(1337 31337 4444 5555 6666 8888 12345)
        local suspicious_found=false
        
        for port in "${suspicious_ports[@]}"; do
            if ss -tlnp | grep -q ":$port "; then
                print_warning "Found process listening on port $port (common backdoor port)"
                ss -tlnp | grep ":$port "
                suspicious_found=true
            fi
        done
        
        if [[ "$suspicious_found" == false ]]; then
            print_success "No processes listening on common backdoor ports"
        fi
        
        # Check for suspicious files in /tmp and /var/tmp
        echo -e "\n${CYAN}Checking /tmp and /var/tmp for backdoors...${NC}"
        
        local suspicious_files=(
            "/tmp/.ICE-unix/backdoor"
            "/tmp/.X11-unix/backdoor"
            "/var/tmp/.backdoor"
            "/dev/shm/backdoor"
        )
        
        for file in /tmp/.* /tmp/* /var/tmp/.* /var/tmp/* /dev/shm/*; do
            if [[ -f "$file" ]] && file "$file" 2>/dev/null | grep -q "executable\|script"; then
                # Check if it's a shell script or executable
                if [[ -x "$file" ]] || head -1 "$file" 2>/dev/null | grep -q "^#!"; then
                    echo -e "\n${YELLOW}Suspicious executable: $file${NC}"
                    ls -lh "$file"
                    
                    if confirm_action "Remove this file?"; then
                        rm -f "$file"
                        print_success "Removed: $file"
                        changes_made=true
                        ((backdoors_found++))
                    fi
                fi
            fi
        done
        
        echo -e "\n${BOLD}Backdoor Scan Summary:${NC}"
        if [[ $backdoors_found -gt 0 ]]; then
            echo -e "${YELLOW}!${NC} Found and removed $backdoors_found potential backdoor(s)"
        else
            print_success "No backdoors detected"
        fi
    fi
    
    # Part 5: Audit Cronjobs
    echo -e "\n${BOLD}Step 4: Cronjob Audit${NC}"
    print_info "Checking for scheduled tasks (cronjobs) on the system"
    
    if ! confirm_action "Scan and review cronjobs?"; then
        print_info "Cronjob audit skipped"
        print_header "MEDIA FILE REMOVAL COMPLETE"
        press_enter
        return
    fi
    
    local cron_changes=false
    local crons_removed=0
    
    # Check system-wide crontabs
    echo -e "\n${CYAN}Scanning system-wide crontabs...${NC}"
    
    # 1. Check /etc/crontab
    if [[ -f "/etc/crontab" ]]; then
        echo -e "\n${BOLD}System Crontab (/etc/crontab):${NC}"
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        cat /etc/crontab
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        
        if confirm_action "Edit /etc/crontab to remove suspicious entries?"; then
            print_warning "Opening /etc/crontab in nano - remove any suspicious lines"
            nano /etc/crontab
            print_success "Finished editing /etc/crontab"
            cron_changes=true
        fi
    fi
    
    # 2. Check /etc/cron.d/*
    if [[ -d "/etc/cron.d" ]] && [[ -n "$(ls -A /etc/cron.d 2>/dev/null)" ]]; then
        echo -e "\n${BOLD}Cron Jobs in /etc/cron.d/:${NC}"
        for cronfile in /etc/cron.d/*; do
            if [[ -f "$cronfile" ]]; then
                echo -e "\n${YELLOW}File: $cronfile${NC}"
                echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                cat "$cronfile"
                echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                
                if confirm_action "Delete this cron file: $(basename $cronfile)?"; then
                    if rm -f "$cronfile" 2>/dev/null; then
                        print_success "Deleted: $cronfile"
                        ((crons_removed++))
                        cron_changes=true
                        log_message "REMOVED CRON FILE: $cronfile"
                    else
                        print_error "Failed to delete: $cronfile"
                    fi
                fi
            fi
        done
    else
        print_info "No files in /etc/cron.d/"
    fi
    
    # 3. Check user crontabs
    echo -e "\n${BOLD}User Crontabs:${NC}"
    local found_user_crons=false
    
    # Get list of users with crontabs
    for user_cron in /var/spool/cron/crontabs/*; do
        if [[ -f "$user_cron" ]]; then
            found_user_crons=true
            local username=$(basename "$user_cron")
            
            echo -e "\n${YELLOW}Crontab for user: $username${NC}"
            echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            crontab -u "$username" -l 2>/dev/null || cat "$user_cron"
            echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            
            if confirm_action "Edit crontab for user $username?"; then
                print_warning "Opening crontab editor - delete suspicious entries or remove all"
                crontab -u "$username" -e
                print_success "Finished editing crontab for $username"
                cron_changes=true
            fi
            
            if confirm_action "Remove ALL cronjobs for user $username?"; then
                crontab -u "$username" -r 2>/dev/null
                if [[ $? -eq 0 ]]; then
                    print_success "Removed all cronjobs for $username"
                    ((crons_removed++))
                    cron_changes=true
                    log_message "REMOVED ALL CRONTABS FOR USER: $username"
                else
                    print_error "Failed to remove crontabs for $username"
                fi
            fi
        fi
    done
    
    if [[ "$found_user_crons" == false ]]; then
        print_success "No user crontabs found"
    fi
    
    # 4. Check periodic cron directories
    for cron_dir in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
        if [[ -d "$cron_dir" ]] && [[ -n "$(ls -A $cron_dir 2>/dev/null)" ]]; then
            echo -e "\n${BOLD}Scripts in $cron_dir:${NC}"
            ls -lh "$cron_dir"
            
            for script in "$cron_dir"/*; do
                if [[ -f "$script" ]] && [[ -x "$script" ]]; then
                    echo -e "\n${YELLOW}Script: $(basename $script)${NC}"
                    
                    if confirm_action "View contents of $(basename $script)?"; then
                        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                        head -20 "$script"
                        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                    fi
                    
                    if confirm_action "Delete this script: $(basename $script)?"; then
                        if rm -f "$script" 2>/dev/null; then
                            print_success "Deleted: $script"
                            ((crons_removed++))
                            cron_changes=true
                            log_message "REMOVED CRON SCRIPT: $script"
                        else
                            print_error "Failed to delete: $script"
                        fi
                    fi
                fi
            done
        fi
    done
    
    # Summary
    echo -e "\n${BOLD}Cronjob Audit Summary:${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}[i]${NC} Cronjobs/scripts removed: $crons_removed"
    
    if [[ "$cron_changes" == true ]]; then
        echo -e "${GREEN}✓${NC} Cronjob audit completed with changes"
        
        # Restart cron service to apply changes
        if confirm_action "Restart cron service to apply changes?"; then
            systemctl restart cron 2>/dev/null || systemctl restart crond 2>/dev/null
            print_success "Cron service restarted"
        fi
    else
        echo -e "${BLUE}[i]${NC} No changes made to cronjobs"
    fi
    
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    print_header "MEDIA FILE REMOVAL COMPLETE"
    press_enter
}

#############################################
# Task 9: SSH Hardening
#############################################

harden_ssh() {
    print_header "SSH HARDENING"
    print_info "This module will harden SSH configuration"
    
    local changes_made=false
    local ssh_config="/etc/ssh/sshd_config"
    
    # Check if SSH is installed
    if [[ ! -f "$ssh_config" ]]; then
        print_warning "SSH is not installed or config file not found"
        press_enter
        return 1
    fi
    
    # Backup config
    cp "$ssh_config" "${ssh_config}.bak.$(date +%Y%m%d_%H%M%S)"
    print_success "Created backup of sshd_config"
    
    # Helper function to set SSH config parameter
    set_ssh_param() {
        local param=$1
        local value=$2
        
        if grep -q "^${param}" "$ssh_config"; then
            sed -i "s/^${param}.*/${param} ${value}/" "$ssh_config"
        elif grep -q "^#${param}" "$ssh_config"; then
            sed -i "s/^#${param}.*/${param} ${value}/" "$ssh_config"
        else
            echo "${param} ${value}" >> "$ssh_config"
        fi
    }
    
    echo -e "\n${BOLD}Configuring SSH security settings...${NC}"
    
    if confirm_action "Apply comprehensive SSH hardening?"; then
        # Protocol 2 only
        set_ssh_param "Protocol" "2"
        print_success "Set Protocol 2"
        
        # Change port to 2222
        if confirm_action "Change SSH port to 2222 (non-standard port)?"; then
            set_ssh_param "Port" "2222"
            print_success "Set Port 2222"
            print_warning "Remember to update firewall rules for port 2222!"
        fi
        
        # Address family (IPv4 only)
        set_ssh_param "AddressFamily" "inet"
        print_success "Set AddressFamily inet (IPv4 only)"
        
        # Disable root login
        set_ssh_param "PermitRootLogin" "no"
        print_success "Set PermitRootLogin no"
        
        # Disable X11 forwarding
        set_ssh_param "X11Forwarding" "no"
        print_success "Set X11Forwarding no"
        
        # Enable PAM
        set_ssh_param "UsePAM" "yes"
        print_success "Set UsePAM yes"
        
        # Additional security settings
        set_ssh_param "PermitEmptyPasswords" "no"
        set_ssh_param "MaxAuthTries" "3"
        set_ssh_param "HostbasedAuthentication" "no"
        set_ssh_param "IgnoreRhosts" "yes"
        set_ssh_param "PasswordAuthentication" "yes"
        set_ssh_param "PubkeyAuthentication" "yes"
        
        print_success "Applied additional SSH security settings"
        changes_made=true
    fi
    
    # AllowUsers / DenyUsers configuration
    echo -e "\n${BOLD}Configuring SSH user access...${NC}"
    print_warning "You can restrict SSH access to specific users"
    
    if confirm_action "Configure AllowUsers (whitelist specific users)?"; then
        echo -e "${CYAN}Enter usernames to allow (space-separated), or leave empty to skip:${NC}"
        read -r allowed_users
        
        if [[ -n "$allowed_users" ]]; then
            # Remove existing AllowUsers/DenyUsers lines
            sed -i '/^AllowUsers/d' "$ssh_config"
            sed -i '/^DenyUsers/d' "$ssh_config"
            
            echo "AllowUsers $allowed_users" >> "$ssh_config"
            print_success "Set AllowUsers: $allowed_users"
            changes_made=true
        fi
    fi
    
    # Display final config
    echo -e "\n${BOLD}Current SSH Configuration:${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    grep "^Protocol\|^Port\|^AddressFamily\|^PermitRootLogin\|^X11Forwarding\|^UsePAM\|^AllowUsers\|^DenyUsers\|^PermitEmptyPasswords\|^MaxAuthTries" "$ssh_config"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    # Restart SSH
    if [[ "$changes_made" == true ]]; then
        echo -e "\n${BOLD}Restarting SSH service...${NC}"
        if confirm_action "Restart SSH service to apply changes?"; then
            systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
            if [[ $? -eq 0 ]]; then
                print_success "SSH service restarted"
                print_warning "If you changed the port, reconnect using: ssh -p 2222 user@host"
            else
                print_error "Failed to restart SSH service"
            fi
        fi
    fi
    
    print_header "SSH HARDENING COMPLETE"
    press_enter
}

#############################################
# Task 10: Enable Security Features
#############################################

enable_security_features() {
    print_header "ENABLE SECURITY FEATURES"
    print_info "This module will enable various system security features"
    
    local changes_made=false
    
    # 1. Enable ASLR (Address Space Layout Randomization)
    echo -e "\n${BOLD}Checking ASLR (Address Space Layout Randomization)...${NC}"
    
    local aslr_value=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null)
    print_info "Current ASLR value: $aslr_value (0=disabled, 1=partial, 2=full)"
    
    if [[ "$aslr_value" != "2" ]]; then
        if confirm_action "Enable full ASLR (randomize_va_space=2)?"; then
            sysctl -w kernel.randomize_va_space=2
            
            # Make it permanent
            if ! grep -q "^kernel.randomize_va_space" /etc/sysctl.conf; then
                echo "kernel.randomize_va_space=2" >> /etc/sysctl.conf
            else
                sed -i 's/^kernel.randomize_va_space.*/kernel.randomize_va_space=2/' /etc/sysctl.conf
            fi
            
            sysctl -p
            print_success "ASLR enabled (full randomization)"
            changes_made=true
        fi
    else
        print_success "ASLR already enabled (full randomization)"
    fi
    
    # 2. Configure /etc/sysctl.conf for network security
    echo -e "\n${BOLD}Configuring sysctl network security settings...${NC}"
    
    if confirm_action "Apply comprehensive sysctl security settings?"; then
        local sysctl_conf="/etc/sysctl.conf"
        cp "$sysctl_conf" "${sysctl_conf}.bak.$(date +%Y%m%d_%H%M%S)"
        print_success "Created backup of sysctl.conf"
        
        # Network security parameters
        local sysctl_params=(
            "net.ipv4.conf.all.rp_filter=1"
            "net.ipv4.conf.default.rp_filter=1"
            "net.ipv4.icmp_echo_ignore_broadcasts=1"
            "net.ipv4.conf.all.accept_source_route=0"
            "net.ipv6.conf.all.accept_source_route=0"
            "net.ipv4.conf.default.accept_source_route=0"
            "net.ipv6.conf.default.accept_source_route=0"
            "net.ipv4.conf.all.send_redirects=0"
            "net.ipv4.conf.default.send_redirects=0"
            "net.ipv4.tcp_syncookies=1"
            "net.ipv4.tcp_max_syn_backlog=2048"
            "net.ipv4.tcp_synack_retries=2"
            "net.ipv4.tcp_syn_retries=5"
            "net.ipv4.conf.all.log_martians=1"
            "net.ipv4.icmp_ignore_bogus_error_responses=1"
            "net.ipv4.conf.all.accept_redirects=0"
            "net.ipv6.conf.all.accept_redirects=0"
            "net.ipv4.conf.default.accept_redirects=0"
            "net.ipv6.conf.default.accept_redirects=0"
            "net.ipv4.icmp_echo_ignore_all=1"
            "net.ipv4.ip_forward=0"
            "net.ipv6.conf.all.disable_ipv6=1"
            "net.ipv6.conf.default.disable_ipv6=1"
            "net.ipv6.conf.lo.disable_ipv6=1"
            "net.ipv4.tcp_rfc1337=1"
            "kernel.yama.ptrace_scope=1"
            "kernel.pid_max=32768"
            "fs.protected_symlinks=1"
            "fs.protected_fifos=1"
        )
        
        echo -e "\n# CyberPatriot Security Settings - $(date +%Y-%m-%d)" >> "$sysctl_conf"
        
        for param in "${sysctl_params[@]}"; do
            local key="${param%%=*}"
            local value="${param##*=}"
            
            # Remove existing entry if present
            sed -i "/^${key}/d" "$sysctl_conf"
            sed -i "/^#${key}/d" "$sysctl_conf"
            
            # Add new entry
            echo "$param" >> "$sysctl_conf"
        done
        
        # Apply settings
        sysctl -p
        print_success "Applied sysctl security settings"
        changes_made=true
    fi
    
    # 3. Disable X Server TCP connections
    echo -e "\n${BOLD}Disabling X Server TCP connections...${NC}"
    print_info "This prevents remote X11 connections which can be a security risk"
    
    if confirm_action "Disable X Server TCP listening?"; then
        local lightdm_conf="/etc/lightdm/lightdm.conf"
        local lightdm_conf_d="/etc/lightdm/lightdm.conf.d"
        local gdm_custom="/etc/gdm3/custom.conf"
        
        # For LightDM
        if [[ -d "$lightdm_conf_d" ]] || [[ -f "$lightdm_conf" ]]; then
            mkdir -p "$lightdm_conf_d"
            cat > "$lightdm_conf_d/50-xserver-command.conf" << 'EOF'
[Seat:*]
xserver-command=X -nolisten tcp
EOF
            print_success "Configured LightDM to disable X Server TCP listening"
            changes_made=true
        fi
        
        # For GDM3
        if [[ -f "$gdm_custom" ]]; then
            if ! grep -q "DisallowTCP=true" "$gdm_custom"; then
                sed -i '/\[security\]/a DisallowTCP=true' "$gdm_custom"
                print_success "Configured GDM3 to disable X Server TCP listening"
                changes_made=true
            fi
        fi
        
        # Also configure via X11 startup
        local x11_startup="/etc/X11/xinit/xserverrc"
        if [[ -f "$x11_startup" ]]; then
            if ! grep -q "nolisten tcp" "$x11_startup"; then
                sed -i 's/exec \/usr\/bin\/X.*/exec \/usr\/bin\/X -nolisten tcp "$@"/' "$x11_startup"
                print_success "Configured X11 startup to disable TCP listening"
                changes_made=true
            fi
        else
            # Create the file if it doesn't exist
            cat > "$x11_startup" << 'EOF'
#!/bin/sh
exec /usr/bin/X -nolisten tcp "$@"
EOF
            chmod +x "$x11_startup"
            print_success "Created X11 startup configuration to disable TCP listening"
            changes_made=true
        fi
    fi
    
    # 4. Check for insecure sudo configurations
    echo -e "\n${BOLD}Checking sudo configuration for security issues...${NC}"
    
    local sudoers_file="/etc/sudoers"
    local insecure_sudo=false
    
    # Check for NOPASSWD entries
    if grep -rq "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
        print_warning "Found NOPASSWD entries in sudo configuration"
        insecure_sudo=true
        
        echo -e "\n${YELLOW}Insecure sudo entries:${NC}"
        grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v "^#"
        
        if confirm_action "Remove NOPASSWD entries from sudo configuration?"; then
            # Backup sudoers
            cp "$sudoers_file" "${sudoers_file}.bak.$(date +%Y%m%d_%H%M%S)"
            
            # Remove NOPASSWD from main sudoers file
            sed -i 's/NOPASSWD://g' "$sudoers_file"
            
            # Remove NOPASSWD from sudoers.d files
            for file in /etc/sudoers.d/*; do
                if [[ -f "$file" ]]; then
                    sed -i 's/NOPASSWD://g' "$file"
                fi
            done
            
            print_success "Removed NOPASSWD entries from sudo configuration"
            changes_made=true
        fi
    else
        print_success "No insecure NOPASSWD entries found in sudo configuration"
    fi
    
    # Check for overly permissive sudo rules
    if grep -rq "ALL=(ALL:ALL) ALL" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v "^#" | grep -v "%sudo"; then
        print_warning "Found potentially overly permissive sudo rules"
        echo -e "\n${YELLOW}Review these sudo rules:${NC}"
        grep -r "ALL=(ALL:ALL) ALL" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v "^#" | grep -v "%sudo"
    fi
    
    # 5. Install and configure Fail2Ban
    echo -e "\n${BOLD}Configuring Fail2Ban...${NC}"
    
    if ! command -v fail2ban-client &>/dev/null; then
        if confirm_action "Install Fail2Ban for intrusion prevention?"; then
            apt install -y fail2ban
            if [[ $? -eq 0 ]]; then
                print_success "Fail2Ban installed"
                changes_made=true
            else
                print_error "Failed to install Fail2Ban"
            fi
        fi
    else
        print_success "Fail2Ban already installed"
    fi
    
    if command -v fail2ban-client &>/dev/null; then
        if confirm_action "Configure Fail2Ban for SSH protection?"; then
            local jail_local="/etc/fail2ban/jail.local"
            
            cat > "$jail_local" << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled  = true
port     = ssh,2222
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3
EOF
            
            print_success "Configured Fail2Ban for SSH"
            
            systemctl enable fail2ban
            systemctl restart fail2ban
            print_success "Fail2Ban enabled and restarted"
            changes_made=true
        fi
    fi
    
    # 7. Configure GRUB security
    echo -e "\n${BOLD}Configuring GRUB security...${NC}"
    
    if [[ -f "/etc/default/grub" ]]; then
        if confirm_action "Add security=apparmor to GRUB configuration?"; then
            cp /etc/default/grub /etc/default/grub.bak.$(date +%Y%m%d_%H%M%S)
            
            if grep -q "GRUB_CMDLINE_LINUX=" /etc/default/grub; then
                if ! grep "GRUB_CMDLINE_LINUX=" /etc/default/grub | grep -q "security=apparmor"; then
                    sed -i 's/GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX="security=apparmor /' /etc/default/grub
                    print_success "Added security=apparmor to GRUB"
                    
                    update-grub
                    print_success "GRUB configuration updated"
                    changes_made=true
                else
                    print_success "security=apparmor already in GRUB configuration"
                fi
            fi
        fi
    fi
    
    # 8. Configure DNS (if BIND is installed)
    if [[ -f "/etc/bind/named.conf.options" ]]; then
        echo -e "\n${BOLD}Configuring DNS (BIND) security...${NC}"
        
        if confirm_action "Disable DNS recursion and hide version?"; then
            cp /etc/bind/named.conf.options /etc/bind/named.conf.options.bak.$(date +%Y%m%d_%H%M%S)
            
            # Add to options section if not present
            if ! grep -q "recursion no;" /etc/bind/named.conf.options; then
                sed -i '/options {/a \    recursion no;' /etc/bind/named.conf.options
                print_success "Disabled DNS recursion"
            fi
            
            if ! grep -q "version" /etc/bind/named.conf.options; then
                sed -i '/options {/a \    version "Not Disclosed";' /etc/bind/named.conf.options
                print_success "Hidden BIND version"
            fi
            
            systemctl restart bind9 2>/dev/null
            print_success "BIND9 restarted"
            changes_made=true
        fi
    fi
    
    # 9. Web Server Security (ask first if it should be configured or disabled)
    echo -e "\n${BOLD}Web Server Configuration${NC}"
    
    local is_web_server=false
    if confirm_action "Is this system a WEB SERVER (check README)?"; then
        is_web_server=true
    fi
    
    # Apache Configuration
    if systemctl is-active apache2 &>/dev/null || [[ -d "/etc/apache2" ]]; then
        if [[ "$is_web_server" == true ]]; then
            echo -e "\n${BOLD}Hardening Apache...${NC}"
            
            if confirm_action "Apply Apache security hardening?"; then
                local apache_security="/etc/apache2/conf-enabled/security.conf"
                
                if [[ -f "$apache_security" ]]; then
                    cp "$apache_security" "${apache_security}.bak.$(date +%Y%m%d_%H%M%S)"
                    
                    # Set ServerTokens to Prod (least information disclosure)
                    sed -i 's/^ServerTokens.*/ServerTokens Prod/' "$apache_security"
                    if ! grep -q "^ServerTokens" "$apache_security"; then
                        echo "ServerTokens Prod" >> "$apache_security"
                    fi
                    print_success "Set ServerTokens to Prod (least verbose)"
                    
                    # Disable ServerSignature
                    sed -i 's/^ServerSignature.*/ServerSignature Off/' "$apache_security"
                    if ! grep -q "^ServerSignature" "$apache_security"; then
                        echo "ServerSignature Off" >> "$apache_security"
                    fi
                    print_success "Disabled Apache server signature"
                    
                    print_success "Configured Apache security settings"
                    
                    systemctl restart apache2
                    print_success "Apache restarted"
                    changes_made=true
                else
                    print_warning "Apache security.conf not found"
                fi
            fi
            
            # WordPress configuration
            if [[ -f "/var/www/html/wp-config.php" ]]; then
                if confirm_action "Disable WordPress debugging?"; then
                    sed -i "s/define('WP_DEBUG', true);/define('WP_DEBUG', false);/" /var/www/html/wp-config.php
                    sed -i "s/define( 'WP_DEBUG', true );/define('WP_DEBUG', false);/" /var/www/html/wp-config.php
                    print_success "Disabled WordPress debugging"
                    changes_made=true
                fi
            fi
        else
            print_warning "System is NOT a web server - Apache should be disabled"
            print_info "Use 'Audit Services' menu option to disable Apache"
        fi
    fi
    
    # Nginx Configuration
    if systemctl is-active nginx &>/dev/null || [[ -d "/etc/nginx" ]]; then
        if [[ "$is_web_server" == true ]]; then
            echo -e "\n${BOLD}Hardening Nginx...${NC}"
            
            if confirm_action "Apply Nginx security hardening?"; then
                local nginx_conf="/etc/nginx/nginx.conf"
                
                if [[ -f "$nginx_conf" ]]; then
                    cp "$nginx_conf" "${nginx_conf}.bak.$(date +%Y%m%d_%H%M%S)"
                    
                    # Add server_tokens off if not present
                    if ! grep -q "server_tokens off;" "$nginx_conf"; then
                        sed -i '/http {/a \    server_tokens off;' "$nginx_conf"
                        print_success "Configured Nginx to hide version"
                        
                        systemctl restart nginx
                        print_success "Nginx restarted"
                        changes_made=true
                    else
                        print_success "Nginx already configured"
                    fi
                else
                    print_warning "Nginx configuration not found"
                fi
            fi
        else
            print_warning "System is NOT a web server - Nginx should be disabled"
            print_info "Use 'Audit Services' menu option to disable Nginx"
        fi
    fi
    
    # Squid Configuration
    if systemctl is-active squid &>/dev/null || [[ -f "/etc/squid/squid.conf" ]]; then
        if [[ "$is_web_server" == true ]]; then
            echo -e "\n${BOLD}Hardening Squid...${NC}"
            
            if confirm_action "Apply Squid security hardening?"; then
                local squid_conf="/etc/squid/squid.conf"
                
                if [[ -f "$squid_conf" ]]; then
                    cp "$squid_conf" "${squid_conf}.bak.$(date +%Y%m%d_%H%M%S)"
                    
                    # Add security settings if not present
                    
                    # Disable X-Forwarded-For headers
                    if ! grep -q "^forwarded_for" "$squid_conf"; then
                        echo "forwarded_for delete" >> "$squid_conf"
                        print_success "Disabled X-Forwarded-For headers"
                    fi
                    
                    # Disable Via headers
                    if ! grep -q "^via" "$squid_conf"; then
                        echo "via off" >> "$squid_conf"
                        print_success "Disabled Via headers"
                    fi
                    
                    # Don't send Squid version
                    if ! grep -q "^httpd_suppress_version_string" "$squid_conf"; then
                        echo "httpd_suppress_version_string on" >> "$squid_conf"
                        print_success "Suppressed Squid version in headers"
                    fi
                    
                    # Ignore unknown nameservers
                    if ! grep -q "^ignore_unknown_nameservers" "$squid_conf"; then
                        echo "ignore_unknown_nameservers on" >> "$squid_conf"
                        print_success "Enabled ignore unknown nameservers"
                    fi
                    
                    # Disable SNMP
                    if ! grep -q "^snmp_port 0" "$squid_conf"; then
                        sed -i 's/^snmp_port.*/snmp_port 0/' "$squid_conf" 2>/dev/null || echo "snmp_port 0" >> "$squid_conf"
                        print_success "Disabled SNMP (set port to 0)"
                    fi
                    
                    print_success "Configured Squid security settings"
                    
                    systemctl restart squid
                    print_success "Squid restarted"
                    changes_made=true
                else
                    print_warning "Squid configuration not found"
                fi
            fi
        else
            print_warning "System is NOT a web server - Squid should be disabled"
            print_info "Use 'Audit Services' menu option to disable Squid"
        fi
    fi
    
    # Browser Hardening (Chromium/Chrome)
    echo -e "\n${BOLD}Browser Security Configuration${NC}"
    
    if confirm_action "Configure browser security settings (Chromium/Chrome)?"; then
        # Chromium/Chrome policy directory
        local chrome_policy_dir="/etc/chromium/policies/managed"
        local chrome_alt_policy_dir="/etc/opt/chrome/policies/managed"
        
        # Create policy directories
        mkdir -p "$chrome_policy_dir"
        mkdir -p "$chrome_alt_policy_dir"
        
        # Create security policy JSON
        cat > "$chrome_policy_dir/security_policy.json" << 'EOF'
{
  "EnableOnlineRevocationChecks": true,
  "SafeBrowsingEnabled": true,
  "SafeBrowsingExtendedReportingEnabled": false,
  "PasswordManagerEnabled": false,
  "AutofillCreditCardEnabled": false,
  "AutofillAddressEnabled": false,
  "SyncDisabled": true,
  "BlockThirdPartyCookies": true,
  "EnableMediaRouter": false,
  "CloudPrintProxyEnabled": false,
  "MetricsReportingEnabled": false,
  "SearchSuggestEnabled": false,
  "NetworkPredictionOptions": 2,
  "DefaultCookiesSetting": 1,
  "DefaultGeolocationSetting": 2,
  "DefaultNotificationsSetting": 2,
  "UrlKeyedAnonymizedDataCollectionEnabled": false,
  "UserFeedbackAllowed": false,
  "DeveloperToolsDisabled": false,
  "ChromeCleanupEnabled": false,
  "ChromeCleanupReportingEnabled": false,
  "EnableMediaRouterMDns": false,
  "BackgroundModeEnabled": false,
  "AdsSettingForIntrusiveAdsSites": 2,
  "EnableMediaRouterDiagnostics": false
}
EOF
        
        # Copy to Chrome policy directory as well
        cp "$chrome_policy_dir/security_policy.json" "$chrome_alt_policy_dir/security_policy.json" 2>/dev/null
        
        print_success "Configured Chromium/Chrome security policies"
        print_info "  - Blocks intrusive advertisements (AdsSettingForIntrusiveAdsSites: 2)"
        print_info "  - Safe Browsing enabled"
        print_info "  - Third-party cookies blocked"
        print_info "  - Sync and metrics disabled"
        changes_made=true
        
        # Add Do Not Track preference for Chrome
        cat > "$chrome_policy_dir/dnt_policy.json" << 'EOF'
{
  "EnableDoNotTrack": true
}
EOF
        cp "$chrome_policy_dir/dnt_policy.json" "$chrome_alt_policy_dir/dnt_policy.json" 2>/dev/null
        
        print_success "Enabled Do Not Track for Chromium/Chrome"
        changes_made=true
    fi
    
    # Firefox hardening (bonus)
    if command -v firefox &>/dev/null; then
        if confirm_action "Configure Firefox security settings?"; then
            # Find Firefox profiles
            local firefox_profiles_dir="$HOME/.mozilla/firefox"
            if [[ -d "$firefox_profiles_dir" ]]; then
                for profile in "$firefox_profiles_dir"/*.default*; do
                    if [[ -d "$profile" ]]; then
                        local prefs_js="$profile/prefs.js"
                        if [[ -f "$prefs_js" ]]; then
                            # Backup
                            cp "$prefs_js" "${prefs_js}.bak.$(date +%Y%m%d_%H%M%S)"
                            
                            # Add security preferences
                            cat >> "$prefs_js" << 'EOF'

// CyberPatriot Security Settings
user_pref("privacy.donottrackheader.enabled", true);
user_pref("privacy.trackingprotection.enabled", true);
user_pref("privacy.trackingprotection.socialtracking.enabled", true);
user_pref("network.cookie.cookieBehavior", 1);
user_pref("network.dns.disablePrefetch", true);
user_pref("network.prefetch-next", false);
user_pref("geo.enabled", false);
EOF
                            print_success "Configured Firefox security settings"
                        fi
                    fi
                done
            fi
        fi
    fi
    
    # Summary
    echo -e "\n${BOLD}Security Features Summary:${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    local aslr_current=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null)
    if [[ "$aslr_current" == "2" ]]; then
        echo -e "${GREEN}✓${NC} ASLR: Enabled (full)"
    else
        echo -e "${YELLOW}!${NC} ASLR: $aslr_current"
    fi
    
    if grep -q "^net.ipv4.tcp_syncookies=1" /etc/sysctl.conf; then
        echo -e "${GREEN}✓${NC} Network hardening: Configured"
    else
        echo -e "${YELLOW}!${NC} Network hardening: Not configured"
    fi
    
    if systemctl is-active apparmor &>/dev/null; then
        echo -e "${GREEN}✓${NC} AppArmor: Active"
    else
        echo -e "${YELLOW}!${NC} AppArmor: Inactive"
    fi
    
    if systemctl is-active rsyslog &>/dev/null; then
        echo -e "${GREEN}✓${NC} rsyslog: Active"
    else
        echo -e "${YELLOW}!${NC} rsyslog: Inactive"
    fi
    
    if systemctl is-active fail2ban &>/dev/null; then
        echo -e "${GREEN}✓${NC} Fail2Ban: Active"
    else
        echo -e "${YELLOW}!${NC} Fail2Ban: Not active"
    fi
    
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    if [[ "$changes_made" == true ]]; then
        print_success "Security features enabled successfully"
        print_warning "Some changes require a reboot to take full effect"
    else
        print_info "No changes were made"
    fi
    
    print_header "SECURITY FEATURES CONFIGURATION COMPLETE"
    press_enter
}

#############################################
# Task 11: Safe Password Complexity (No Lockout Risk)
#############################################

enforce_password_complexity() {
    print_header "SAFE PASSWORD COMPLEXITY ENFORCEMENT"
    print_warning "⚠️  CRITICAL: TAKE A VM SNAPSHOT BEFORE PROCEEDING ⚠️"
    echo ""
    print_info "This function enables REAL password complexity enforcement"
    print_info "This is REQUIRED for CyberPatriot points but has lockout risk"
    echo ""
    
    local changes_made=false
    
    # Safety check
    echo -e "${RED}${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${RED}${BOLD}                    ⚠️  WARNING ⚠️${NC}"
    echo -e "${RED}${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}Enabling PAM password complexity CAN cause lockouts if:${NC}"
    echo -e "${YELLOW}  • Existing user passwords don't meet new requirements${NC}"
    echo -e "${YELLOW}  • You forget your password after changing it${NC}"
    echo -e "${YELLOW}  • PAM configuration gets corrupted${NC}"
    echo ""
    echo -e "${CYAN}${BOLD}REQUIRED BEFORE CONTINUING:${NC}"
    echo -e "${GREEN}  1. Take a VM snapshot NOW${NC}"
    echo -e "${GREEN}  2. Write down your current password${NC}"
    echo -e "${GREEN}  3. Have the main user password ready to test${NC}"
    echo ""
    echo -e "${RED}${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    
    if ! confirm_action "I have taken a snapshot and want to proceed"; then
        print_warning "Cancelled - no changes made"
        press_enter
        return
    fi
    
    # Step 1: Install libpam-pwquality (SAFE - just installs package)
    echo -e "\n${BOLD}Step 1: Install Password Quality Library${NC}"
    
    if ! dpkg -l | grep -q "^ii.*libpam-pwquality"; then
        if confirm_action "Install libpam-pwquality?"; then
            apt-get update -qq
            apt-get install -y libpam-pwquality
            if [[ $? -eq 0 ]]; then
                print_success "libpam-pwquality installed"
                changes_made=true
            else
                print_error "Failed to install libpam-pwquality"
                press_enter
                return
            fi
        fi
    else
        print_success "libpam-pwquality already installed"
    fi
    
    # Step 2: Configure /etc/security/pwquality.conf (SAFE - just sets rules)
    echo -e "\n${BOLD}Step 2: Configure Password Rules${NC}"
    
    local pwquality_conf="/etc/security/pwquality.conf"
    
    if [[ -f "$pwquality_conf" ]]; then
        if confirm_action "Set password complexity rules in pwquality.conf?"; then
            cp "$pwquality_conf" "${pwquality_conf}.bak.$(date +%Y%m%d_%H%M%S)"
            
            # Clear existing CyberPatriot settings if any
            sed -i '/# CyberPatriot Password Complexity/,+6d' "$pwquality_conf"
            
            # Add new settings
            {
                echo ""
                echo "# CyberPatriot Password Complexity - $(date +%Y-%m-%d)"
                echo "minlen = 8"
                echo "dcredit = -1"
                echo "ucredit = -1"
                echo "lcredit = -1"
                echo "ocredit = -1"
            } >> "$pwquality_conf"
            
            print_success "Password rules configured"
            print_info "  Min length: 8 | Digit: 1 | Upper: 1 | Lower: 1 | Special: 1"
            changes_made=true
        fi
    fi
    
    # Step 3: Enable PAM enforcement (DANGEROUS - This is the risky part)
    echo -e "\n${BOLD}Step 3: Enable PAM Password Quality Enforcement${NC}"
    echo -e "${RED}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${RED}${BOLD}⚠️  DANGER ZONE - LOCKOUT RISK ⚠️${NC}"
    echo -e "${RED}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    print_warning "This step ENFORCES password complexity via PAM"
    print_warning "Existing passwords that don't meet requirements may cause issues"
    print_info "This is what gets you CyberPatriot points for password complexity"
    echo ""
    
    local common_password="/etc/pam.d/common-password"
    
    if [[ -f "$common_password" ]]; then
        # Check if already configured
        if grep -q "pam_pwquality.so" "$common_password" 2>/dev/null; then
            print_info "PAM password quality already enabled"
        else
            echo -e "${YELLOW}Current PAM configuration:${NC}"
            grep "^password" "$common_password" | head -5
            echo ""
            
            if confirm_action "ENABLE PAM password quality enforcement? (RISKY)"; then
                # Backup
                cp "$common_password" "${common_password}.bak.$(date +%Y%m%d_%H%M%S)"
                print_success "Created backup of common-password"
                
                # Add pam_pwquality BEFORE pam_unix.so
                sed -i '/^password.*pam_unix.so/i password\trequisite\t\t\tpam_pwquality.so retry=3' "$common_password"
                
                print_success "PAM password quality enforcement ENABLED"
                print_warning "New passwords MUST now meet complexity requirements"
                changes_made=true
                
                echo ""
                echo -e "${CYAN}${BOLD}IMMEDIATE ACTION REQUIRED:${NC}"
                echo -e "${YELLOW}1. Test that you can still use sudo: ${NC}sudo whoami"
                echo -e "${YELLOW}2. If locked out, reboot and restore from snapshot${NC}"
                echo -e "${YELLOW}3. If successful, test changing a password${NC}"
                echo ""
            fi
        fi
    fi
    
    # Step 4: Enable Password History (OPTIONAL - less risky)
    echo -e "\n${BOLD}Step 4: Enable Password History${NC}"
    print_info "Prevents reusing last 5 passwords"
    print_warning "Moderate risk - existing users can still login with current password"
    
    if [[ -f "$common_password" ]]; then
        if ! grep "pam_unix.so" "$common_password" | grep -q "remember=" 2>/dev/null; then
            if confirm_action "Enable password history (remember last 5)?"; then
                # Backup if not already done
                if [[ ! -f "${common_password}.bak.$(date +%Y%m%d_%H%M%S)" ]]; then
                    cp "$common_password" "${common_password}.bak.$(date +%Y%m%d_%H%M%S)"
                fi
                
                # Add remember=5 to the password line with pam_unix.so
                sed -i '/^password.*pam_unix.so/ s/$/ remember=5/' "$common_password"
                
                print_success "Password history enabled (last 5 passwords)"
                changes_made=true
            fi
        else
            print_info "Password history already configured"
        fi
    fi
    
    # Summary
    echo -e "\n${BOLD}Password Complexity Enforcement Summary:${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    if [[ -f "$pwquality_conf" ]] && grep -q "^minlen" "$pwquality_conf" 2>/dev/null; then
        echo -e "${GREEN}✓${NC} Password rules configured in pwquality.conf"
    fi
    
    if [[ -f "$common_password" ]] && grep -q "pam_pwquality.so" "$common_password" 2>/dev/null; then
        echo -e "${GREEN}✓${NC} PAM enforcement ENABLED (passwords will be checked)"
    else
        echo -e "${YELLOW}!${NC} PAM enforcement NOT ENABLED (rules are advisory only)"
    fi
    
    if [[ -f "$common_password" ]] && grep "pam_unix.so" "$common_password" | grep -q "remember=" 2>/dev/null; then
        echo -e "${GREEN}✓${NC} Password history enabled"
    else
        echo -e "${YELLOW}!${NC} Password history not enabled"
    fi
    
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    if grep -q "pam_pwquality.so" "$common_password" 2>/dev/null; then
        echo ""
        echo -e "${RED}${BOLD}⚠️  POST-CONFIGURATION TESTING REQUIRED ⚠️${NC}"
        echo ""
        echo -e "${YELLOW}Run these tests NOW:${NC}"
        echo -e "${CYAN}  1. Test sudo:${NC} sudo whoami"
        echo -e "${CYAN}  2. Test password change:${NC} passwd"
        echo -e "${CYAN}  3. If anything fails, reboot and restore snapshot${NC}"
        echo ""
    fi
    
    if [[ "$changes_made" == true ]]; then
        print_success "Password complexity enforcement configured"
    else
        print_info "No changes were made"
    fi
    
    print_header "PASSWORD COMPLEXITY ENFORCEMENT COMPLETE"
    press_enter
}

#############################################
# Main Menu
#############################################

show_menu() {
    clear
    echo -e "${GREEN} 1)${NC} User Auditing"
    echo -e "${GREEN} 2)${NC} Disable Root Login"
    echo -e "${GREEN} 3)${NC} Configure Firewall (UFW)"
    echo -e "${GREEN} 4)${NC} Configure Password Policies"
    echo -e "${GREEN} 5)${NC} Audit Services"
    echo -e "${GREEN} 6)${NC} Audit File Permissions"
    echo -e "${GREEN} 7)${NC} Update System"
    echo -e "${GREEN} 8)${NC} Remove Prohibited Software"
    echo -e "${GREEN} 9)${NC} Harden SSH Configuration"
    echo -e "${GREEN}10)${NC} Enable Security Features"
    echo -e "${YELLOW}11)${NC} Enforce Password Complexity ${RED}(⚠️  SNAPSHOT FIRST!)${NC}"
    echo ""
    echo -e "${RED} 0)${NC} Exit"
    echo ""
    echo -e -n "${CYAN}Select an option: ${NC}"
}

#############################################
# Main Program Loop
#############################################

main() {
    check_root
    show_splash
    
    while true; do
        show_menu
        read -r choice
        
        case $choice in
            1) user_auditing ;;
            2) disable_root_login ;;
            3) configure_firewall ;;
            4) configure_password_policy ;;
            5) audit_services ;;
            6) audit_file_permissions ;;
            7) update_system ;;
            8) remove_prohibited_software ;;
            9) harden_ssh ;;
            10) enable_security_features ;;
            11) enforce_password_complexity ;;
            0)
                print_header "EXITING"
                print_info "Security audit log saved to: $LOG_FILE"
                echo -e "${GREEN}Thank you for using CyberPatriot Security Tool!${NC}"
                exit 0
                ;;
            *)
                print_error "Invalid option. Please try again."
                sleep 2
                ;;
        esac
    done
}

# Run the main program
main