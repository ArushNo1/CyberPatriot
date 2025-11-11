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
    sleep 2
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
    
    # HTTP (optional)
    if confirm_action "Allow HTTP (port 80) through the firewall?"; then
        ufw allow http
        print_success "HTTP allowed through firewall"
        changes_made=true
    fi
    
    # 5. Allow custom applications
    echo -e "\n${BOLD}Custom Application Rules${NC}"
    echo -e "${CYAN}You can now add custom applications/ports to allow through the firewall${NC}"
    echo -e "${YELLOW}Examples: '80/tcp', '8080', 'smtp', 'dns', etc.${NC}"
    echo -e "${YELLOW}Enter 'done' when finished${NC}\n"
    
    while true; do
        echo -e -n "${CYAN}Enter application/port to allow (or 'done'): ${NC}"
        read -r custom_app
        
        [[ "$custom_app" == "done" ]] && break
        [[ -z "$custom_app" ]] && continue
        
        # Ask for protocol if not specified
        if [[ ! "$custom_app" =~ / ]]; then
            echo -e "${YELLOW}Options:${NC}"
            echo -e "  ${GREEN}1)${NC} TCP"
            echo -e "  ${GREEN}2)${NC} UDP"
            echo -e "  ${GREEN}3)${NC} Both"
            echo -e "  ${GREEN}4)${NC} Application name (as-is)"
            echo -e -n "${CYAN}Select protocol: ${NC}"
            read -r proto_choice
            
            case $proto_choice in
                1) custom_app="${custom_app}/tcp" ;;
                2) custom_app="${custom_app}/udp" ;;
                3) 
                    # Allow both TCP and UDP
                    ufw allow "${custom_app}/tcp"
                    ufw allow "${custom_app}/udp"
                    print_success "Allowed ${custom_app}/tcp and ${custom_app}/udp"
                    changes_made=true
                    continue
                    ;;
                4) ;; # Use as-is
                *)
                    print_error "Invalid choice, skipping..."
                    continue
                    ;;
            esac
        fi
        
        # Allow the application/port
        if confirm_action "Allow '$custom_app' through the firewall?"; then
            ufw allow "$custom_app"
            if [[ $? -eq 0 ]]; then
                print_success "Allowed $custom_app through firewall"
                changes_made=true
            else
                print_error "Failed to allow $custom_app"
            fi
        fi
    done
    
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
    
    # 2. Install and configure libpam-pwquality for password complexity
    echo -e "\n${BOLD}Configuring system-wide password complexity...${NC}"
    
    if ! dpkg -l | grep -q "libpam-pwquality"; then
        print_warning "libpam-pwquality not installed"
        if confirm_action "Install libpam-pwquality for password complexity enforcement?"; then
            apt-get update -qq
            apt-get install -y libpam-pwquality
            if [[ $? -eq 0 ]]; then
                print_success "libpam-pwquality installed"
                changes_made=true
            else
                print_error "Failed to install libpam-pwquality"
                print_warning "Skipping password complexity configuration"
                echo ""
                return
            fi
        fi
    else
        print_success "libpam-pwquality already installed"
    fi
    
    # Configure /etc/security/pwquality.conf
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
            
            print_success "Password complexity configured system-wide"
            print_info "  - Minimum length: 8 characters"
            print_info "  - At least 1 digit required"
            print_info "  - At least 1 uppercase letter required"
            print_info "  - At least 1 lowercase letter required"
            print_info "  - At least 1 special character required"
            changes_made=true
        fi
    else
        print_error "$pwquality_conf not found"
    fi
    
    # 3. Configure PAM to use pwquality and password history
    echo -e "\n${BOLD}Configuring PAM password policies...${NC}"
    print_info "System-wide enforcement through PAM"
    
    local common_password="/etc/pam.d/common-password"
    
    if [[ -f "$common_password" ]]; then
        cp "$common_password" "${common_password}.bak.$(date +%Y%m%d_%H%M%S)"
        print_success "Created backup of common-password"
        
        # Enable pam_pwquality if not already enabled
        if ! grep -q "pam_pwquality.so" "$common_password"; then
            if confirm_action "Enable PAM password quality checking?"; then
                # Add BEFORE pam_unix.so lines
                sed -i '/pam_unix.so/i password\trequisite\t\t\tpam_pwquality.so retry=3' "$common_password"
                print_success "Enabled PAM password quality module"
                changes_made=true
            fi
        else
            print_info "PAM password quality already enabled"
        fi
        
        # Enable password history
        if ! grep "pam_unix.so" "$common_password" | grep -q "remember="; then
            if confirm_action "Enable password history (remember last 5 passwords)?"; then
                # Add remember=5 to pam_unix.so line
                sed -i '/pam_unix.so.*password/ s/$/ remember=5/' "$common_password"
                print_success "Password history enabled (system-wide)"
                print_info "  - Users cannot reuse last 5 passwords"
                changes_made=true
            fi
        else
            print_info "Password history already configured"
        fi
    else
        print_error "$common_password not found"
    fi
    
    # 4. Configure account lockout policy (system-wide)
    echo -e "\n${BOLD}Configuring system-wide account lockout...${NC}"
    print_info "Locks accounts after repeated failed login attempts"
    print_warning "NOTE: Faillock affects all users - MAIN_USER cannot be exempted from PAM"
    print_info "Make sure you know the password for: $MAIN_USER"
    
    # Check which lockout mechanism is available
    if command -v faillock &>/dev/null || [[ -f "/usr/sbin/faillock" ]]; then
        print_info "System uses 'faillock' for account lockout"
        
        if confirm_action "Configure account lockout (5 failed attempts, 15 min lockout)?"; then
            local faillock_conf="/etc/security/faillock.conf"
            
            if [[ ! -f "$faillock_conf" ]]; then
                # Create new faillock.conf
                cat > "$faillock_conf" << 'EOF'
# CyberPatriot Account Lockout Configuration
# Lock account after 5 failed attempts for 15 minutes (900 seconds)
# WARNING: This affects ALL users including admins
deny = 5
unlock_time = 900
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
                
                print_success "Updated faillock configuration"
                changes_made=true
            fi
            
            print_info "  - Lock after: 5 failed attempts"
            print_info "  - Lockout duration: 15 minutes (auto-unlock)"
            print_info "  - Applies to: ALL users (cannot exempt specific users)"
            print_warning "  - Admin can unlock with: faillock --user <username> --reset"
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
    if dpkg -l 2>/dev/null | grep -q "libpam-pwquality"; then
        echo -e "${GREEN}✓${NC} Password quality module: INSTALLED"
    else
        echo -e "${YELLOW}!${NC} Password quality module: NOT INSTALLED"
    fi
    
    if [[ -f "/etc/security/pwquality.conf" ]] && grep -q "^minlen" /etc/security/pwquality.conf 2>/dev/null; then
        local minlen=$(grep "^minlen" /etc/security/pwquality.conf | tail -1 | awk '{print $3}')
        echo -e "${GREEN}✓${NC} Password complexity: CONFIGURED (min length: $minlen)"
    else
        echo -e "${YELLOW}!${NC} Password complexity: NOT CONFIGURED"
    fi
    
    # Check PAM
    if [[ -f "/etc/pam.d/common-password" ]]; then
        if grep -q "pam_pwquality.so" /etc/pam.d/common-password 2>/dev/null; then
            echo -e "${GREEN}✓${NC} PAM password quality: ENABLED"
        else
            echo -e "${YELLOW}!${NC} PAM password quality: NOT ENABLED"
        fi
        
        if grep "pam_unix.so" /etc/pam.d/common-password 2>/dev/null | grep -q "remember="; then
            echo -e "${GREEN}✓${NC} Password history: ENABLED (system-wide)"
        else
            echo -e "${YELLOW}!${NC} Password history: NOT ENABLED"
        fi
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
# Task 5: Service Audit
#############################################

audit_services() {
    print_header "SERVICE AUDIT"
    print_info "This module will audit running services"
    echo -e "${YELLOW}[TO BE IMPLEMENTED]${NC}"
    press_enter
}

#############################################
# Task 6: File Permissions Audit
#############################################

audit_file_permissions() {
    print_header "FILE PERMISSIONS AUDIT"
    print_info "This module will check critical file permissions"
    echo -e "${YELLOW}[TO BE IMPLEMENTED]${NC}"
    press_enter
}

#############################################
# Task 7: Update System
#############################################

update_system() {
    print_header "SYSTEM UPDATE"
    print_info "This module will update the system"
    echo -e "${YELLOW}[TO BE IMPLEMENTED]${NC}"
    press_enter
}

#############################################
# Task 8: Remove Prohibited Software
#############################################

remove_prohibited_software() {
    print_header "REMOVE PROHIBITED SOFTWARE"
    print_info "This module will scan for and remove prohibited software"
    echo -e "${YELLOW}[TO BE IMPLEMENTED]${NC}"
    press_enter
}

#############################################
# Task 9: SSH Hardening
#############################################

harden_ssh() {
    print_header "SSH HARDENING"
    print_info "This module will harden SSH configuration"
    echo -e "${YELLOW}[TO BE IMPLEMENTED]${NC}"
    press_enter
}

#############################################
# Task 10: Enable Security Features
#############################################

enable_security_features() {
    print_header "ENABLE SECURITY FEATURES"
    print_info "This module will enable various security features"
    echo -e "${YELLOW}[TO BE IMPLEMENTED]${NC}"
    press_enter
}

#############################################
# Task 11: Generate Security Report
#############################################

generate_report() {
    print_header "SECURITY REPORT"
    print_info "This module will generate a comprehensive security report"
    echo -e "${YELLOW}[TO BE IMPLEMENTED]${NC}"
    press_enter
}

#############################################
# Main Menu
#############################################

show_menu() {
    clear
    echo -e "${BOLD}Configuring login policies (/etc/login.defs)...${NC}"
    
    local login_defs="/etc/login.defs"
    local login_defs_backup="${login_defs}.bak.$(date +%Y%m%d_%H%M%S)"
    
    if [[ -f "$login_defs" ]]; then
        cp "$login_defs" "$login_defs_backup"
        print_success "Created backup: $login_defs_backup"
        
        # Function to set or update a parameter in login.defs
        set_login_def() {
            local param=$1
            local value=$2
            
            if grep -q "^${param}" "$login_defs"; then
                sed -i "s/^${param}.*/${param} ${value}/" "$login_defs"
            elif grep -q "^#${param}" "$login_defs"; then
                sed -i "s/^#${param}.*/${param} ${value}/" "$login_defs"
            else
                echo "${param} ${value}" >> "$login_defs"
            fi
        }
        
        if confirm_action "Configure password aging policies?"; then
            set_login_def "PASS_MAX_DAYS" "90"
            set_login_def "PASS_MIN_DAYS" "7"
            set_login_def "PASS_WARN_AGE" "14"
            print_success "Password aging: Max 90 days, Min 7 days, Warn 14 days"
            changes_made=true
        fi
        
        if confirm_action "Configure login security policies?"; then
            set_login_def "FAILLOG_ENAB" "yes"
            set_login_def "LOG_UNKFAIL_ENAB" "yes"
            set_login_def "SYSLOG_SU_ENAB" "yes"
            set_login_def "SYSLOG_SG_ENAB" "yes"
            set_login_def "LOGIN_TIMEOUT" "60"
            set_login_def "LOGIN_RETRIES" "5"
            print_success "Login policies: Logging enabled, 60s timeout, 5 retries"
            changes_made=true
        fi
        
        # Verify changes
        if confirm_action "View updated login.defs settings?"; then
            echo -e "\n${CYAN}Password Aging Settings:${NC}"
            grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE" "$login_defs"
            echo -e "\n${CYAN}Login Security Settings:${NC}"
            grep "^FAILLOG_ENAB\|^LOG_UNKFAIL_ENAB\|^SYSLOG_SU_ENAB\|^SYSLOG_SG_ENAB\|^LOGIN_TIMEOUT\|^LOGIN_RETRIES" "$login_defs"
            echo ""
        fi
    else
        print_error "File $login_defs not found"
    fi
    
    # 2. Configure /etc/security/pwquality.conf (SAFE - doesn't affect existing passwords)
    echo -e "\n${BOLD}Configuring password quality requirements...${NC}"
    print_info "Note: These settings only affect NEW passwords, not existing ones"
    
    local pwquality_conf="/etc/security/pwquality.conf"
    
    # Check if libpam-pwquality is installed
    if ! dpkg -l | grep -q "libpam-pwquality"; then
        print_warning "libpam-pwquality is not installed"
        if confirm_action "Install libpam-pwquality? (Required for password quality enforcement)"; then
            apt install -y libpam-pwquality
            if [[ $? -eq 0 ]]; then
                print_success "libpam-pwquality installed successfully"
            else
                print_error "Failed to install libpam-pwquality"
            fi
        fi
    else
        print_success "libpam-pwquality is already installed"
    fi
    
    if [[ -f "$pwquality_conf" ]]; then
        local pwquality_backup="${pwquality_conf}.bak.$(date +%Y%m%d_%H%M%S)"
        cp "$pwquality_conf" "$pwquality_backup"
        print_success "Created backup: $pwquality_backup"
        
        if confirm_action "Configure password complexity requirements?"; then
            # Function to set pwquality parameter
            set_pwquality() {
                local param=$1
                local value=$2
                
                if grep -q "^${param}" "$pwquality_conf"; then
                    sed -i "s/^${param}.*/${param} = ${value}/" "$pwquality_conf"
                elif grep -q "^# ${param}" "$pwquality_conf"; then
                    sed -i "s/^# ${param}.*/${param} = ${value}/" "$pwquality_conf"
                else
                    echo "${param} = ${value}" >> "$pwquality_conf"
                fi
            }
            
            set_pwquality "minlen" "8"
            set_pwquality "dcredit" "-1"  # At least 1 digit
            set_pwquality "ucredit" "-1"  # At least 1 uppercase
            set_pwquality "lcredit" "-1"  # At least 1 lowercase
            set_pwquality "ocredit" "-1"  # At least 1 special char
            
            print_success "Password complexity: Min 8 chars, 1 digit, 1 upper, 1 lower, 1 special"
            changes_made=true
            
            if confirm_action "View pwquality.conf settings?"; then
                echo -e "\n${CYAN}Password Quality Settings:${NC}"
                grep "^minlen\|^dcredit\|^ucredit\|^lcredit\|^ocredit" "$pwquality_conf"
                echo ""
            fi
        fi
    else
        print_warning "File $pwquality_conf not found"
    fi
    
    # 3. Configure PAM (CAREFUL - avoided dangerous settings)
    echo -e "\n${BOLD}Configuring PAM password policies...${NC}"
    print_warning "AVOIDING libpam-cracklib - it can cause authentication issues"
    print_info "Using safe pam_pwquality configuration instead"
    
    local common_password="/etc/pam.d/common-password"
    
    if [[ -f "$common_password" ]]; then
        local pam_backup="${common_password}.bak.$(date +%Y%m%d_%H%M%S)"
        cp "$common_password" "$pam_backup"
        print_success "Created backup: $pam_backup"
        
        if confirm_action "Configure PAM to enforce password quality and history?"; then
            # Check if pam_pwquality line exists
            if ! grep -q "pam_pwquality.so" "$common_password"; then
                # Add pam_pwquality before pam_unix
                sed -i '/pam_unix.so/i password requisite pam_pwquality.so retry=3' "$common_password"
                print_success "Added pam_pwquality.so with retry=3"
                changes_made=true
            else
                print_info "pam_pwquality.so already configured"
            fi
            
            # Add password history (remember last 5 passwords) - SAFE
            if grep -q "pam_unix.so.*password" "$common_password"; then
                if ! grep "pam_unix.so.*password" "$common_password" | grep -q "remember="; then
                    sed -i '/pam_unix.so.*password/ s/$/ remember=5/' "$common_password"
                    print_success "Added password history (remember 5 passwords)"
                    changes_made=true
                else
                    print_info "Password history already configured"
                fi
            fi
            
            print_success "PAM configuration updated safely"
        fi
    else
        print_error "File $common_password not found"
    fi
    
    # 4. Run password consistency check
    echo -e "\n${BOLD}Running password file consistency check...${NC}"
    if confirm_action "Run pwck to verify password file integrity?"; then
        pwck -r
        print_success "Password file check completed"
    fi
    
    # 5. Apply password aging to existing users (except protected user)
    echo -e "\n${BOLD}Applying password aging to existing users...${NC}"
    if confirm_action "Apply password aging policies to existing users?"; then
        local aged_count=0
        
        while IFS=: read -r username _ uid _ _ home shell; do
            # Only apply to human users (UID >= 1000) with valid shells
            if [[ $uid -ge 1000 && $uid -lt 65534 ]]; then
                if [[ "$shell" != "/usr/sbin/nologin" && "$shell" != "/bin/false" ]]; then
                    # Skip the protected main user
                    if [[ "$username" != "$MAIN_USER" && "$username" != "root" ]]; then
                        chage -M 90 -m 7 -W 14 "$username" 2>/dev/null
                        if [[ $? -eq 0 ]]; then
                            print_success "Applied aging policy to: $username"
                            ((aged_count++))
                        fi
                    else
                        print_info "Skipped protected user: $username"
                    fi
                fi
            fi
        done < /etc/passwd
        
        print_success "Applied password aging to $aged_count users"
        changes_made=true
    fi
    
    # 6. Summary
    echo -e "\n${BOLD}Password Policy Configuration Summary:${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    # Check password aging settings
    if grep -q "^PASS_MAX_DAYS.*90" "$login_defs" 2>/dev/null; then
        echo -e "${GREEN}✓${NC} Password max age: 90 days"
    else
        echo -e "${YELLOW}!${NC} Password max age: Not configured"
    fi
    
    if grep -q "^PASS_MIN_DAYS.*7" "$login_defs" 2>/dev/null; then
        echo -e "${GREEN}✓${NC} Password min age: 7 days"
    else
        echo -e "${YELLOW}!${NC} Password min age: Not configured"
    fi
    
    # Check password quality
    if [[ -f "$pwquality_conf" ]] && grep -q "^minlen.*8" "$pwquality_conf" 2>/dev/null; then
        echo -e "${GREEN}✓${NC} Minimum password length: 8 characters"
    else
        echo -e "${YELLOW}!${NC} Password length requirement: Not configured"
    fi
    
    # Check PAM
    if grep -q "pam_pwquality.so" "$common_password" 2>/dev/null; then
        echo -e "${GREEN}✓${NC} PAM password quality: Enabled"
    else
        echo -e "${YELLOW}!${NC} PAM password quality: Not enabled"
    fi
    
    if grep "pam_unix.so.*password" "$common_password" 2>/dev/null | grep -q "remember="; then
        echo -e "${GREEN}✓${NC} Password history: Enabled"
    else
        echo -e "${YELLOW}!${NC} Password history: Not enabled"
    fi
    
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    print_warning "IMPORTANT: These policies only affect NEW passwords"
    print_info "Existing passwords remain valid until changed"
    print_info "Protected user: $MAIN_USER (exempt from restrictions)"
    
    if [[ "$changes_made" == true ]]; then
        print_success "Password policies configured successfully"
    else
        print_info "No changes were made"
    fi
    
    print_header "PASSWORD POLICY CONFIGURATION COMPLETE"
    press_enter
}

#############################################
# Task 5: Service Audit
#############################################

audit_services() {
    print_header "SERVICE AUDIT"
    print_info "This module will audit running services"
    echo -e "${YELLOW}[TO BE IMPLEMENTED]${NC}"
    press_enter
}

#############################################
# Task 6: File Permissions Audit
#############################################

audit_file_permissions() {
    print_header "FILE PERMISSIONS AUDIT"
    print_info "This module will check critical file permissions"
    echo -e "${YELLOW}[TO BE IMPLEMENTED]${NC}"
    press_enter
}

#############################################
# Task 7: Update System
#############################################

update_system() {
    print_header "SYSTEM UPDATE"
    print_info "This module will update the system"
    echo -e "${YELLOW}[TO BE IMPLEMENTED]${NC}"
    press_enter
}

#############################################
# Task 8: Remove Prohibited Software
#############################################

remove_prohibited_software() {
    print_header "REMOVE PROHIBITED SOFTWARE"
    print_info "This module will scan for and remove prohibited software"
    echo -e "${YELLOW}[TO BE IMPLEMENTED]${NC}"
    press_enter
}

#############################################
# Task 9: SSH Hardening
#############################################

harden_ssh() {
    print_header "SSH HARDENING"
    print_info "This module will harden SSH configuration"
    echo -e "${YELLOW}[TO BE IMPLEMENTED]${NC}"
    press_enter
}

#############################################
# Task 10: Enable Security Features
#############################################

enable_security_features() {
    print_header "ENABLE SECURITY FEATURES"
    print_info "This module will enable various security features"
    echo -e "${YELLOW}[TO BE IMPLEMENTED]${NC}"
    press_enter
}

#############################################
# Task 11: Generate Security Report
#############################################

generate_report() {
    print_header "SECURITY REPORT"
    print_info "This module will generate a comprehensive security report"
    echo -e "${YELLOW}[TO BE IMPLEMENTED]${NC}"
    press_enter
}

#############################################
# Main Menu
#############################################

show_menu() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║          CYBERPATRIOT SECURITY MENU                        ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
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
    echo -e "${GREEN}11)${NC} Generate Security Report"
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
            11) generate_report ;;
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