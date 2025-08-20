#!/bin/bash

#==============================================================================
#                    Security Audit Tool (SAT) - Plus Edition
#                  Professional Security Assessment for Linux Systems
#==============================================================================
# Version: 4.2-PLUS-FIXED
# Purpose: Comprehensive security assessment for Linux systems (Kali-aware)
# Features: Multiple scan modes, quiet mode, HTML/JSON reports, security scoring
#==============================================================================

set -uo pipefail
IFS=$'\n\t'

# --- Metadata and file locations ---
readonly VERSION="4.2-PLUS-FIXED"
readonly SCRIPT_NAME="Security Audit Tool Plus"
REPORT_DIR="${HOME}/security_audits"
readonly TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="${REPORT_DIR}/security_audit_${TIMESTAMP}.txt"
JSON_REPORT="${REPORT_DIR}/security_audit_${TIMESTAMP}.json"
HTML_REPORT="${REPORT_DIR}/security_audit_${TIMESTAMP}.html"
LOG_FILE="${REPORT_DIR}/audit_${TIMESTAMP}.log"

# --- Color constants (FIXED with proper escape sequences) ---
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly BLUE='\033[0;34m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly RED='\033[0;31m'
readonly BOLD='\033[1m'
readonly DIM='\033[2m'
readonly NC='\033[0m'

# --- Operational defaults ---
readonly FIND_TIMEOUT=20
readonly MAX_FIND_DEPTH=4
WARNINGS=0
ISSUES=0
RECOMMENDATIONS=0
KALI_SPECIFIC_CHECKS=0
TOTAL_CHECKS=0
COMPLETED_CHECKS=0
QUIET_MODE=false
VERBOSE_MODE=false
MODE="full"  # ssh, network, full

declare -A JSON_DATA

# -----------------------------
# Utility & UI functions
# -----------------------------
print_banner() {
    if ! $QUIET_MODE; then
        echo -e "${PURPLE}"
        cat <<'EOF'
╔════════════════════════════════════════════════════════════════╗
║        Security Audit Tool - Plus Edition v4.2                 ║
║           Professional Linux Security Assessment               ║
╚════════════════════════════════════════════════════════════════╝
EOF
        echo -e "${NC}"
    fi
}

# Early initialization to ensure log directory exists
ensure_log_directory() {
    if [[ ! -d "$REPORT_DIR" ]]; then
        mkdir -p "$REPORT_DIR" 2>/dev/null || {
            echo "Error: Cannot create report directory: $REPORT_DIR"
            echo "Using /tmp as fallback"
            REPORT_DIR="/tmp/security_audits"
            # Update all file paths with new REPORT_DIR
            REPORT_FILE="${REPORT_DIR}/security_audit_${TIMESTAMP}.txt"
            JSON_REPORT="${REPORT_DIR}/security_audit_${TIMESTAMP}.json"
            HTML_REPORT="${REPORT_DIR}/security_audit_${TIMESTAMP}.html"
            LOG_FILE="${REPORT_DIR}/audit_${TIMESTAMP}.log"
            mkdir -p "$REPORT_DIR" 2>/dev/null || {
                echo "Fatal: Cannot create any report directory"
                exit 1
            }
        }
    fi
    
    # Create log file immediately
    touch "$LOG_FILE" 2>/dev/null || {
        echo "Warning: Cannot create log file: $LOG_FILE"
        LOG_FILE="/dev/null"  # Fallback to null device
    }
}

log_message() {
    local level="$1"; shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Only write to log if it exists and is writable
    if [[ -w "$LOG_FILE" ]]; then
        echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    fi

    # In quiet mode, only show warnings and errors
    if $QUIET_MODE && [[ "$level" != "ERROR" && "$level" != "WARNING" ]]; then
        return
    fi
    
    # In verbose mode, show everything
    if ! $VERBOSE_MODE && [[ "$level" == "DEBUG" ]]; then
        return
    fi

    case "$level" in
        INFO)     echo -e "${BLUE}[ℹ]${NC} $message" ;;
        SUCCESS)  echo -e "${GREEN}[✓]${NC} $message" ;;
        WARNING)  echo -e "${YELLOW}[⚠]${NC} $message" ; ((WARNINGS++)) ;;
        ERROR)    echo -e "${RED}[✗]${NC} $message" ; ((ISSUES++)) ;;
        KALI)     echo -e "${PURPLE}[K]${NC} $message" ; ((KALI_SPECIFIC_CHECKS++)) ;;
        DEBUG)    echo -e "${DIM}[D]${NC} $message" ;;
    esac
}

show_progress() {
    if $QUIET_MODE; then
        return
    fi
    
    local current=$1 
    local total=$2 
    local width=50
    
    # FIX: Prevent division by zero
    if [[ $total -eq 0 ]]; then
        return
    fi
    
    local percent=$((current * 100 / total))
    local filled=$((width * current / total))
    
    printf "\r${CYAN}Progress: ${NC}["
    printf "%${filled}s" | tr ' ' '█'
    printf "%$((width - filled))s" | tr ' ' '░'
    printf "] ${BOLD}%3d%%${NC} (%d/%d)" "$percent" "$current" "$total"
    
    [[ $current -eq $total ]] && echo ""
}

# FIX: Safe wrapper function - no eval, proper quoting
safe_find() {
    local path="$1"
    shift  # Remove path from arguments
    local timeout_s=${FIND_TIMEOUT:-20}
    
    # Check if path exists and is a directory
    if [[ ! -d "$path" ]]; then
        return 1
    fi
    
    # Execute find with all remaining arguments properly quoted
    timeout "$timeout_s" find "$path" -maxdepth "$MAX_FIND_DEPTH" "$@" 2>/dev/null || return 1
}

check_command() { 
    command -v "$1" >/dev/null 2>&1
}

safe_sudo() {
    if [[ $EUID -eq 0 ]]; then
        "$@"
    elif sudo -n true 2>/dev/null; then
        sudo "$@"
    else
        log_message DEBUG "Sudo required for: $*"
        return 1
    fi
}

# -----------------------------
# Environment & prerequisites
# -----------------------------
check_prerequisites() {
    log_message INFO "Checking required commands..."
    
    local required=(ss ps df grep awk timeout find stat)
    local optional=(jq aide docker systemctl sudo)
    local missing=()
    local missing_optional=()
    
    for cmd in "${required[@]}"; do
        if ! check_command "$cmd"; then
            missing+=("$cmd")
        fi
    done
    
    for cmd in "${optional[@]}"; do
        if ! check_command "$cmd"; then
            missing_optional+=("$cmd")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_message ERROR "Missing REQUIRED commands: ${missing[*]}"
        echo "Please install: ${missing[*]}" >&2
        exit 1
    fi
    
    if [[ ${#missing_optional[@]} -gt 0 ]]; then
        log_message DEBUG "Missing optional commands: ${missing_optional[*]}"
    fi
    
    log_message SUCCESS "All prerequisites present"
}

setup_environment() {
    log_message INFO "Setting up environment..."
    
    # Create report directory
    if ! mkdir -p "$REPORT_DIR"; then
        log_message ERROR "Failed to create report directory: $REPORT_DIR"
        exit 1
    fi
    
    chmod 700 "$REPORT_DIR" 2>/dev/null || true
    
    # Initialize report file
    {
        echo "Security Audit Report - Plus Edition"
        echo "====================================="
        echo "Generated: $(date)"
        echo "Hostname: $(hostname)"
        echo "Kernel: $(uname -r)"
        echo "User: $(whoami)"
        echo "Version: $VERSION"
        echo ""
    } > "$REPORT_FILE"
    
    # Initialize JSON data
    JSON_DATA[version]="$VERSION"
    JSON_DATA[timestamp]="$(date -Iseconds)"
    JSON_DATA[hostname]="$(hostname)"
    JSON_DATA[kernel]="$(uname -r)"
    JSON_DATA[user]="$(whoami)"
    
    log_message SUCCESS "Environment ready. Reports directory: $REPORT_DIR"
}

# -----------------------------
# System detection
# -----------------------------
detect_system() {
    # FIX: Always initialize JSON_DATA defaults first
    JSON_DATA[is_kali]="false"
    JSON_DATA[system_type]="Unknown Linux"
    
    local is_kali=false
    local system_info=""
    
    if [[ -f /etc/os-release ]]; then
        if grep -qi kali /etc/os-release 2>/dev/null; then
            is_kali=true
            system_info="Kali Linux $(grep VERSION= /etc/os-release 2>/dev/null | cut -d'"' -f2 || echo 'Unknown')"
        else
            system_info=$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'"' -f2 || echo 'Unknown Linux')
        fi
    fi
    
    # Update with detected values
    JSON_DATA[is_kali]="$is_kali"
    JSON_DATA[system_type]="$system_info"
    
    if $is_kali; then
        log_message KALI "Kali Linux detected - enabling Kali-specific checks"
        return 0
    else
        log_message INFO "System: $system_info"
        return 1
    fi
}

# -----------------------------
# Kali-specific checks
# -----------------------------
check_kali_system_health() {
    # FIX: Check with default value to prevent undefined errors
    [[ "${JSON_DATA[is_kali]:-false}" != "true" ]] && return
    
    log_message KALI "Running Kali system health checks..."
    ((TOTAL_CHECKS++))
    
    {
        echo "=== KALI SYSTEM HEALTH CHECK ==="
        echo ""
        
        # Check if running as root
        if [[ $EUID -eq 0 ]]; then
            echo "  ⚠ Running as root user (common in Kali but risky)"
            ((WARNINGS++))
            JSON_DATA[running_as_root]="true"
        else
            echo "  ✓ Running as non-root user"
            JSON_DATA[running_as_root]="false"
        fi
        
        # Check PATH integrity
        if echo "$PATH" | grep -q "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin" || true; then
            echo "  ✓ PATH environment looks normal"
        else
            echo "  ⚠ PATH may have been modified"
            ((WARNINGS++))
        fi
        
        # Check for system updates
        if check_command apt-get; then
            echo "  ℹ Run 'apt update && apt upgrade' to check for updates"
        fi
        
        echo ""
    } >> "$REPORT_FILE"
    
    ((COMPLETED_CHECKS++))
    show_progress $COMPLETED_CHECKS $TOTAL_CHECKS
}

check_kali_repositories() {
    # FIX: Check with default value
    [[ "${JSON_DATA[is_kali]:-false}" != "true" ]] && return
    
    log_message KALI "Checking Kali repositories..."
    ((TOTAL_CHECKS++))
    
    {
        echo "=== KALI REPOSITORY CHECK ==="
        echo ""
        
        if [[ -f /etc/apt/sources.list ]]; then
            echo "Active repositories:"
            (grep -v '^#' /etc/apt/sources.list 2>/dev/null || true) | grep -v '^$' | while read -r line; do
                echo "  - $line"
            done
            
            # Check for third-party repos
            local third_party_count=0
            if [[ -d /etc/apt/sources.list.d/ ]]; then
                third_party_count=$(find /etc/apt/sources.list.d/ -name "*.list" -type f 2>/dev/null | wc -l || echo 0)
                if [[ $third_party_count -gt 0 ]]; then
                    echo "  ⚠ Found $third_party_count third-party repositories"
                    ((WARNINGS++))
                fi
            fi
            JSON_DATA[third_party_repos]="$third_party_count"
        fi
        echo ""
    } >> "$REPORT_FILE"
    
    ((COMPLETED_CHECKS++))
    show_progress $COMPLETED_CHECKS $TOTAL_CHECKS
}

check_vpn_configurations() {
    # FIX: Check if is_kali is set and true (with default)
    [[ "${JSON_DATA[is_kali]:-false}" != "true" ]] && return
    
    log_message KALI "Checking VPN configurations..."
    ((TOTAL_CHECKS++))
    
    {
        echo "=== VPN CONFIGURATION CHECK ==="
        echo ""
        
        local ovpn_count=0
        for dir in /etc/openvpn "$HOME/openvpn" "$HOME/Documents" "$HOME/Desktop"; do
            if [[ -d "$dir" ]]; then
                # FIX: Use safe_find with proper arguments
                local count=$(safe_find "$dir" -name "*.ovpn" -type f 2>/dev/null | wc -l || echo 0)
                ovpn_count=$((ovpn_count + count))
            fi
        done
        
        echo "  OpenVPN config files found: $ovpn_count"
        JSON_DATA[openvpn_configs]="$ovpn_count"
        
        # Check if VPN is active
        if ip a 2>/dev/null | grep -q "tun0\|tap0" || false; then
            echo "  ✓ VPN connection appears to be active"
            JSON_DATA[vpn_active]="true"
        else
            echo "  ℹ No active VPN connection detected"
            JSON_DATA[vpn_active]="false"
        fi
        echo ""
    } >> "$REPORT_FILE"
    
    ((COMPLETED_CHECKS++))
    show_progress $COMPLETED_CHECKS $TOTAL_CHECKS
}

# -----------------------------
# Core security checks
# -----------------------------
check_ssh_security() {
    log_message INFO "Analyzing SSH security..."
    ((TOTAL_CHECKS++))
    
    {
        echo "=== SSH SECURITY CONFIGURATION ==="
        echo ""
        
        if [[ -f /etc/ssh/sshd_config ]]; then
            # Check PermitRootLogin
            local permit_root
            permit_root=$(grep -E '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "not_set")
            permit_root=${permit_root:-yes}
            
            if [[ "$permit_root" == "yes" ]]; then
                echo "  ⚠ PermitRootLogin is enabled (high risk)"
                ((WARNINGS++))
                JSON_DATA[ssh_permit_root]="true"
            else
                echo "  ✓ PermitRootLogin is disabled or restricted: $permit_root"
                JSON_DATA[ssh_permit_root]="false"
            fi
            
            # Check PasswordAuthentication
            local pass_auth
            pass_auth=$(grep -E '^PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "yes")
            
            if [[ "$pass_auth" == "yes" ]]; then
                echo "  ℹ Password authentication is enabled (consider using keys only)"
                JSON_DATA[ssh_password_auth]="true"
            else
                echo "  ✓ Password authentication is disabled"
                JSON_DATA[ssh_password_auth]="false"
            fi
            
            # Check SSH port
            local ssh_port
            ssh_port=$(grep -E '^Port' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "22")
            echo "  SSH Port: $ssh_port"
            JSON_DATA[ssh_port]="$ssh_port"
        else
            echo "  SSH configuration file not found"
            JSON_DATA[ssh_configured]="false"
        fi
        echo ""
    } >> "$REPORT_FILE"
    
    ((COMPLETED_CHECKS++))
    show_progress $COMPLETED_CHECKS $TOTAL_CHECKS
}

check_cron_jobs() {
    log_message INFO "Analyzing cron jobs..."
    ((TOTAL_CHECKS++))
    
    {
        echo "=== CRON JOBS ANALYSIS ==="
        echo ""
        
        echo "User crontab:"
        if crontab -l 2>/dev/null | grep -v '^#' | grep -v '^$' >/dev/null 2>&1; then
            crontab -l 2>/dev/null | grep -v '^#' | grep -v '^$' | while read -r job; do
                echo "  - $job"
                # Check for suspicious patterns
                if echo "$job" | grep -qE "wget|curl|/tmp/|nc |netcat" || false; then
                    echo "    ⚠ Potentially suspicious command detected"
                    ((WARNINGS++))
                fi
            done
        else
            echo "  No user crontab entries"
        fi
        
        # System cron directories
        echo ""
        echo "System cron directories:"
        for crondir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly; do
            if [[ -d "$crondir" ]]; then
                local count=$(ls -1 "$crondir" 2>/dev/null | wc -l || echo 0)
                echo "  $crondir: $count entries"
            fi
        done
        echo ""
    } >> "$REPORT_FILE"
    
    ((COMPLETED_CHECKS++))
    show_progress $COMPLETED_CHECKS $TOTAL_CHECKS
}

check_kernel_hardening() {
    log_message INFO "Checking kernel hardening..."
    ((TOTAL_CHECKS++))
    
    {
        echo "=== KERNEL HARDENING PARAMETERS ==="
        echo ""
        
        local params=(
            "net.ipv4.tcp_syncookies:1:SYN flood protection"
            "net.ipv4.conf.all.rp_filter:1:Reverse path filtering"
            "kernel.randomize_va_space:2:ASLR enabled"
            "kernel.yama.ptrace_scope:1:Ptrace protection"
        )
        
        for param_info in "${params[@]}"; do
            IFS=':' read -r param expected desc <<< "$param_info"
            local actual
            actual=$(sysctl -n "$param" 2>/dev/null || echo "unknown")
            
            if [[ "$actual" == "$expected" ]]; then
                echo "  ✓ $desc ($param = $actual)"
            elif [[ "$actual" == "unknown" ]]; then
                echo "  ? $desc (unable to check)"
            else
                echo "  ⚠ $desc ($param = $actual, expected $expected)"
                ((WARNINGS++))
            fi
        done
        echo ""
    } >> "$REPORT_FILE"
    
    ((COMPLETED_CHECKS++))
    show_progress $COMPLETED_CHECKS $TOTAL_CHECKS
}

check_docker_security() {
    log_message INFO "Checking Docker security..."
    ((TOTAL_CHECKS++))
    
    {
        echo "=== DOCKER SECURITY CHECK ==="
        echo ""
        
        if check_command docker; then
            echo "Docker Status:"
            
            if systemctl is-active --quiet docker 2>/dev/null || false; then
                echo "  ✓ Docker daemon is running"
                JSON_DATA[docker_running]="true"
                
                # Check containers if we have permission
                if docker ps &>/dev/null || false; then
                    local running_containers=$(docker ps -q 2>/dev/null | wc -l || echo 0)
                    local total_containers=$(docker ps -aq 2>/dev/null | wc -l || echo 0)
                    echo "  Running containers: $running_containers"
                    echo "  Total containers: $total_containers"
                    JSON_DATA[docker_containers_running]="$running_containers"
                else
                    echo "  ℹ Need permissions to check containers"
                fi
            else
                echo "  Docker is installed but not running"
                JSON_DATA[docker_running]="false"
            fi
        else
            echo "  Docker is not installed"
            JSON_DATA[docker_installed]="false"
        fi
        echo ""
    } >> "$REPORT_FILE"
    
    ((COMPLETED_CHECKS++))
    show_progress $COMPLETED_CHECKS $TOTAL_CHECKS
}

check_network_connections_advanced() {
    log_message INFO "Running advanced network analysis..."
    ((TOTAL_CHECKS++))
    
    {
        echo "=== NETWORK CONNECTIONS ANALYSIS ==="
        echo ""
        
        echo "Listening services:"
        if [[ $EUID -eq 0 ]]; then
            ss -tlnp 2>/dev/null | grep LISTEN | head -20 || true
        else
            ss -tln 2>/dev/null | grep LISTEN | head -20 || true
            echo "  ℹ Run with sudo for process information"
        fi
        
        echo ""
        echo "Connection statistics:"
        local established=$(ss -tn state established 2>/dev/null | wc -l || echo 1)
        echo "  Established connections: $((established - 1))"  # Subtract header
        JSON_DATA[established_connections]="$((established - 1))"
        
        # Check for suspicious ports
        local suspicious_ports=(4444 5555 6666 1337 31337)
        echo ""
        echo "Checking for suspicious ports:"
        for port in "${suspicious_ports[@]}"; do
            if ss -tln 2>/dev/null | grep -q ":$port " || false; then
                echo "  ⚠ Suspicious port $port is listening!"
                ((WARNINGS++))
            fi
        done
        echo ""
    } >> "$REPORT_FILE"
    
    ((COMPLETED_CHECKS++))
    show_progress $COMPLETED_CHECKS $TOTAL_CHECKS
}

check_file_integrity() {
    log_message INFO "Checking file integrity..."
    ((TOTAL_CHECKS++))
    
    {
        echo "=== FILE INTEGRITY CHECK ==="
        echo ""
        
        # Check for AIDE
        if check_command aide; then
            echo "  ✓ AIDE is installed"
            if [[ -f /var/lib/aide/aide.db ]]; then
                echo "  ✓ AIDE database exists"
            else
                echo "  ⚠ AIDE database not initialized"
                ((WARNINGS++))
            fi
        else
            echo "  ℹ AIDE not installed (recommended for integrity monitoring)"
        fi
        
        # Check SUID files - FIX: Use safe_find properly
        echo ""
        echo "SUID file analysis:"
        local suid_count
        local usr_suid=$(safe_find /usr -perm -4000 -type f | wc -l)
        local bin_suid=$(safe_find /bin -perm -4000 -type f | wc -l)
        local sbin_suid=$(safe_find /sbin -perm -4000 -type f | wc -l)
        usr_suid=${usr_suid:-0}
        bin_suid=${bin_suid:-0}
        sbin_suid=${sbin_suid:-0}
        suid_count=$((usr_suid + bin_suid + sbin_suid))
        echo "  SUID files found in system directories: $suid_count"
        JSON_DATA[suid_files_count]="$suid_count"
        
        # Check for SUID in suspicious locations - FIX: Use safe_find
        local suspicious_suid
        local tmp_suid=$(safe_find /tmp -perm -4000 -type f | wc -l)
        local var_tmp_suid=$(safe_find /var/tmp -perm -4000 -type f | wc -l)
        tmp_suid=${tmp_suid:-0}
        var_tmp_suid=${var_tmp_suid:-0}
        suspicious_suid=$((tmp_suid + var_tmp_suid))
        if [[ $suspicious_suid -gt 0 ]]; then
            echo "  ⚠ Found $suspicious_suid SUID files in /tmp or /var/tmp!"
            ((WARNINGS++))
        else
            echo "  ✓ No SUID files in temporary directories"
        fi
        echo ""
    } >> "$REPORT_FILE"
    
    ((COMPLETED_CHECKS++))
    show_progress $COMPLETED_CHECKS $TOTAL_CHECKS
}

# -----------------------------
# Report generation
# -----------------------------
generate_json_report() {
    log_message INFO "Generating JSON report..."
    
    # Calculate risk score
    local risk_score=$((ISSUES * 10 + WARNINGS * 3))
    local security_score=$((100 - risk_score))
    [[ $security_score -lt 0 ]] && security_score=0
    
    JSON_DATA[total_warnings]="$WARNINGS"
    JSON_DATA[total_issues]="$ISSUES"
    JSON_DATA[total_recommendations]="$RECOMMENDATIONS"
    JSON_DATA[kali_checks]="$KALI_SPECIFIC_CHECKS"
    JSON_DATA[risk_score]="$risk_score"
    JSON_DATA[security_score]="$security_score"
    
    # Generate JSON file
    {
        echo "{"
        echo "  \"audit_info\": {"
        echo "    \"version\": \"${JSON_DATA[version]}\","
        echo "    \"timestamp\": \"${JSON_DATA[timestamp]}\","
        echo "    \"hostname\": \"${JSON_DATA[hostname]}\","
        echo "    \"kernel\": \"${JSON_DATA[kernel]}\","
        echo "    \"user\": \"${JSON_DATA[user]}\","
        echo "    \"system_type\": \"${JSON_DATA[system_type]:-Unknown}\","
        echo "    \"is_kali\": ${JSON_DATA[is_kali]:-false}"
        echo "  },"
        echo "  \"results\": {"
        echo "    \"warnings\": ${JSON_DATA[total_warnings]},"
        echo "    \"issues\": ${JSON_DATA[total_issues]},"
        echo "    \"recommendations\": ${JSON_DATA[total_recommendations]},"
        echo "    \"risk_score\": ${JSON_DATA[risk_score]},"
        echo "    \"security_score\": ${JSON_DATA[security_score]}"
        echo "  },"
        echo "  \"findings\": {"
        echo "    \"ssh\": {"
        echo "      \"permit_root\": ${JSON_DATA[ssh_permit_root]:-false},"
        echo "      \"password_auth\": ${JSON_DATA[ssh_password_auth]:-true},"
        echo "      \"port\": \"${JSON_DATA[ssh_port]:-22}\""
        echo "    },"
        echo "    \"network\": {"
        echo "      \"established_connections\": ${JSON_DATA[established_connections]:-0}"
        echo "    },"
        echo "    \"system\": {"
        echo "      \"suid_files\": ${JSON_DATA[suid_files_count]:-0},"
        echo "      \"docker_running\": ${JSON_DATA[docker_running]:-false}"
        echo "    }"
        echo "  }"
        echo "}"
    } > "$JSON_REPORT"
    
    log_message SUCCESS "JSON report saved to: $JSON_REPORT"
}

# HTML escape function for security
html_escape() {
    local string="$1"
    string="${string//&/&amp;}"
    string="${string//</&lt;}"
    string="${string//>/&gt;}"
    string="${string//\"/&quot;}"
    string="${string//\'/&#39;}"
    echo "$string"
}

write_html_report() {
    log_message INFO "Generating HTML report..."
    
    local score=$((100 - (ISSUES * 10 + WARNINGS * 3)))
    [[ $score -lt 0 ]] && score=0
    
    local status_color="green"
    local status_text="Good"
    
    if [[ $score -lt 50 ]]; then
        status_color="red"
        status_text="High Risk"
    elif [[ $score -lt 80 ]]; then
        status_color="orange"
        status_text="Medium Risk"
    fi
    
    # FIX: Escape all dynamic content to prevent XSS
    local safe_hostname=$(html_escape "$(hostname)")
    local safe_kernel=$(html_escape "$(uname -r)")
    local safe_user=$(html_escape "$(whoami)")
    local safe_timestamp=$(html_escape "$TIMESTAMP")
    local safe_system_type=$(html_escape "${JSON_DATA[system_type]:-Unknown}")
    
    cat > "$HTML_REPORT" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Audit Report - ${safe_timestamp}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .header {
            background: white;
            border-radius: 10px;
            padding: 30px;
            margin-bottom: 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }
        .header h1 {
            color: #2d3748;
            margin-bottom: 10px;
        }
        .header .meta {
            color: #718096;
            font-size: 14px;
        }
        .score-card {
            background: white;
            border-radius: 10px;
            padding: 30px;
            margin-bottom: 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            text-align: center;
        }
        .score-circle {
            width: 200px;
            height: 200px;
            margin: 0 auto 20px;
            position: relative;
        }
        .score-circle svg {
            transform: rotate(-90deg);
        }
        .score-circle .score-text {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            font-size: 48px;
            font-weight: bold;
            color: #2d3748;
        }
        .status {
            font-size: 24px;
            font-weight: 600;
            color: ${status_color};
            margin-bottom: 20px;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: white;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }
        .stat-card h3 {
            color: #718096;
            font-size: 14px;
            font-weight: 600;
            text-transform: uppercase;
            margin-bottom: 10px;
        }
        .stat-card .value {
            font-size: 32px;
            font-weight: bold;
            color: #2d3748;
        }
        .stat-card.critical .value { color: #f56565; }
        .stat-card.warning .value { color: #ed8936; }
        .stat-card.info .value { color: #4299e1; }
        .details {
            background: white;
            border-radius: 10px;
            padding: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }
        .details h2 {
            color: #2d3748;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e2e8f0;
        }
        .details table {
            width: 100%;
            border-collapse: collapse;
        }
        .details th {
            text-align: left;
            padding: 10px;
            background: #f7fafc;
            color: #4a5568;
            font-weight: 600;
        }
        .details td {
            padding: 10px;
            border-bottom: 1px solid #e2e8f0;
            color: #2d3748;
        }
        .footer {
            text-align: center;
            color: white;
            margin-top: 40px;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Security Audit Report</h1>
            <div class="meta">
                <strong>Generated:</strong> $(date) | 
                <strong>Host:</strong> ${safe_hostname} | 
                <strong>Kernel:</strong> ${safe_kernel} | 
                <strong>User:</strong> ${safe_user}
            </div>
        </div>
        
        <div class="score-card">
            <div class="score-circle">
                <svg width="200" height="200">
                    <circle cx="100" cy="100" r="90" stroke="#e2e8f0" stroke-width="20" fill="none"/>
                    <circle cx="100" cy="100" r="90" stroke="${status_color}" stroke-width="20" fill="none"
                            stroke-dasharray="565" stroke-dashoffset="$((565 - (565 * score / 100)))"
                            stroke-linecap="round"/>
                </svg>
                <div class="score-text">${score}/100</div>
            </div>
            <div class="status">Status: ${status_text}</div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card critical">
                <h3>Critical Issues</h3>
                <div class="value">${ISSUES}</div>
            </div>
            <div class="stat-card warning">
                <h3>Warnings</h3>
                <div class="value">${WARNINGS}</div>
            </div>
            <div class="stat-card info">
                <h3>Checks Performed</h3>
                <div class="value">${COMPLETED_CHECKS}</div>
            </div>
        </div>
        
        <div class="details">
            <h2>📊 Audit Details</h2>
            <table>
                <tr>
                    <th>Category</th>
                    <th>Status</th>
                    <th>Details</th>
                </tr>
                <tr>
                    <td>SSH Security</td>
                    <td>${JSON_DATA[ssh_permit_root]:-Unknown}</td>
                    <td>Root login: ${JSON_DATA[ssh_permit_root]:-Unknown}, Port: ${JSON_DATA[ssh_port]:-22}</td>
                </tr>
                <tr>
                    <td>Network</td>
                    <td>Checked</td>
                    <td>Active connections: ${JSON_DATA[established_connections]:-0}</td>
                </tr>
                <tr>
                    <td>File Integrity</td>
                    <td>Checked</td>
                    <td>SUID files: ${JSON_DATA[suid_files_count]:-0}</td>
                </tr>
                <tr>
                    <td>System Type</td>
                    <td>${safe_system_type}</td>
                    <td>Kali: ${JSON_DATA[is_kali]:-false}</td>
                </tr>
            </table>
        </div>
        
        <div class="footer">
            <p>Security Audit Tool Plus v${VERSION} | Report generated on ${TIMESTAMP}</p>
        </div>
    </div>
</body>
</html>
EOF
    
    log_message SUCCESS "HTML report saved to: $HTML_REPORT"
}

generate_recommendations() {
    log_message INFO "Generating recommendations..."
    
    {
        echo ""
        echo "=== SECURITY RECOMMENDATIONS ==="
        echo ""
        
        local rec_count=0
        
        if [[ "${JSON_DATA[ssh_permit_root]}" == "true" ]]; then
            echo "$((++rec_count)). Disable SSH root login in /etc/ssh/sshd_config"
            ((RECOMMENDATIONS++))
        fi
        
        if [[ "${JSON_DATA[ssh_password_auth]}" == "true" ]]; then
            echo "$((++rec_count)). Consider disabling password authentication and using SSH keys"
            ((RECOMMENDATIONS++))
        fi
        
        if [[ "${JSON_DATA[running_as_root]}" == "true" ]]; then
            echo "$((++rec_count)). Create and use a non-root user for daily operations"
            ((RECOMMENDATIONS++))
        fi
        
        if [[ $WARNINGS -gt 5 ]]; then
            echo "$((++rec_count)). Address the $WARNINGS warnings found during the scan"
            ((RECOMMENDATIONS++))
        fi
        
        if [[ $rec_count -eq 0 ]]; then
            echo "No critical recommendations. Continue with regular security practices."
        fi
        
        echo ""
    } >> "$REPORT_FILE"
}

final_summary() {
    # Calculate final score
    local score=$((100 - (ISSUES * 10 + WARNINGS * 3)))
    [[ $score -lt 0 ]] && score=0
    
    if ! $QUIET_MODE; then
        echo ""
        echo -e "${BOLD}╔════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${BOLD}║                    FINAL SECURITY SCORE                        ║${NC}"
        echo -e "${BOLD}╚════════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        
        # Display score with color
        if [[ $score -ge 80 ]]; then
            echo -e "  ${GREEN}${BOLD}Score: $score/100 - GOOD${NC}"
        elif [[ $score -ge 50 ]]; then
            echo -e "  ${YELLOW}${BOLD}Score: $score/100 - MEDIUM RISK${NC}"
        else
            echo -e "  ${RED}${BOLD}Score: $score/100 - HIGH RISK${NC}"
        fi
        
        echo ""
        echo "  Statistics:"
        echo "  • Critical Issues: $ISSUES"
        echo "  • Warnings: $WARNINGS"
        echo "  • Recommendations: $RECOMMENDATIONS"
        echo "  • Total Checks: $COMPLETED_CHECKS"
        
        if [[ "${JSON_DATA[is_kali]}" == "true" ]]; then
            echo "  • Kali-specific checks: $KALI_SPECIFIC_CHECKS"
        fi
        
        echo ""
        echo -e "${BOLD}Reports saved to:${NC}"
        echo "  • Text: $REPORT_FILE"
        echo "  • JSON: $JSON_REPORT"
        echo "  • HTML: $HTML_REPORT"
        echo ""
    fi
}

# -----------------------------
# CLI parsing and main flow
# -----------------------------
usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Security Audit Tool Plus - Professional Linux Security Assessment

OPTIONS:
    --ssh-only      Run only SSH related checks
    --network       Run only network related checks
    --full          Run full audit (default)
    --quiet         Quiet mode (only warnings/errors shown)
    --verbose       Verbose mode (show debug information)
    --help          Show this help message

EXAMPLES:
    $0                    # Run full audit
    $0 --ssh-only        # Check only SSH configuration
    $0 --network --quiet # Check network quietly
    
REPORTS:
    Reports are saved to: ~/security_audits/
    Formats: Text, JSON, and HTML

EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --ssh-only)
                MODE="ssh"
                shift
                ;;
            --network)
                MODE="network"
                shift
                ;;
            --full)
                MODE="full"
                shift
                ;;
            --quiet)
                QUIET_MODE=true
                shift
                ;;
            --verbose)
                VERBOSE_MODE=true
                shift
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
}

# Count total checks based on mode - FIX: More accurate counting
count_total_checks() {
    case "$MODE" in
        ssh)
            TOTAL_CHECKS=1
            ;;
        network)
            TOTAL_CHECKS=1
            ;;
        full)
            # Count standard checks
            TOTAL_CHECKS=6  # ssh, cron, kernel, docker, network, file_integrity
            
            # Add Kali checks if applicable (already detected)
            if [[ "${JSON_DATA[is_kali]:-false}" == "true" ]]; then
                TOTAL_CHECKS=$((TOTAL_CHECKS + 3))  # health, repos, vpn
            fi
            ;;
    esac
    
    log_message DEBUG "Total checks to perform: $TOTAL_CHECKS"
}

main() {
    # Parse command line arguments
    parse_args "$@"
    
    # Ensure log directory exists BEFORE any logging
    ensure_log_directory
    
    # Setup
    print_banner
    check_prerequisites
    setup_environment
    
    # Detect system type
    detect_system || true
    
    # Count total checks for progress bar
    count_total_checks
    
    # Run checks based on mode
    log_message INFO "Running security audit in '$MODE' mode..."
    
    case "$MODE" in
        ssh)
            check_ssh_security
            ;;
        network)
            check_network_connections_advanced
            ;;
        full)
            # Run Kali-specific checks if on Kali
            if [[ "${JSON_DATA[is_kali]}" == "true" ]]; then
                check_kali_system_health
                check_kali_repositories
                check_vpn_configurations
            fi
            
            # Run standard security checks
            check_ssh_security
            check_cron_jobs
            check_kernel_hardening
            check_docker_security
            check_network_connections_advanced
            check_file_integrity
            ;;
    esac
    
    # Generate recommendations
    generate_recommendations
    
    # Generate reports
    generate_json_report
    write_html_report
    
    # Show final summary
    final_summary
    
    log_message SUCCESS "Security audit completed successfully!"
}

# Trap to handle interruptions gracefully
trap 'echo -e "\n${RED}[!]${NC} Audit interrupted by user"; exit 130' INT TERM

# Run main function
main "$@"
