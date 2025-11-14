#!/usr/bin/env bash
#
# Try `install_jueudp.sh --help` for usage.
#
# (c) 2023 Jue Htet
#

set -e

# Domain Name
DOMAIN="eg.jueudp.com"
# PROTOCOL
PROTOCOL="udp"
# UDP PORT
UDP_PORT=":36712"
# OBFS
OBFS="jaideevpn"
# PASSWORDS
PASSWORD="jaideevpn"
# Web Dashboard Port
WEB_DASHBOARD_PORT="88"

# Script paths
SCRIPT_NAME="$(basename "$0")"
SCRIPT_ARGS=("$@")
EXECUTABLE_INSTALL_PATH="/usr/local/bin/hysteria"
SYSTEMD_SERVICES_DIR="/etc/systemd/system"
CONFIG_DIR="/etc/hysteria"
USER_DB="$CONFIG_DIR/udpusers.db"
REPO_URL="https://github.com/apernet/hysteria"
CONFIG_FILE="$CONFIG_DIR/config.json"
API_BASE_URL="https://api.github.com/repos/apernet/hysteria"
CURL_FLAGS=(-L -f -q --retry 5 --retry-delay 10 --retry-max-time 60)
PACKAGE_MANAGEMENT_INSTALL="${PACKAGE_MANAGEMENT_INSTALL:-}"
SYSTEMD_SERVICE="$SYSTEMD_SERVICES_DIR/hysteria-server.service"

mkdir -p "$CONFIG_DIR"
touch "$USER_DB"

# Other configurations
OPERATING_SYSTEM=""
ARCHITECTURE=""
HYSTERIA_USER=""
HYSTERIA_HOME_DIR=""
VERSION=""
FORCE=""
LOCAL_FILE=""
FORCE_NO_ROOT=""
FORCE_NO_SYSTEMD=""

# Utility functions
has_command() {
    local _command=$1
    type -P "$_command" > /dev/null 2>&1
}

curl() {
    command curl "${CURL_FLAGS[@]}" "$@"
}

mktemp() {
    command mktemp "$@" "hyservinst.XXXXXXXXXX"
}

tput() {
    if has_command tput; then
        command tput "$@"
    fi
}

tred() {
    tput setaf 1
}

tgreen() {
    tput setaf 2
}

tyellow() {
    tput setaf 3
}

tblue() {
    tput setaf 4
}

taoi() {
    tput setaf 6
}

tbold() {
    tput bold
}

treset() {
    tput sgr0
}

note() {
    local _msg="$1"
    echo -e "$SCRIPT_NAME: $(tbold)note: $_msg$(treset)"
}

warning() {
    local _msg="$1"
    echo -e "$SCRIPT_NAME: $(tyellow)warning: $_msg$(treset)"
}

error() {
    local _msg="$1"
    echo -e "$SCRIPT_NAME: $(tred)error: $_msg$(treset)"
}

show_argument_error_and_exit() {
    local _error_msg="$1"
    error "$_error_msg"
    echo "Try \"$0 --help\" for the usage." >&2
    exit 22
}

install_content() {
    local _install_flags="$1"
    local _content="$2"
    local _destination="$3"
    local _tmpfile="$(mktemp)"
    echo -ne "Install $_destination ... "
    echo "$_content" > "$_tmpfile"
    if install "$_install_flags" "$_tmpfile" "$_destination"; then
        echo -e "ok"
    fi
    rm -f "$_tmpfile"
}

remove_file() {
    local _target="$1"
    echo -ne "Remove $_target ... "
    if rm "$_target"; then
        echo -e "ok"
    fi
}

exec_sudo() {
    local _saved_ifs="$IFS"
    IFS=$'\n'
    local _preserved_env=(
        $(env | grep "^PACKAGE_MANAGEMENT_INSTALL=" || true)
        $(env | grep "^OPERATING_SYSTEM=" || true)
        $(env | grep "^ARCHITECTURE=" || true)
        $(env | grep "^HYSTERIA_\w*=" || true)
        $(env | grep "^FORCE_\w*=" || true)
    )
    IFS="$_saved_ifs"
    exec sudo env \
        "${_preserved_env[@]}" \
        "$@"
}

install_software() {
    local package="$1"
    if has_command apt-get; then
        echo "Installing $package using apt-get..."
        apt-get update && apt-get install -y "$package"
    elif has_command dnf; then
        echo "Installing $package using dnf..."
        dnf install -y "$package"
    elif has_command yum; then
        echo "Installing $package using yum..."
        yum install -y "$package"
    elif has_command zypper; then
        echo "Installing $package using zypper..."
        zypper install -y "$package"
    elif has_command pacman; then
        echo "Installing $package using pacman..."
        pacman -Sy --noconfirm "$package"
    else
        echo "Error: No supported package manager found. Please install $package manually."
        exit 1
    fi
}

is_user_exists() {
    local _user="$1"
    id "$_user" > /dev/null 2>&1
}

check_permission() {
    if [[ "$UID" -eq '0' ]]; then
        return
    fi
    note "The user currently executing this script is not root."
    case "$FORCE_NO_ROOT" in
        '1')
            warning "FORCE_NO_ROOT=1 is specified, we will process without root and you may encounter the insufficient privilege error."
            ;;
        *)
            if has_command sudo; then
                note "Re-running this script with sudo, you can also specify FORCE_NO_ROOT=1 to force this script running with current user."
                exec_sudo "$0" "${SCRIPT_ARGS[@]}"
            else
                error "Please run this script with root or specify FORCE_NO_ROOT=1 to force this script running with current user."
                exit 13
            fi
            ;;
    esac
}

check_environment_operating_system() {
    if [[ -n "$OPERATING_SYSTEM" ]]; then
        warning "OPERATING_SYSTEM=$OPERATING_SYSTEM is specified, operating system detection will not be performed."
        return
    fi
    if [[ "x$(uname)" == "xLinux" ]]; then
        OPERATING_SYSTEM=linux
        return
    fi
    error "This script only supports Linux."
    note "Specify OPERATING_SYSTEM=[linux|darwin|freebsd|windows] to bypass this check and force this script running on this $(uname)."
    exit 95
}

check_environment_architecture() {
    if [[ -n "$ARCHITECTURE" ]]; then
        warning "ARCHITECTURE=$ARCHITECTURE is specified, architecture detection will not be performed."
        return
    fi
    case "$(uname -m)" in
        'i386' | 'i686')
            ARCHITECTURE='386'
            ;;
        'amd64' | 'x86_64')
            ARCHITECTURE='amd64'
            ;;
        'armv5tel' | 'armv6l' | 'armv7' | 'armv7l')
            ARCHITECTURE='arm'
            ;;
        'armv8' | 'aarch64')
            ARCHITECTURE='arm64'
            ;;
        'mips' | 'mipsle' | 'mips64' | 'mips64le')
            ARCHITECTURE='mipsle'
            ;;
        's390x')
            ARCHITECTURE='s390x'
            ;;
        *)
            error "The architecture '$(uname -a)' is not supported."
            note "Specify ARCHITECTURE=<architecture> to bypass this check and force this script running on this $(uname -m)."
            exit 8
            ;;
    esac
}

check_environment_systemd() {
    if [[ -d "/run/systemd/system" ]] || grep -q systemd <(ls -l /sbin/init); then
        return
    fi
    case "$FORCE_NO_SYSTEMD" in
        '1')
            warning "FORCE_NO_SYSTEMD=1 is specified, we will process as normal even if systemd is not detected by us."
            ;;
        '2')
            warning "FORCE_NO_SYSTEMD=2 is specified, we will process but all systemd related commands will not be executed."
            ;;
        *)
            error "This script only supports Linux distributions with systemd."
            note "Specify FORCE_NO_SYSTEMD=1 to disable this check and force this script running as systemd is detected."
            note "Specify FORCE_NO_SYSTEMD=2 to disable this check along with all systemd related commands."
            ;;
    esac
}

parse_arguments() {
    while [[ "$#" -gt '0' ]]; do
        case "$1" in
            '--remove')
                if [[ -n "$OPERATION" && "$OPERATION" != 'remove' ]]; then
                    show_argument_error_and_exit "Option '--remove' is conflicted with other options."
                fi
                OPERATION='remove'
                ;;
            '--version')
                VERSION="$2"
                if [[ -z "$VERSION" ]]; then
                    show_argument_error_and_exit "Please specify the version for option '--version'."
                fi
                shift
                if ! [[ "$VERSION" == v* ]]; then
                    show_argument_error_and_exit "Version numbers should begin with 'v' (such like 'v1.3.1'), got '$VERSION'"
                fi
                ;;
            '-h' | '--help')
                show_usage_and_exit
                ;;
            '-l' | '--local')
                LOCAL_FILE="$2"
                if [[ -z "$LOCAL_FILE" ]]; then
                    show_argument_error_and_exit "Please specify the local binary to install for option '-l' or '--local'."
                fi
                break
                ;;
            *)
                show_argument_error_and_exit "Unknown option '$1'"
                ;;
        esac
        shift
    done
    if [[ -z "$OPERATION" ]]; then
        OPERATION='install'
    fi

    # validate arguments
    case "$OPERATION" in
        'install')
            if [[ -n "$VERSION" && -n "$LOCAL_FILE" ]]; then
                show_argument_error_and_exit '--version and --local cannot be specified together.'
            fi
            ;;
        *)
            if [[ -n "$VERSION" ]]; then
                show_argument_error_and_exit "--version is only available when installing."
            fi
            if [[ -n "$LOCAL_FILE" ]]; then
                show_argument_error_and_exit "--local is only available when installing."
            fi
            ;;
    esac
}

check_hysteria_homedir() {
    local _default_hysteria_homedir="$1"
    if [[ -n "$HYSTERIA_HOME_DIR" ]]; then
        return
    fi
    if ! is_user_exists "$HYSTERIA_USER"; then
        HYSTERIA_HOME_DIR="$_default_hysteria_homedir"
        return
    fi
    HYSTERIA_HOME_DIR="$(eval echo ~"$HYSTERIA_USER")"
}

download_hysteria() {
    local _version="$1"
    local _destination="$2"
    local _download_url="$REPO_URL/releases/download/v1.3.5/hysteria-$OPERATING_SYSTEM-$ARCHITECTURE"
    echo "Downloading hysteria archive: $_download_url ..."
    if ! curl -R -H 'Cache-Control: no-cache' "$_download_url" -o "$_destination"; then
        error "Download failed! Please check your network and try again."
        return 11
    fi
    return 0
}

check_hysteria_user() {
    local _default_hysteria_user="$1"
    if [[ -n "$HYSTERIA_USER" ]]; then
        return
    fi
    if [[ ! -e "$SYSTEMD_SERVICES_DIR/hysteria-server.service" ]]; then
        HYSTERIA_USER="$_default_hysteria_user"
        return
    fi
    HYSTERIA_USER="$(grep -o '^User=\w*' "$SYSTEMD_SERVICES_DIR/hysteria-server.service" | tail -1 | cut -d '=' -f 2 || true)"
    if [[ -z "$HYSTERIA_USER" ]]; then
        HYSTERIA_USER="$_default_hysteria_user"
    fi
}

check_environment_curl() {
    if ! has_command curl; then
        install_software "curl"
    fi
}

check_environment_grep() {
    if ! has_command grep; then
        install_software "grep"
    fi
}

check_environment_sqlite3() {
    if ! has_command sqlite3; then
        install_software "sqlite3"
    fi
}

check_environment_pip() {
    if ! has_command pip; then
        install_software "pip"
    fi
}

check_environment_jq() {
    if ! has_command jq; then
        install_software "jq"
    fi
}

check_environment() {
    check_environment_operating_system
    check_environment_architecture
    check_environment_systemd
    check_environment_curl
    check_environment_grep
    check_environment_pip
    check_environment_sqlite3
    check_environment_jq
}

show_usage_and_exit() {
    echo
    echo -e "\t$(tbold)$SCRIPT_NAME$(treset) - AGN-UDP server install script"
    echo
    echo -e "Usage:"
    echo
    echo -e "$(tbold)Install AGN-UDP$(treset)"
    echo -e "\t$0 [ -f | -l <file> | --version <version> ]"
    echo -e "Flags:"
    echo -e "\t-f, --force\tForce re-install latest or specified version even if it has been installed."
    echo -e "\t-l, --local <file>\tInstall specified AGN-UDP binary instead of download it."
    echo -e "\t--version <version>\tInstall specified version instead of the latest."
    echo
    echo -e "$(tbold)Remove AGN-UDP$(treset)"
    echo -e "\t$0 --remove"
    echo
    echo -e "$(tbold)Check for the update$(treset)"
    echo -e "\t$0 -c"
    echo -e "\t$0 --check"
    echo
    echo -e "$(tbold)Show this help$(treset)"
    echo -e "\t$0 -h"
    echo -e "\t$0 --help"
    exit 0
}

tpl_hysteria_server_service_base() {
    local _config_name="$1"
    cat << EOF
[Unit]
Description=AGN-UDP Service
After=network.target

[Service]
User=root
Group=root
WorkingDirectory=/etc/hysteria
Environment="PATH=/usr/local/bin/hysteria"
ExecStart=/usr/local/bin/hysteria server --config /etc/hysteria/config.json

[Install]
WantedBy=multi-user.target
EOF
}

tpl_hysteria_server_service() {
    tpl_hysteria_server_service_base 'config'
}

tpl_hysteria_server_x_service() {
    tpl_hysteria_server_service_base '%i'
}

tpl_etc_hysteria_config_json() {
    local_users=$(fetch_users)
    mkdir -p "$CONFIG_DIR"
    cat << EOF > "$CONFIG_FILE"
{
  "server": "$DOMAIN",
  "listen": "$UDP_PORT",
  "protocol": "$PROTOCOL",
  "cert": "/etc/hysteria/hysteria.server.crt",
  "key": "/etc/hysteria/hysteria.server.key",
  "up": "100 Mbps",
  "up_mbps": 100,
  "down": "100 Mbps",
  "down_mbps": 100,
  "disable_udp": false,
  "insecure": true,
  "obfs": "$OBFS",
  "auth": {
    "mode": "passwords",
    "config": [ "$(echo $local_users)" ]
  }
}
EOF
}

setup_db() {
    echo "Setting up database"
    mkdir -p "$(dirname "$USER_DB")"
    if [[ ! -f "$USER_DB" ]]; then
        # Create the database file
        sqlite3 "$USER_DB" ".databases"
        if [[ $? -ne 0 ]]; then
            echo "Error: Unable to create database file at $USER_DB"
            exit 1
        fi
    fi

    # Create the users table
    sqlite3 "$USER_DB" <<EOF
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password TEXT NOT NULL
);
EOF

    # Check if the table 'users' was created successfully
    table_exists=$(sqlite3 "$USER_DB" "SELECT name FROM sqlite_master WHERE type='table' AND name='users';")
    if [[ "$table_exists" == "users" ]]; then
        echo "Database setup completed successfully. Table 'users' exists."
        
        # Add a default user if not already exists
        default_username="default"
        default_password="password"
        user_exists=$(sqlite3 "$USER_DB" "SELECT username FROM users WHERE username='$default_username';")
        if [[ -z "$user_exists" ]]; then
            sqlite3 "$USER_DB" "INSERT INTO users (username, password) VALUES ('$default_username', '$default_password');"
            if [[ $? -eq 0 ]]; then
                echo "Default user created successfully."
            else
                echo "Error: Failed to create default user."
            fi
        else
            echo "Default user already exists."
        fi
    else
        echo "Error: Table 'users' was not created successfully."
        # Show the database schema for debugging
        echo "Current database schema:"
        sqlite3 "$USER_DB" ".schema"
        exit 1
    fi
}

fetch_users() {
    DB_PATH="/etc/hysteria/udpusers.db"
    if [[ -f "$DB_PATH" ]]; then
        sqlite3 "$DB_PATH" "SELECT username || ':' || password FROM users;" | paste -sd, -
    fi
}

perform_install_hysteria_binary() {
    if [[ -n "$LOCAL_FILE" ]]; then
        note "Performing local install: $LOCAL_FILE"
        echo -ne "Installing hysteria executable ... "
        if install -Dm755 "$LOCAL_FILE" "$EXECUTABLE_INSTALL_PATH"; then
            echo "ok"
        else
            exit 2
        fi
        return
    fi

    local _tmpfile=$(mktemp)
    if ! download_hysteria "$VERSION" "$_tmpfile"; then
        rm -f "$_tmpfile"
        exit 11
    fi

    echo -ne "Installing hysteria executable ... "
    if install -Dm755 "$_tmpfile" "$EXECUTABLE_INSTALL_PATH"; then
        echo "ok"
    else
        exit 13
    fi
    rm -f "$_tmpfile"
}

perform_remove_hysteria_binary() {
    remove_file "$EXECUTABLE_INSTALL_PATH"
}

perform_install_hysteria_example_config() {
    tpl_etc_hysteria_config_json
}

perform_install_hysteria_systemd() {
    if [[ "x$FORCE_NO_SYSTEMD" == "x2" ]]; then
        return
    fi
    install_content -Dm644 "$(tpl_hysteria_server_service)" "$SYSTEMD_SERVICES_DIR/hysteria-server.service"
    install_content -Dm644 "$(tpl_hysteria_server_x_service)" "$SYSTEMD_SERVICES_DIR/hysteria-server@.service"
    systemctl daemon-reload
}

perform_remove_hysteria_systemd() {
    remove_file "$SYSTEMD_SERVICES_DIR/hysteria-server.service"
    remove_file "$SYSTEMD_SERVICES_DIR/hysteria-server@.service"
    systemctl daemon-reload
}

perform_install_hysteria_home_legacy() {
    if ! is_user_exists "$HYSTERIA_USER"; then
        echo -ne "Creating user $HYSTERIA_USER ... "
        useradd -r -d "$HYSTERIA_HOME_DIR" -m "$HYSTERIA_USER"
        echo "ok"
    fi
}

perform_install_manager_script() {
    local _manager_script="/usr/local/bin/jueudp_manager.sh"
    local _symlink_path="/usr/local/bin/jueudp"
    
    echo "Downloading manager script..."
    curl -o "$_manager_script" "https://raw.githubusercontent.com/Juessh/Juevpnscript/main/jueudp_manager.sh"
    chmod +x "$_manager_script"
    
    echo "Creating symbolic link to run the manager script using 'jueudp' command..."
    ln -sf "$_manager_script" "$_symlink_path"
    
    echo "Manager script installed at $_manager_script"
    echo "You can now run the manager using the 'jueudp' command."
}

setup_web_dashboard() {
    echo "Setting up professional web dashboard for real-time monitoring..."
    
    # Install required packages
    install_software "nginx"
    install_software "php-fpm"
    install_software "php-sqlite3"
    
    # Create web directory structure - udpserver ဆိုတဲ့ folder name ကိုသုံးမယ်
    local web_dir="/var/www/udpserver"
    mkdir -p "$web_dir"
    
    # Create main dashboard page
    cat > "$web_dir/index.php" << 'EOF'
<?php
header('Content-Type: text/html; charset=utf-8');
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AGN UDP Server Dashboard</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        .header {
            text-align: center;
            color: white;
            margin-bottom: 30px;
            padding: 20px;
        }
        
        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        
        .header p {
            font-size: 1.1rem;
            opacity: 0.9;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: rgba(255, 255, 255, 0.95);
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            text-align: center;
        }
        
        .stat-card h3 {
            color: #333;
            margin-bottom: 10px;
            font-size: 1rem;
        }
        
        .stat-number {
            font-size: 2rem;
            font-weight: bold;
            color: #667eea;
        }
        
        .server-list {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 30px;
        }
        
        .server-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        
        .server-card {
            background: white;
            padding: 20px;
            border-radius: 12px;
            box-shadow: 0 4px 16px rgba(0,0,0,0.1);
            border-left: 4px solid;
        }
        
        .server-card.online {
            border-left-color: #10b981;
        }
        
        .server-card.offline {
            border-left-color: #ef4444;
        }
        
        .server-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .server-name {
            font-weight: bold;
            font-size: 1.2rem;
            color: #333;
        }
        
        .status-badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: bold;
            color: white;
        }
        
        .status-online {
            background: #10b981;
        }
        
        .status-offline {
            background: #ef4444;
        }
        
        .server-info {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
        }
        
        .info-item {
            display: flex;
            flex-direction: column;
        }
        
        .info-label {
            font-size: 0.8rem;
            color: #666;
            margin-bottom: 4px;
        }
        
        .info-value {
            font-weight: bold;
            color: #333;
        }
        
        .api-links {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            padding: 20px;
            text-align: center;
        }
        
        .api-link {
            display: inline-block;
            margin: 10px;
            padding: 10px 20px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            transition: background 0.3s;
        }
        
        .api-link:hover {
            background: #5a6fd8;
        }
        
        .last-updated {
            text-align: center;
            color: white;
            margin-top: 20px;
            font-size: 0.9rem;
            opacity: 0.8;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><i class="fas fa-server"></i> AGN UDP Server Dashboard</h1>
            <p>Real-time Server Monitoring & User Statistics</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <h3><i class="fas fa-server"></i> Total Servers</h3>
                <div class="stat-number" id="total-servers">0</div>
            </div>
            <div class="stat-card">
                <h3><i class="fas fa-users"></i> Online Users</h3>
                <div class="stat-number" id="online-users">0</div>
            </div>
            <div class="stat-card">
                <h3><i class="fas fa-signal"></i> Active Servers</h3>
                <div class="stat-number" id="active-servers">0</div>
            </div>
        </div>
        
        <div class="server-list">
            <h3 style="color: #333; margin-bottom: 20px;">
                <i class="fas fa-list"></i> Server Status
            </h3>
            <div class="server-grid" id="server-grid">
                <!-- Server cards will be populated by JavaScript -->
            </div>
        </div>
        
        <div class="api-links">
            <h3 style="color: #333; margin-bottom: 15px;">API Endpoints</h3>
            <a href="online_app" class="api-link" target="_blank">
                <i class="fas fa-code"></i> JSON API
            </a>
            <a href="online" class="api-link" target="_blank">
                <i class="fas fa-text"></i> Text API
            </a>
        </div>
        
        <div class="last-updated">
            Last updated: <span id="last-updated-time">Loading...</span>
        </div>
    </div>

    <script>
        function updateDashboard() {
            fetch('online_app')
                .then(response => response.json())
                .then(data => {
                    // Update stats
                    document.getElementById('total-servers').textContent = data.servers.length;
                    document.getElementById('online-users').textContent = data.total_online;
                    document.getElementById('active-servers').textContent = 
                        data.servers.filter(s => s.status === 'Online').length;
                    
                    // Update server grid
                    const serverGrid = document.getElementById('server-grid');
                    serverGrid.innerHTML = data.servers.map(server => `
                        <div class="server-card ${server.status.toLowerCase()}">
                            <div class="server-header">
                                <div class="server-name">${server.name}</div>
                                <div class="status-badge status-${server.status.toLowerCase()}">
                                    ${server.status}
                                </div>
                            </div>
                            <div class="server-info">
                                <div class="info-item">
                                    <span class="info-label">Users</span>
                                    <span class="info-value">${server.users}</span>
                                </div>
                                <div class="info-item">
                                    <span class="info-label">Load</span>
                                    <span class="info-value">${server.load}</span>
                                </div>
                                <div class="info-item">
                                    <span class="info-label">Ping</span>
                                    <span class="info-value">${server.ping}</span>
                                </div>
                                <div class="info-item">
                                    <span class="info-label">Uptime</span>
                                    <span class="info-value">${server.uptime}</span>
                                </div>
                            </div>
                        </div>
                    `).join('');
                    
                    // Update last updated time
                    document.getElementById('last-updated-time').textContent = new Date().toLocaleString();
                })
                .catch(error => {
                    console.error('Error:', error);
                });
        }
        
        // Update every 3 seconds
        setInterval(updateDashboard, 3000);
        updateDashboard();
    </script>
</body>
</html>
EOF

    # Create JSON API endpoint
    cat > "$web_dir/online_app.php" << 'EOF'
<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

function getOnlineUsers() {
    $online_users = [];
    
    // Check Hysteria server status and get connected users
    exec("ss -uap | grep hysteria | wc -l", $output);
    $connection_count = intval($output[0]) - 1; // Subtract the listener
    
    // Get users from database
    $db_path = '/etc/hysteria/udpusers.db';
    if (file_exists($db_path)) {
        try {
            $db = new SQLite3($db_path);
            $result = $db->query("SELECT username FROM users");
            
            while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                $online_users[] = $row['username'];
            }
        } catch (Exception $e) {
            error_log("Database error: " . $e->getMessage());
        }
    }
    
    return max($connection_count, count($online_users));
}

// Simulate multiple servers (you can replace with real server monitoring)
$servers = [
    [
        'name' => 'TH-01',
        'status' => 'Online',
        'users' => getOnlineUsers() . ' / 80',
        'load' => 'Good',
        'ping' => rand(10, 60) . ' ms',
        'uptime' => '15 days'
    ],
    [
        'name' => 'TH-02', 
        'status' => 'Online',
        'users' => rand(5, 20) . ' / 80',
        'load' => 'Good',
        'ping' => rand(5, 30) . ' ms',
        'uptime' => '12 days'
    ],
    [
        'name' => 'TH-03',
        'status' => 'Online', 
        'users' => rand(1, 10) . ' / 80',
        'load' => 'Good',
        'ping' => rand(30, 80) . ' ms',
        'uptime' => '8 days'
    ],
    [
        'name' => 'TH-04',
        'status' => 'Online',
        'users' => rand(3, 15) . ' / 80',
        'load' => 'Good',
        'ping' => rand(1, 50) . ' ms',
        'uptime' => '10 days'
    ],
    [
        'name' => 'JP-01',
        'status' => 'Offline',
        'users' => '0 / 80',
        'load' => 'Offline',
        'ping' => '3220 ms',
        'uptime' => '0 days'
    ],
    [
        'name' => 'SG-01',
        'status' => 'Offline',
        'users' => '0 / 80',
        'load' => 'Offline',
        'ping' => '5007 ms',
        'uptime' => '0 days'
    ],
    [
        'name' => 'SG-02',
        'status' => 'Offline',
        'users' => '0 / 80',
        'load' => 'Offline',
        'ping' => '54 ms',
        'uptime' => '0 days'
    ],
    [
        'name' => 'SG-03',
        'status' => 'Offline',
        'users' => '0 / 80',
        'load' => 'Offline',
        'ping' => '0 ms',
        'uptime' => '0 days'
    ]
];

echo json_encode([
    'status' => 'success',
    'total_online' => getOnlineUsers(),
    'server_status' => 'running',
    'timestamp' => time(),
    'servers' => $servers
]);
?>
EOF

    # Create Text API endpoint
    cat > "$web_dir/online.php" << 'EOF'
<?php
header('Content-Type: text/plain');
header('Access-Control-Allow-Origin: *');

function getOnlineUsers() {
    // Check Hysteria server status and get connected users
    exec("ss -uap | grep hysteria | wc -l", $output);
    $connection_count = intval($output[0]) - 1;
    return max($connection_count, 0);
}

$online_users = getOnlineUsers();
echo "Online Users: " . $online_users . "\n";
echo "Server Status: Running\n";
echo "Last Updated: " . date('Y-m-d H:i:s') . "\n";
?>
EOF

    # Create nginx configuration - port 88 ကိုပဲသုံးမယ်
    cat > "/etc/nginx/sites-available/udpserver" << EOF
server {
    listen $WEB_DASHBOARD_PORT;
    server_name _;
    root /var/www/udpserver;
    index index.php index.html;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php-fpm.sock;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
}
EOF

    # Set proper permissions
    chown -R www-data:www-data "$web_dir"
    chmod -R 755 "$web_dir"
    
    # Enable site
    ln -sf "/etc/nginx/sites-available/udpserver" "/etc/nginx/sites-enabled/"
    rm -f /etc/nginx/sites-enabled/default
    
    # Restart services
    systemctl enable nginx
    systemctl enable php7.4-fpm || systemctl enable php8.0-fpm || systemctl enable php8.1-fpm || systemctl enable php8.2-fpm
    systemctl restart nginx
    systemctl restart php7.4-fpm || systemctl restart php8.0-fpm || systemctl restart php8.1-fpm || systemctl restart php8.2-fpm
    
    # Get server IP
    SERVER_IP=$(curl -s ifconfig.me || hostname -I | awk '{print $1}')
    
    echo "=================================================="
    echo "🔥 AGN UDP Professional Dashboard Installed! 🔥"
    echo "=================================================="
    echo ""
    echo "📊 Dashboard URL: http://$SERVER_IP:$WEB_DASHBOARD_PORT/"
    echo "🔗 JSON API: http://$SERVER_IP:$WEB_DASHBOARD_PORT/online_app"
    echo "📝 Text API: http://$SERVER_IP:$WEB_DASHBOARD_PORT/online"
    echo ""
    echo "💡 Features:"
    echo "   ✅ Real-time server monitoring"
    echo "   ✅ Online user counting"
    echo "   ✅ Professional design"
    echo "   ✅ JSON & Text APIs"
    echo "   ✅ Mobile responsive"
    echo ""
    echo "=================================================="
}

is_hysteria_installed() {
    # RETURN VALUE
    # 0: hysteria is installed
    # 1: hysteria is not installed
    if [[ -f "$EXECUTABLE_INSTALL_PATH" || -h "$EXECUTABLE_INSTALL_PATH" ]]; then
        return 0
    fi
    return 1
}

get_running_services() {
    if [[ "x$FORCE_NO_SYSTEMD" == "x2" ]]; then
        return
    fi
    systemctl list-units --state=active --plain --no-legend \
        | grep -o "hysteria-server@*[^\s]*.service" || true
}

restart_running_services() {
    if [[ "x$FORCE_NO_SYSTEMD" == "x2" ]]; then
        return
    fi
    echo "Restarting running service ... "
    for service in $(get_running_services); do
        echo -ne "Restarting $service ... "
        systemctl restart "$service"
        echo "done"
    done
}

stop_running_services() {
    if [[ "x$FORCE_NO_SYSTEMD" == "x2" ]]; then
        return
    fi
    echo "Stopping running service ... "
    for service in $(get_running_services); do
        echo -ne "Stopping $service ... "
        systemctl stop "$service"
        echo "done"
    done
}

perform_install() {
    local _is_fresh_install
    if ! is_hysteria_installed; then
        _is_fresh_install=1
    fi
    
    perform_install_hysteria_binary
    perform_install_hysteria_example_config
    perform_install_hysteria_home_legacy
    perform_install_hysteria_systemd
    setup_ssl
    start_services
    perform_install_manager_script
    setup_web_dashboard
    
    if [[ -n "$_is_fresh_install" ]]; then
        echo
        echo -e "$(tbold)Congratulations! JUE-UDP has been successfully installed on your server.$(treset)"
        echo "Use 'jueudp' command to access the manager."
        echo
        echo -e "$(tbold)Client app Jaidee VPN:$(treset)"
        echo -e "$(tblue)https://play.google.com/store/apps/details?id=com.jaideevpn.net$(treset)"
        echo
        echo -e "Follow me!"
        echo
        echo -e "\t+ Check out my website at $(tblue)https://t.me/jaideevpn$(treset)"
        echo -e "\t+ Follow me on Telegram: $(tblue)https://t.me/Pussy1990$(treset)"
        echo -e "\t+ Follow me on Facebook: $(tblue)https://www.facebook.com/juehtet2025$(treset)"
        echo
    else
        restart_running_services
        start_services
        echo
        echo -e "$(tbold)JUE-UDP has been successfully updated to $VERSION.$(treset)"
        echo
    fi
}

perform_remove() {
    perform_remove_hysteria_binary
    stop_running_services
    perform_remove_hysteria_systemd
    
    # Remove web dashboard
    rm -rf /var/www/udpserver
    rm -f /etc/nginx/sites-available/udpserver
    rm -f /etc/nginx/sites-enabled/udpserver
    
    echo
    echo -e "$(tbold)Congratulations! AGN-UDP has been successfully removed from your server.$(treset)"
    echo
    echo -e "You still need to remove configuration files and ACME certificates manually with the following commands:"
    echo
    echo -e "\t$(tred)rm -rf "$CONFIG_DIR"$(treset)"
    if [[ "x$HYSTERIA_USER" != "xroot" ]]; then
        echo -e "\t$(tred)userdel -r "$HYSTERIA_USER"$(treset)"
    fi
    if [[ "x$FORCE_NO_SYSTEMD" != "x2" ]]; then
        echo
        echo -e "You still might need to disable all related systemd services with the following commands:"
        echo
        echo -e "\t$(tred)rm -f /etc/systemd/system/multi-user.target.wants/hysteria-server.service$(treset)"
        echo -e "\t$(tred)rm -f /etc/systemd/system/multi-user.target.wants/hysteria-server@*.service$(treset)"
        echo -e "\t$(tred)systemctl daemon-reload$(treset)"
    fi
    echo
}

setup_ssl() {
    echo "Installing SSL certificates"
    openssl genrsa -out /etc/hysteria/hysteria.ca.key 2048
    openssl req -new -x509 -days 3650 -key /etc/hysteria/hysteria.ca.key -subj "/C=CN/ST=GD/L=SZ/O=Hysteria, Inc./CN=Hysteria Root CA" -out /etc/hysteria/hysteria.ca.crt
    openssl req -newkey rsa:2048 -nodes -keyout /etc/hysteria/hysteria.server.key -subj "/C=CN/ST=GD/L=SZ/O=Hysteria, Inc./CN=$DOMAIN" -out /etc/hysteria/hysteria.server.csr
    openssl x509 -req -extfile <(printf "subjectAltName=DNS:$DOMAIN,DNS:$DOMAIN") -days 3650 -in /etc/hysteria/hysteria.server.csr -CA /etc/hysteria/hysteria.ca.crt -CAkey /etc/hysteria/hysteria.ca.key -CAcreateserial -out /etc/hysteria/hysteria.server.crt
}

start_services() {
    echo "Starting AGN-UDP"
    apt update
    sudo debconf-set-selections <<< "iptables-persistent iptables-persistent/autosave_v4 boolean true"
    sudo debconf-set-selections <<< "iptables-persistent iptables-persistent/autosave_v6 boolean true"
    apt -y install iptables-persistent
    
    iptables -t nat -A PREROUTING -i $(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1) -p udp --dport 10000:65000 -j DNAT --to-destination $UDP_PORT
    ip6tables -t nat -A PREROUTING -i $(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1) -p udp --dport 10000:65000 -j DNAT --to-destination $UDP_PORT
    
    sysctl net.ipv4.conf.all.rp_filter=0
    sysctl net.ipv4.conf.$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1).rp_filter=0
    
    echo "net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1).rp_filter=0" > /etc/sysctl.conf
    
    sysctl -p
    sudo iptables-save > /etc/iptables/rules.v4
    sudo ip6tables-save > /etc/iptables/rules.v6
    
    systemctl enable hysteria-server.service
    systemctl start hysteria-server.service
}

main() {
    parse_arguments "$@"
    check_permission
    check_environment
    check_hysteria_user "hysteria"
    check_hysteria_homedir "/var/lib/$HYSTERIA_USER"
    
    case "$OPERATION" in
        "install")
            setup_db
            perform_install
            ;;
        "remove")
            perform_remove
            ;;
        *)
            error "Unknown operation '$OPERATION'."
            ;;
    esac
}

main "$@"