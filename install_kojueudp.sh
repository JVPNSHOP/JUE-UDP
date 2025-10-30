#!/usr/bin/env bash
# Optimized AGN-UDP (Hysteria) installer — zIVPN-style fast path
# (c) 2023 Jue Htet | edited for performance by ChatGPT

set -e

# ===== User Vars =====
DOMAIN="eg.jueudp.com"
PROTOCOL="udp"
UDP_PORT=":36712"         # final listen port (e.g. :36712)
OBFS="jaideevpn"
PASSWORD="jaideevpn"

# ===== Paths =====
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
mkdir -p "$CONFIG_DIR"; touch "$USER_DB"

# ===== Other Configs =====
OPERATING_SYSTEM=""
ARCHITECTURE=""
HYSTERIA_USER=""
HYSTERIA_HOME_DIR=""
VERSION=""
FORCE=""
LOCAL_FILE=""
FORCE_NO_ROOT=""
FORCE_NO_SYSTEMD=""

# ===== Utils =====
has_command(){ type -P "$1" >/dev/null 2>&1; }
curl(){ command curl "${CURL_FLAGS[@]}" "$@"; }
mktemp(){ command mktemp "$@" "hyservinst.XXXXXXXXXX"; }
tput(){ has_command tput && command tput "$@" || true; }
tred(){ tput setaf 1; }
tyellow(){ tput setaf 3; }
tblue(){ tput setaf 4; }
tbold(){ tput bold; }
treset(){ tput sgr0; }
note(){ echo -e "$SCRIPT_NAME: $(tbold)note: $1$(treset)"; }
warning(){ echo -e "$SCRIPT_NAME: $(tyellow)warning: $1$(treset)"; }
error(){ echo -e "$SCRIPT_NAME: $(tred)error: $1$(treset)"; }
show_argument_error_and_exit(){ error "$1"; echo "Try \"$0 --help\" for the usage." >&2; exit 22; }
install_content(){ local f="$1" c="$2" d="$3"; local tmp="$(mktemp)"; echo -ne "Install $d ... "; echo "$c" > "$tmp"; install "$f" "$tmp" "$d" && echo "ok"; rm -f "$tmp"; }
remove_file(){ echo -ne "Remove $1 ... "; rm "$1" && echo "ok"; }
exec_sudo(){
  local _saved_ifs="$IFS"; IFS=$'\n'
  local _preserved_env=($(env | grep -E '^(PACKAGE_MANAGEMENT_INSTALL|OPERATING_SYSTEM|ARCHITECTURE|HYSTERIA_.*|FORCE_.*)=' || true))
  IFS="$_saved_ifs"
  exec sudo env "${_preserved_env[@]}" "$@"
}
install_software(){
  local p="$1"
  if has_command apt-get; then apt-get update && apt-get install -y "$p"
  elif has_command dnf; then dnf install -y "$p"
  elif has_command yum; then yum install -y "$p"
  elif has_command zypper; then zypper install -y "$p"
  elif has_command pacman; then pacman -Sy --noconfirm "$p"
  else echo "Error: No supported package manager found. Please install $p manually."; exit 1; fi
}
is_user_exists(){ id "$1" >/dev/null 2>&1; }

check_permission(){
  if [[ "$UID" -eq 0 ]]; then return; fi
  note "Current user is not root."
  case "$FORCE_NO_ROOT" in
    1) warning "FORCE_NO_ROOT=1 set — proceeding without root."; ;;
    *) if has_command sudo; then note "Re-running with sudo…"; exec_sudo "$0" "${SCRIPT_ARGS[@]}"; else error "Run as root or set FORCE_NO_ROOT=1"; exit 13; fi ;;
  esac
}
check_environment_operating_system(){
  [[ -n "$OPERATING_SYSTEM" ]] && { warning "OPERATING_SYSTEM preset: $OPERATING_SYSTEM"; return; }
  if [[ "x$(uname)" == "xLinux" ]]; then OPERATING_SYSTEM=linux; return; fi
  error "Linux only."; exit 95
}
check_environment_architecture(){
  [[ -n "$ARCHITECTURE" ]] && { warning "ARCHITECTURE preset: $ARCHITECTURE"; return; }
  case "$(uname -m)" in
    i386|i686) ARCHITECTURE=386;;
    amd64|x86_64) ARCHITECTURE=amd64;;
    armv5tel|armv6l|armv7|armv7l) ARCHITECTURE=arm;;
    armv8|aarch64) ARCHITECTURE=arm64;;
    mips|mipsle|mips64|mips64le) ARCHITECTURE=mipsle;;
    s390x) ARCHITECTURE=s390x;;
    *) error "Unsupported arch $(uname -a)"; exit 8;;
  esac
}
check_environment_systemd(){
  if [[ -d /run/systemd/system ]] || grep -q systemd <(ls -l /sbin/init); then return; fi
  case "$FORCE_NO_SYSTEMD" in
    1) warning "FORCE_NO_SYSTEMD=1 — continue anyway."; ;;
    2) warning "FORCE_NO_SYSTEMD=2 — systemd commands will be skipped."; ;;
    *) error "This script requires systemd."; exit 1;;
  esac
}
parse_arguments(){
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --remove) [[ -n "$OPERATION" && "$OPERATION" != remove ]] && show_argument_error_and_exit "Conflicted option"; OPERATION=remove;;
      --version) VERSION="$2"; [[ -z "$VERSION" ]] && show_argument_error_and_exit "Missing version"; shift; [[ "$VERSION" == v* ]] || show_argument_error_and_exit "Version must start with v";;
      -h|--help) show_usage_and_exit;;
      -l|--local) LOCAL_FILE="$2"; [[ -z "$LOCAL_FILE" ]] && show_argument_error_and_exit "Missing file for --local"; break;;
      *) show_argument_error_and_exit "Unknown option '$1'";;
    esac; shift
  done
  [[ -z "$OPERATION" ]] && OPERATION=install
  case "$OPERATION" in
    install) [[ -n "$VERSION" && -n "$LOCAL_FILE" ]] && show_argument_error_and_exit "--version and --local cannot be together.";;
    *) [[ -n "$VERSION" ]] && show_argument_error_and_exit "--version only for install."; [[ -n "$LOCAL_FILE" ]] && show_argument_error_and_exit "--local only for install.";;
  esac
}
check_hysteria_homedir(){ local d="$1"; [[ -n "$HYSTERIA_HOME_DIR" ]] && return; is_user_exists "$HYSTERIA_USER" || { HYSTERIA_HOME_DIR="$d"; return; }; HYSTERIA_HOME_DIR="$(eval echo ~"$HYSTERIA_USER")"; }

download_hysteria(){
  local _v="$1" _dst="$2"
  local _url="$REPO_URL/releases/download/v1.3.5/hysteria-$OPERATING_SYSTEM-$ARCHITECTURE"
  echo "Downloading hysteria: $_url ..."
  curl -R -H 'Cache-Control: no-cache' "$_url" -o "$_dst" || return 11
  return 0
}
check_hysteria_user(){ local def="$1"; [[ -n "$HYSTERIA_USER" ]] && return; [[ ! -e "$SYSTEMD_SERVICES_DIR/hysteria-server.service" ]] && { HYSTERIA_USER="$def"; return; }
  HYSTERIA_USER="$(grep -o '^User=\w*' "$SYSTEMD_SERVICES_DIR/hysteria-server.service" | tail -1 | cut -d '=' -f 2 || true)"
  [[ -z "$HYSTERIA_USER" ]] && HYSTERIA_USER="$def"
}
check_environment_curl(){ has_command curl || install_software curl; }
check_environment_grep(){ has_command grep || install_software grep; }
check_environment_sqlite3(){ has_command sqlite3 || install_software sqlite3; }
check_environment_pip(){ has_command pip || install_software pip; }
check_environment_jq(){ has_command jq || install_software jq; }
check_environment(){
  check_environment_operating_system
  check_environment_architecture
  check_environment_systemd
  check_environment_curl
  check_environment_grep
  check_environment_pip
  check_environment_sqlite3
  check_environment_jq
}
show_usage_and_exit(){
  echo
  echo -e "\t$(tbold)$SCRIPT_NAME$(treset) - AGN-UDP server install script (optimized)"
  echo
  echo -e "Install:   $0 [ -l <file> | --version <version> ]"
  echo -e "Remove:    $0 --remove"
  echo -e "Optional:  USE_NOTRACK=1 $0  (skip conntrack for hysteria port)"
  exit 0
}

tpl_hysteria_server_service_base(){
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
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
}
tpl_hysteria_server_service(){ tpl_hysteria_server_service_base 'config'; }
tpl_hysteria_server_x_service(){ tpl_hysteria_server_service_base '%i'; }

# ===== CONFIG JSON — Unlimited Mbps (cap removed) =====
tpl_etc_hysteria_config_json(){
  local_users=$(fetch_users)
  mkdir -p "$CONFIG_DIR"
  cat > "$CONFIG_FILE" << EOF
{
  "server": "$DOMAIN",
  "listen": "$UDP_PORT",
  "protocol": "$PROTOCOL",
  "cert": "/etc/hysteria/hysteria.server.crt",
  "key": "/etc/hysteria/hysteria.server.key",
  "up_mbps": 0,
  "down_mbps": 0,
  "disable_udp": false,
  "insecure": true,
  "obfs": "$OBFS",
  "auth": {
    "mode": "passwords",
    "config": [
      "$(echo $local_users)"
    ]
  }
}
EOF
}

# ===== DB =====
setup_db(){
  echo "Setting up database"
  mkdir -p "$(dirname "$USER_DB")"
  [[ -f "$USER_DB" ]] || sqlite3 "$USER_DB" ".databases" || { echo "DB create failed"; exit 1; }
  sqlite3 "$USER_DB" <<'SQL'
CREATE TABLE IF NOT EXISTS users (
  username TEXT PRIMARY KEY,
  password TEXT NOT NULL
);
SQL
  local default_username="default" default_password="password"
  local exists=$(sqlite3 "$USER_DB" "SELECT username FROM users WHERE username='$default_username';")
  [[ -z "$exists" ]] && sqlite3 "$USER_DB" "INSERT INTO users (username, password) VALUES ('$default_username', '$default_password');" || true
}
fetch_users(){
  DB_PATH="/etc/hysteria/udpusers.db"
  [[ -f "$DB_PATH" ]] && sqlite3 "$DB_PATH" "SELECT username || ':' || password FROM users;" | paste -sd, - || true
}

# ===== Install/Remove Binaries & Services =====
perform_install_hysteria_binary(){
  if [[ -n "$LOCAL_FILE" ]]; then
    note "Local install: $LOCAL_FILE"
    echo -ne "Installing hysteria executable ... "
    install -Dm755 "$LOCAL_FILE" "$EXECUTABLE_INSTALL_PATH" && echo "ok" || exit 2
    return
  fi
  local tmp=$(mktemp)
  download_hysteria "$VERSION" "$tmp" || { rm -f "$tmp"; exit 11; }
  echo -ne "Installing hysteria executable ... "
  install -Dm755 "$tmp" "$EXECUTABLE_INSTALL_PATH" && echo "ok" || exit 13
  rm -f "$tmp"
}
perform_remove_hysteria_binary(){ remove_file "$EXECUTABLE_INSTALL_PATH"; }
perform_install_hysteria_example_config(){ tpl_etc_hysteria_config_json; }

perform_install_hysteria_systemd(){
  [[ "x$FORCE_NO_SYSTEMD" == "x2" ]] && return
  install_content -Dm644 "$(tpl_hysteria_server_service)"   "$SYSTEMD_SERVICES_DIR/hysteria-server.service"
  install_content -Dm644 "$(tpl_hysteria_server_x_service)" "$SYSTEMD_SERVICES_DIR/hysteria-server@.service"
  systemctl daemon-reload
}
perform_remove_hysteria_systemd(){
  remove_file "$SYSTEMD_SERVICES_DIR/hysteria-server.service"
  remove_file "$SYSTEMD_SERVICES_DIR/hysteria-server@.service"
  systemctl daemon-reload
}
perform_install_hysteria_home_legacy(){
  if ! is_user_exists "$HYSTERIA_USER"; then
    echo -ne "Creating user $HYSTERIA_USER ... "
    useradd -r -d "$HYSTERIA_HOME_DIR" -m "$HYSTERIA_USER"; echo "ok"
  fi
}
perform_install_manager_script(){
  local mgr="/usr/local/bin/jueudp_manager.sh"
  local link="/usr/local/bin/jueudp"
  echo "Downloading manager script..."
  curl -o "$mgr" "https://raw.githubusercontent.com/Juessh/Juevpnscript/main/jueudp_manager.sh"
  chmod +x "$mgr"
  ln -sf "$mgr" "$link"
  echo "Manager installed as 'jueudp'"
}

is_hysteria_installed(){ [[ -f "$EXECUTABLE_INSTALL_PATH" || -h "$EXECUTABLE_INSTALL_PATH" ]]; }
get_running_services(){
  [[ "x$FORCE_NO_SYSTEMD" == "x2" ]] && return
  systemctl list-units --state=active --plain --no-legend | grep -o "hysteria-server@*[^\s]*.service" || true
}
restart_running_services(){
  [[ "x$FORCE_NO_SYSTEMD" == "x2" ]] && return
  echo "Restarting running service ..."
  for s in $(get_running_services); do echo -ne "Restarting $s ... "; systemctl restart "$s"; echo "done"; done
}
stop_running_services(){
  [[ "x$FORCE_NO_SYSTEMD" == "x2" ]] && return
  echo "Stopping running service ..."
  for s in $(get_running_services); do echo -ne "Stopping $s ... "; systemctl stop "$s"; echo "done"; done
}

# ===== SSL (self-signed) =====
setup_ssl(){
  echo "Installing SSL certificates"
  openssl genrsa -out /etc/hysteria/hysteria.ca.key 2048
  openssl req -new -x509 -days 3650 -key /etc/hysteria/hysteria.ca.key -subj "/C=CN/ST=GD/L=SZ/O=Hysteria, Inc./CN=Hysteria Root CA" -out /etc/hysteria/hysteria.ca.crt
  openssl req -newkey rsa:2048 -nodes -keyout /etc/hysteria/hysteria.server.key -subj "/C=CN/ST=GD/L=SZ/O=Hysteria, Inc./CN=$DOMAIN" -out /etc/hysteria/hysteria.server.csr
  openssl x509 -req -extfile <(printf "subjectAltName=DNS:$DOMAIN,DNS:$DOMAIN") -days 3650 -in /etc/hysteria/hysteria.server.csr -CA /etc/hysteria/hysteria.ca.crt -CAkey /etc/hysteria/hysteria.ca.key -CAcreateserial -out /etc/hysteria/hysteria.server.crt
}

# ===== Performance Tuning =====
apply_sysctl_tuning(){
  cat >/etc/sysctl.d/99-hysteria-udp.conf <<'SYS'
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 4194304
net.core.wmem_default = 4194304
net.core.netdev_max_backlog = 250000
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.ip_forward = 1
SYS
  sysctl --system
}

start_services(){
  echo "Starting AGN-UDP (fast path)"
  systemctl enable hysteria-server.service

  # Detect default iface & parsed listen port
  IFACE=$(ip -4 route show default | awk '/default/ {print $5; exit}')
  LPORT=$(echo "$UDP_PORT" | sed 's/^://')   # ":36712" -> "36712"

  # Apply kernel tuning
  apply_sysctl_tuning

  # Optional: MTU alignment (uncomment to try)
  # ip link set dev "$IFACE" mtu 1380 || true

  # Clean any previous wide-range rules
  iptables -t nat -D PREROUTING -i "$IFACE" -p udp --dport 10000:65000 -j DNAT --to-destination ":$LPORT" 2>/dev/null || true
  ip6tables -t nat -D PREROUTING -i "$IFACE" -p udp --dport 10000:65000 -j DNAT --to-destination ":$LPORT" 2>/dev/null || true

  # Short-range DNAT similar to zivpn
  iptables -t nat -C PREROUTING -i "$IFACE" -p udp --dport 12000:12999 -j DNAT --to-destination ":$LPORT" 2>/dev/null \
    || iptables -t nat -A PREROUTING -i "$IFACE" -p udp --dport 12000:12999 -j DNAT --to-destination ":$LPORT"

  # Open firewall if ufw exists (optional)
  if command -v ufw >/dev/null 2>&1; then
    ufw allow 12000:12999/udp || true
    ufw allow "$LPORT"/udp || true
  fi

  # Relax rp_filter only on the default iface (not global)
  sysctl "net.ipv4.conf.$IFACE.rp_filter=0"

  # Optional: skip conntrack for hysteria port (set USE_NOTRACK=1 when running)
  if [[ "$USE_NOTRACK" == "1" ]]; then
    iptables -t raw -C PREROUTING -p udp --dport "$LPORT" -j NOTRACK 2>/dev/null || \
      iptables -t raw -A PREROUTING -p udp --dport "$LPORT" -j NOTRACK
    iptables -t raw -C OUTPUT -p udp --sport "$LPORT" -j NOTRACK 2>/dev/null || \
      iptables -t raw -A OUTPUT -p udp --sport "$LPORT" -j NOTRACK
  fi

  # Start service
  systemctl restart hysteria-server.service
  echo "AGN-UDP started on UDP :$LPORT (DNAT 12000:12999 → :$LPORT)"
}

# ===== Orchestration =====
perform_install(){
  local fresh=""
  if ! is_hysteria_installed; then fresh=1; fi

  perform_install_hysteria_binary
  perform_install_hysteria_example_config
  perform_install_hysteria_home_legacy
  perform_install_hysteria_systemd
  setup_ssl
  start_services
  perform_install_manager_script

  if [[ -n "$fresh" ]]; then
    echo
    echo -e "$(tbold)JUE-UDP installed successfully.$(treset)"
    echo "Use 'jueudp' to open manager."
  else
    restart_running_services
    start_services
    echo
    echo -e "$(tbold)JUE-UDP updated.$(treset)"
  fi
}

perform_remove(){
  perform_remove_hysteria_binary
  stop_running_services
  perform_remove_hysteria_systemd
  echo
  echo -e "$(tbold)AGN-UDP removed.$(treset)"
  echo -e "Remove configs manually: $(tred)rm -rf $CONFIG_DIR$(treset)"
}

main(){
  parse_arguments "$@"
  check_permission
  check_environment
  check_hysteria_user "hysteria"
  check_hysteria_homedir "/var/lib/$HYSTERIA_USER"
  case "$OPERATION" in
    install) setup_db; perform_install;;
    remove) perform_remove;;
    *) error "Unknown operation '$OPERATION'.";;
  esac
}
main "$@"
