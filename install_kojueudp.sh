#!/usr/bin/env bash
# Try `install_jueudp.sh --help` for usage.
# (c) 2023 Jue Htet  —  updated for Hysteria v2 + stats + http://IP:81/server/online

set -e

# ---- Defaults (can override by env or flags) ----
DOMAIN="${DOMAIN:-eg.jueudp.com}"
PROTOCOL="${PROTOCOL:-udp}"
UDP_PORT="${UDP_PORT:-:36712}"
OBFS="${OBFS:-jaideevpn}"
PASSWORD="${PASSWORD:-jaideevpn}"

UP_MBPS="${UP_MBPS:-100}"
DOWN_MBPS="${DOWN_MBPS:-100}"

ENABLE_STATS="${ENABLE_STATS:-1}"
STATS_LISTEN="${STATS_LISTEN:-127.0.0.1:9999}"
STATS_SECRET="${STATS_SECRET:-}"           # auto-generate if empty

PUBLISH_81="${PUBLISH_81:-0}"              # 1 by --publish-81, 0 by default

# ---- Paths ----
SCRIPT_NAME="$(basename "$0")"
SCRIPT_ARGS=("$@")
EXECUTABLE_INSTALL_PATH="/usr/local/bin/hysteria"
SYSTEMD_SERVICES_DIR="/etc/systemd/system"
CONFIG_DIR="/etc/hysteria"
USER_DB="$CONFIG_DIR/udpusers.db"
REPO_URL="https://github.com/apernet/hysteria"
CONFIG_FILE="$CONFIG_DIR/config.json"
SYSTEMD_SERVICE="$SYSTEMD_SERVICES_DIR/hysteria-server.service"
CURL_FLAGS=(-L -f -q --retry 5 --retry-delay 10 --retry-max-time 60)

mkdir -p "$CONFIG_DIR"; touch "$USER_DB"

# ---- Others ----
OPERATING_SYSTEM=""
ARCHITECTURE=""
HYSTERIA_USER=""
HYSTERIA_HOME_DIR=""
VERSION=""
FORCE=""
LOCAL_FILE=""
FORCE_NO_ROOT=""
FORCE_NO_SYSTEMD=""
OPERATION=""

# ------------ Utils ------------
has_command(){ type -P "$1" >/dev/null 2>&1; }
curl(){ command curl "${CURL_FLAGS[@]}" "$@"; }
mktemp(){ command mktemp "$@" "hyservinst.XXXXXXXXXX"; }
tput(){ if has_command tput; then command tput "$@"; fi; }
tred(){ tput setaf 1; }
tyellow(){ tput setaf 3; }
tblue(){ tput setaf 4; }
tbold(){ tput bold; }
treset(){ tput sgr0; }
note(){ echo -e "$SCRIPT_NAME: $(tbold)note: $1$(treset)"; }
warning(){ echo -e "$SCRIPT_NAME: $(tyellow)warning: $1$(treset)"; }
error(){ echo -e "$SCRIPT_NAME: $(tred)error: $1$(treset)"; }
show_argument_error_and_exit(){ error "$1"; echo "Try \"$0 --help\""; exit 22; }

random_secret(){ head -c 32 /dev/urandom | base64 | tr -d '\n/+='; }

install_content(){
  local f="$1" c="$2" d="$3" tmp="$(mktemp)"
  echo -ne "Install $d ... "
  echo "$c" > "$tmp"
  if install "$f" "$tmp" "$d"; then echo "ok"; fi
  rm -f "$tmp"
}
remove_file(){ local t="$1"; echo -ne "Remove $t ... "; if rm -f "$t"; then echo "ok"; fi; }

exec_sudo(){
  local _saved="$IFS"; IFS=$'\n'
  local _preserved=(
    $(env | grep "^OPERATING_SYSTEM=" || true)
    $(env | grep "^ARCHITECTURE=" || true)
    $(env | grep "^DOMAIN=" || true)
    $(env | grep "^UDP_PORT=" || true)
    $(env | grep "^OBFS=" || true)
    $(env | grep "^PASSWORD=" || true)
    $(env | grep "^UP_MBPS=" || true)
    $(env | grep "^DOWN_MBPS=" || true)
    $(env | grep "^ENABLE_STATS=" || true)
    $(env | grep "^STATS_LISTEN=" || true)
    $(env | grep "^STATS_SECRET=" || true)
    $(env | grep "^PUBLISH_81=" || true)
  ); IFS="$_saved"
  exec sudo env "${_preserved[@]}" "$@"
}

install_software(){
  local p="$1"
  if has_command apt-get; then apt-get update -y && apt-get install -y "$p"
  elif has_command dnf; then dnf install -y "$p"
  elif has_command yum; then yum install -y "$p"
  elif has_command zypper; then zypper install -y "$p"
  elif has_command pacman; then pacman -Sy --noconfirm "$p"
  else echo "No supported package manager for $p"; exit 1
  fi
}

is_user_exists(){ id "$1" >/dev/null 2>&1; }

check_permission(){
  if [[ "$UID" -eq 0 ]]; then return; fi
  note "Re-running with sudo..."
  if has_command sudo; then exec_sudo "$0" "${SCRIPT_ARGS[@]}"; else error "Need root"; exit 13; fi
}

check_environment_operating_system(){
  [[ -n "$OPERATING_SYSTEM" ]] && return
  [[ "x$(uname)" == "xLinux" ]] && { OPERATING_SYSTEM=linux; return; }
  error "Linux only"; exit 95
}

check_environment_architecture(){
  [[ -n "$ARCHITECTURE" ]] && return
  case "$(uname -m)" in
    i386|i686) ARCHITECTURE='386';;
    amd64|x86_64) ARCHITECTURE='amd64';;
    armv7|armv7l|armv6l|armv5tel) ARCHITECTURE='arm';;
    aarch64|armv8) ARCHITECTURE='arm64';;
    s390x) ARCHITECTURE='s390x';;
    *) error "Unsupported arch $(uname -m)"; exit 8;;
  esac
}

check_environment_systemd(){
  if [[ -d /run/systemd/system ]] || grep -q systemd <(ls -l /sbin/init); then return; fi
  error "Need systemd"; exit 1
}

parse_arguments(){
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --remove) OPERATION=remove;;
      --version) VERSION="$2"; shift;;
      -h|--help) show_usage_and_exit;;
      -l|--local) LOCAL_FILE="$2"; shift;;
      --stats-port) STATS_LISTEN="127.0.0.1:${2##*:}"; shift;;
      --stats-secret) STATS_SECRET="$2"; shift;;
      --publish-81) PUBLISH_81=1;;
      --unpublish-81) PUBLISH_81=2;;
      *) show_argument_error_and_exit "Unknown option $1";;
    esac; shift
  done
  [[ -n "$OPERATION" ]] || OPERATION=install
  if [[ "$OPERATION" != install ]]; then
    [[ -z "$VERSION" && -z "$LOCAL_FILE" ]] || show_argument_error_and_exit "version/local only for install"
  fi
}

check_hysteria_homedir(){
  local _default="$1"
  if [[ -n "$HYSTERIA_HOME_DIR" ]]; then return; fi
  if ! is_user_exists "$HYSTERIA_USER"; then HYSTERIA_HOME_DIR="$_default"; return; fi
  HYSTERIA_HOME_DIR="$(eval echo ~"$HYSTERIA_USER")"
}

# -------- v2 downloader --------
download_hysteria(){
  local _version="$1" _dest="$2" _arch
  case "$ARCHITECTURE" in
    amd64) _arch="amd64";;
    arm64) _arch="arm64";;
    386)   _arch="386";;
    arm)   _arch="armv7";;
    s390x) _arch="s390x";;
    *) error "Unsupported arch"; return 8;;
  esac
  local file="hysteria-linux-$_arch"
  local url
  if [[ -n "$_version" ]]; then url="$REPO_URL/releases/download/$_version/$file"
  else url="$REPO_URL/releases/latest/download/$file"; fi
  echo "Downloading hysteria: $url"
  curl -R -H 'Cache-Control: no-cache' "$url" -o "$_dest" || return 11
}

check_hysteria_user(){
  local _default="$1"
  if [[ -n "$HYSTERIA_USER" ]]; then return; fi
  if [[ ! -e "$SYSTEMD_SERVICES_DIR/hysteria-server.service" ]]; then HYSTERIA_USER="$_default"; return; fi
  HYSTERIA_USER="$(grep -o '^User=\w*' "$SYSTEMD_SERVICES_DIR/hysteria-server.service" | tail -1 | cut -d= -f2 || true)"
  [[ -n "$HYSTERIA_USER" ]] || HYSTERIA_USER="$_default"
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
  cat <<EOF

$(tbold)$SCRIPT_NAME$(treset) - AGN-UDP (Hysteria v2) installer

Install:
  $0 [--version vX.Y.Z] [--stats-port 9999] [--stats-secret SECRET] [--publish-81|--unpublish-81]

  --publish-81     Publish http://IP:81/server/online (via Nginx proxy)
  --unpublish-81   Remove the port 81 mapping

Remove:
  $0 --remove

EOF
  exit 0
}

tpl_hysteria_server_service_base(){
  cat << EOF
[Unit]
Description=AGN-UDP Service (Hysteria v2)
After=network.target

[Service]
User=root
Group=root
WorkingDirectory=/etc/hysteria
Environment="PATH=/usr/local/bin/hysteria"
ExecStart=/usr/local/bin/hysteria server --config /etc/hysteria/config.json
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
}
tpl_hysteria_server_service(){ tpl_hysteria_server_service_base 'config'; }
tpl_hysteria_server_x_service(){ tpl_hysteria_server_service_base '%i'; }

# -------- DB --------
setup_db(){
  echo "Setting up database"
  mkdir -p "$(dirname "$USER_DB")"
  if [[ ! -f "$USER_DB" ]]; then sqlite3 "$USER_DB" ".databases" || { echo "DB create failed"; exit 1; }; fi
  sqlite3 "$USER_DB" <<'EOF'
CREATE TABLE IF NOT EXISTS users (
  username TEXT PRIMARY KEY,
  password TEXT NOT NULL
);
EOF
  local default_username="default" default_password="password"
  local exists; exists=$(sqlite3 "$USER_DB" "SELECT username FROM users WHERE username='$default_username';")
  if [[ -z "$exists" ]]; then
    sqlite3 "$USER_DB" "INSERT INTO users(username,password) VALUES('$default_username','$default_password');" || true
  fi
  echo "DB ready."
}

fetch_users(){
  local DB_PATH="$USER_DB"
  [[ -f "$DB_PATH" ]] && sqlite3 "$DB_PATH" "SELECT username || ':' || password FROM users;" | paste -sd, -
}

# -------- v2 config + trafficStats --------
tpl_etc_hysteria_config_json(){
  local_users=$(fetch_users || true)
  mkdir -p "$CONFIG_DIR"

  [[ -n "$STATS_SECRET" ]] || STATS_SECRET="$(random_secret)"

  local users_json="[]"
  if [[ -n "$local_users" ]]; then
    users_json=$(echo "$local_users" | awk -F, 'BEGIN{printf "["}{for(i=1;i<=NF;i++){split($i,a,":");printf "{\"username\":\"%s\",\"password\":\"%s\"}%s",a[1],a[2],(i<NF?",":"")}}END{printf "]"}')
  fi

  {
    echo "{"
    echo "  \"server\": \"$DOMAIN\","
    echo "  \"listen\": \"$UDP_PORT\","
    echo "  \"protocol\": \"$PROTOCOL\","
    echo "  \"cert\": \"/etc/hysteria/hysteria.server.crt\","
    echo "  \"key\": \"/etc/hysteria/hysteria.server.key\","
    echo "  \"obfs\": \"$OBFS\","
    echo "  \"bandwidth\": { \"up\": \"${UP_MBPS} mbps\", \"down\": \"${DOWN_MBPS} mbps\" },"
    echo "  \"auth\": {"
    echo "    \"type\": \"userpass\","
    echo "    \"userpass\": {"
    echo "      \"users\": $users_json,"
    echo "      \"default\": \"$PASSWORD\""
    echo "    }"
    echo "  }"
    if [[ "$ENABLE_STATS" == "1" ]]; then
      echo "  ,\"trafficStats\": {"
      echo "      \"listen\": \"$STATS_LISTEN\","
      echo "      \"secret\": \"$STATS_SECRET\""
      echo "    }"
    fi
    echo "}"
  } > "$CONFIG_FILE"
  echo "Wrote $CONFIG_FILE"
}

# -------- Install binary (v2) --------
perform_install_hysteria_binary(){
  if [[ -n "$LOCAL_FILE" ]]; then
    echo -ne "Installing hysteria executable ... "
    install -Dm755 "$LOCAL_FILE" "$EXECUTABLE_INSTALL_PATH" && echo "ok" || exit 2
    return
  fi
  local _tmp=$(mktemp)
  if ! download_hysteria "$VERSION" "$_tmp"; then rm -f "$_tmp"; exit 11; fi
  echo -ne "Installing hysteria executable ... "
  install -Dm755 "$_tmp" "$EXECUTABLE_INSTALL_PATH" && echo "ok" || exit 13
  rm -f "$_tmp"
}

perform_remove_hysteria_binary(){ remove_file "$EXECUTABLE_INSTALL_PATH"; }

perform_install_hysteria_example_config(){ tpl_etc_hysteria_config_json; }

perform_install_hysteria_systemd(){
  install_content -Dm644 "$(tpl_hysteria_server_service)" "$SYSTEMD_SERVICES_DIR/hysteria-server.service"
  install_content -Dm644 "$(tpl_hysteria_server_x_service)" "$SYSTEMD_SERVICES_DIR/hysteria-server@.service"
  systemctl daemon-reload
}

perform_remove_hysteria_systemd(){
  remove_file "$SYSTEMD_SERVICES_DIR/hysteria-server.service"
  remove_file "$SYSTEMD_SERVICES_DIR/hysteria-server@.service"
  systemctl daemon-reload
}

is_hysteria_installed(){ [[ -f "$EXECUTABLE_INSTALL_PATH" || -h "$EXECUTABLE_INSTALL_PATH" ]]; }

get_iface(){ ip -4 route ls | awk '/default/ {print $5; exit}'; }

start_services(){
  echo "Starting AGN-UDP"
  apt-get update -y || true
  debconf-set-selections <<< "iptables-persistent iptables-persistent/autosave_v4 boolean true" || true
  debconf-set-selections <<< "iptables-persistent iptables-persistent/autosave_v6 boolean true" || true
  apt-get -y install iptables-persistent || true

  local IFACE; IFACE="$(get_iface)"
  iptables -t nat -C PREROUTING -i "$IFACE" -p udp --dport 10000:65000 -j DNAT --to-destination "$UDP_PORT" 2>/dev/null || \
  iptables -t nat -A PREROUTING -i "$IFACE" -p udp --dport 10000:65000 -j DNAT --to-destination "$UDP_PORT" || true
  ip6tables -t nat -C PREROUTING -i "$IFACE" -p udp --dport 10000:65000 -j DNAT --to-destination "$UDP_PORT" 2>/dev/null || \
  ip6tables -t nat -A PREROUTING -i "$IFACE" -p udp --dport 10000:65000 -j DNAT --to-destination "$UDP_PORT" || true

  sysctl net.ipv4.conf.all.rp_filter=0 || true
  sysctl "net.ipv4.conf.$IFACE.rp_filter=0" || true
  cat > /etc/sysctl.conf <<EOF
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.$IFACE.rp_filter=0
EOF
  sysctl -p || true

  iptables-save > /etc/iptables/rules.v4 || true
  ip6tables-save > /etc/iptables/rules.v6 || true

  systemctl enable hysteria-server.service
  systemctl restart hysteria-server.service
}

# -------- Publish http://IP:81/server/online --------
publish_port81(){
  # Requires nginx + jq
  has_command jq || install_software jq
  has_command nginx || install_software nginx

  local SITE="/etc/nginx/conf.d/jue-online-81.conf"
  local PORT SECRET
  PORT="$(jq -r '.trafficStats.listen' "$CONFIG_FILE" | awk -F: '{print $NF}')"
  SECRET="$(jq -r '.trafficStats.secret' "$CONFIG_FILE")"
  if [[ -z "$PORT" || "$PORT" == "null" || -z "$SECRET" || "$SECRET" == "null" ]]; then
    error "trafficStats not enabled in $CONFIG_FILE"; exit 1
  fi

  cat > "$SITE" <<EOF
# auto-generated
server {
    listen 81 default_server;
    server_name _;

    location /server/ {
        proxy_set_header Authorization "${SECRET}";
        proxy_pass http://127.0.0.1:${PORT}/;
        proxy_http_version 1.1;
        proxy_read_timeout 5s;
        add_header Cache-Control "no-store";
    }
}
EOF

  # Open firewall for 81 (best effort)
  if has_command ufw; then ufw allow 81/tcp || true; fi
  if has_command firewall-cmd; then firewall-cmd --add-port=81/tcp --permanent || true; firewall-cmd --reload || true; fi

  nginx -t
  systemctl reload nginx || systemctl restart nginx

  local PUBIP
  PUBIP="$(curl -s http://ifconfig.me || curl -s http://api.ipify.org || hostname -I | awk '{print $1}')"
  echo
  echo -e "$(tbold)Online Users URL:$(treset) $(tblue)http://${PUBIP}:81/server/online$(treset)"
  echo "Tip: Add IP allowlist later for extra security."
}

unpublish_port81(){
  local SITE="/etc/nginx/conf.d/jue-online-81.conf"
  rm -f "$SITE"
  if has_command nginx; then nginx -t && systemctl reload nginx || true; fi
  echo "Port 81 mapping removed."
}

# -------- Main flows --------
perform_install(){
  local fresh=""
  if ! is_hysteria_installed; then fresh=1; fi

  [[ -n "$STATS_SECRET" || "$ENABLE_STATS" != "1" ]] || STATS_SECRET="$(random_secret)"

  perform_install_hysteria_binary
  tpl_etc_hysteria_config_json
  perform_install_hysteria_systemd
  setup_ssl
  start_services

  if [[ "$PUBLISH_81" -eq 1 ]]; then publish_port81; fi
  if [[ "$PUBLISH_81" -eq 2 ]]; then unpublish_port81; fi

  echo
  echo -e "$(tbold)✅ Hysteria v2 installed.$(treset)"
  if [[ "$ENABLE_STATS" == "1" ]]; then
    echo -e "Stats test (server shell):  curl -H 'Authorization: ${STATS_SECRET}' http://127.0.0.1:${STATS_LISTEN##*:}/online"
  fi
  if [[ "$PUBLISH_81" -eq 1 ]]; then
    echo -e "Open:  http://<YOUR_IP>:81/server/online"
  fi
  echo
}

perform_remove(){
  perform_remove_hysteria_binary
  systemctl stop hysteria-server.service || true
  perform_remove_hysteria_systemd
  echo
  echo -e "$(tbold)Removed. Config kept at $CONFIG_DIR$(treset)"
  echo
}

setup_ssl(){
  echo "Installing SSL certificates"
  openssl genrsa -out /etc/hysteria/hysteria.ca.key 2048
  openssl req -new -x509 -days 3650 -key /etc/hysteria/hysteria.ca.key -subj "/C=CN/ST=GD/L=SZ/O=Hysteria, Inc./CN=Hysteria Root CA" -out /etc/hysteria/hysteria.ca.crt
  openssl req -newkey rsa:2048 -nodes -keyout /etc/hysteria/hysteria.server.key -subj "/C=CN/ST=GD/L=SZ/O=Hysteria, Inc./CN=$DOMAIN" -out /etc/hysteria/hysteria.server.csr
  openssl x509 -req -extfile <(printf "subjectAltName=DNS:$DOMAIN,DNS:$DOMAIN") -days 3650 -in /etc/hysteria/hysteria.server.csr -CA /etc/hysteria/hysteria.ca.crt -CAkey /etc/hysteria/hysteria.ca.key -CAcreateserial -out /etc/hysteria/hysteria.server.crt
}

main(){
  parse_arguments "$@"
  check_permission
  check_environment
  check_hysteria_user "hysteria"
  check_hysteria_homedir "/var/lib/$HYSTERIA_USER"

  case "$OPERATION" in
    install)
      setup_db
      perform_install
      ;;
    remove)
      perform_remove
      ;;
    *)
      error "Unknown operation '$OPERATION'."
      ;;
  esac
}

main "$@"
