#!/usr/bin/env bash
# Try `install_jueudp.sh --help` for usage.
# (c) 2023 Jue Htet — updated for Hysteria v2 + stats + mini web panel

set -e

# -----------------------------
# Defaults (can be overridden via env or CLI flags)
# -----------------------------
DOMAIN="${DOMAIN:-eg.jueudp.com}"
PROTOCOL="${PROTOCOL:-udp}"
UDP_PORT="${UDP_PORT:-:36712}"
OBFS="${OBFS:-jaideevpn}"
PASSWORD="${PASSWORD:-jaideevpn}"

UP_MBPS="${UP_MBPS:-100}"
DOWN_MBPS="${DOWN_MBPS:-100}"

ENABLE_STATS="${ENABLE_STATS:-1}"               # 1=enable trafficStats block in config
STATS_LISTEN="${STATS_LISTEN:-127.0.0.1:9999}"  # where hysteria exposes /online
STATS_SECRET="${STATS_SECRET:-}"                # will be generated if empty

INSTALL_PANEL="${INSTALL_PANEL:-1}"             # 1=install mini-fastapi panel
PANEL_PORT="${PANEL_PORT:-9000}"                # internal listen (127.0.0.1)

# -----------------------------
# Paths
# -----------------------------
SCRIPT_NAME="$(basename "$0")"
SCRIPT_ARGS=("$@")
EXECUTABLE_INSTALL_PATH="/usr/local/bin/hysteria"
SYSTEMD_SERVICES_DIR="/etc/systemd/system"
CONFIG_DIR="/etc/hysteria"
USER_DB="$CONFIG_DIR/udpusers.db"
REPO_URL="https://github.com/apernet/hysteria"
CONFIG_FILE="$CONFIG_DIR/config.json"

CURL_FLAGS=(-L -f -q --retry 5 --retry-delay 10 --retry-max-time 60)
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
OPERATION=""

# -----------------------------
# Utils
# -----------------------------
has_command(){ type -P "$1" >/dev/null 2>&1; }
curl(){ command curl "${CURL_FLAGS[@]}" "$@"; }
mktemp(){ command mktemp "$@" "hyservinst.XXXXXXXXXX"; }
tput(){ if has_command tput; then command tput "$@"; fi; }
tred(){ tput setaf 1; }
tgreen(){ tput setaf 2; }
tyellow(){ tput setaf 3; }
tblue(){ tput setaf 4; }
tbold(){ tput bold; }
treset(){ tput sgr0; }
note(){ echo -e "$SCRIPT_NAME: $(tbold)note: $1$(treset)"; }
warning(){ echo -e "$SCRIPT_NAME: $(tyellow)warning: $1$(treset)"; }
error(){ echo -e "$SCRIPT_NAME: $(tred)error: $1$(treset)"; }

random_secret(){
  # 32 bytes base64 w/out non-url chars
  head -c 32 /dev/urandom | base64 | tr -d '\n/+='
}

show_argument_error_and_exit(){
  error "$1"; echo "Try \"$0 --help\" for the usage." >&2; exit 22;
}

install_content(){
  local _install_flags="$1" _content="$2" _destination="$3"
  local _tmpfile="$(mktemp)"
  echo -ne "Install $_destination ... "
  echo "$_content" > "$_tmpfile"
  if install "$_install_flags" "$_tmpfile" "$_destination"; then echo -e "ok"; fi
  rm -f "$_tmpfile"
}
remove_file(){ local _t="$1"; echo -ne "Remove $_t ... "; if rm "$_t"; then echo "ok"; fi; }

exec_sudo(){
  local _saved="$IFS"; IFS=$'\n'
  local _preserved=(
    $(env | grep "^PACKAGE_MANAGEMENT_INSTALL=" || true)
    $(env | grep "^OPERATING_SYSTEM=" || true)
    $(env | grep "^ARCHITECTURE=" || true)
    $(env | grep "^HYSTERIA_\w*=" || true)
    $(env | grep "^FORCE_\w*=" || true)
    $(env | grep "^DOMAIN=" || true)
    $(env | grep "^UDP_PORT=" || true)
    $(env | grep "^OBFS=" || true)
    $(env | grep "^PASSWORD=" || true)
    $(env | grep "^UP_MBPS=" || true)
    $(env | grep "^DOWN_MBPS=" || true)
    $(env | grep "^ENABLE_STATS=" || true)
    $(env | grep "^STATS_LISTEN=" || true)
    $(env | grep "^STATS_SECRET=" || true)
    $(env | grep "^INSTALL_PANEL=" || true)
    $(env | grep "^PANEL_PORT=" || true)
  )
  IFS="$_saved"
  exec sudo env "${_preserved[@]}" "$@"
}

install_software(){
  local p="$1"
  if has_command apt-get; then apt-get update && apt-get install -y "$p"
  elif has_command dnf; then dnf install -y "$p"
  elif has_command yum; then yum install -y "$p"
  elif has_command zypper; then zypper install -y "$p"
  elif has_command pacman; then pacman -Sy --noconfirm "$p"
  else echo "No supported package manager. Install $p manually."; exit 1
  fi
}

is_user_exists(){ id "$1" >/dev/null 2>&1; }

check_permission(){
  if [[ "$UID" -eq 0 ]]; then return; fi
  note "Not running as root."
  case "$FORCE_NO_ROOT" in
    1) warning "FORCE_NO_ROOT=1 set; continuing w/o root (may fail).";;
    *) if has_command sudo; then
         note "Re-running via sudo..."
         exec_sudo "$0" "${SCRIPT_ARGS[@]}"
       else
         error "Run as root or set FORCE_NO_ROOT=1"
         exit 13
       fi;;
  esac
}

check_environment_operating_system(){
  if [[ -n "$OPERATING_SYSTEM" ]]; then
    warning "OPERATING_SYSTEM=$OPERATING_SYSTEM specified; skipping detection."
    return
  fi
  if [[ "x$(uname)" == "xLinux" ]]; then OPERATING_SYSTEM=linux; return; fi
  error "This script only supports Linux."; exit 95
}

check_environment_architecture(){
  if [[ -n "$ARCHITECTURE" ]]; then
    warning "ARCHITECTURE=$ARCHITECTURE specified; skipping detection."
    return
  fi
  case "$(uname -m)" in
    i386|i686) ARCHITECTURE='386';;
    amd64|x86_64) ARCHITECTURE='amd64';;
    armv5tel|armv6l|armv7|armv7l) ARCHITECTURE='arm';;
    armv8|aarch64) ARCHITECTURE='arm64';;
    s390x) ARCHITECTURE='s390x';;
    *) error "Unsupported arch: $(uname -a)"; exit 8;;
  esac
}

check_environment_systemd(){
  if [[ -d "/run/systemd/system" ]] || grep -q systemd <(ls -l /sbin/init); then return; fi
  case "$FORCE_NO_SYSTEMD" in
    1) warning "FORCE_NO_SYSTEMD=1; will proceed."; ;;
    2) warning "FORCE_NO_SYSTEMD=2; will skip systemd commands."; ;;
    *) error "This script requires systemd."; exit 1;;
  esac
}

parse_arguments(){
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --remove) OPERATION='remove';;
      --version) VERSION="$2"; shift; [[ -n "$VERSION" ]] || show_argument_error_and_exit "missing version";;
      -h|--help) show_usage_and_exit;;
      -l|--local) LOCAL_FILE="$2"; shift;;
      --enable-stats) ENABLE_STATS=1;;
      --disable-stats) ENABLE_STATS=0;;
      --stats-port) STATS_LISTEN="127.0.0.1:${2##*:}"; shift;;
      --stats-secret) STATS_SECRET="$2"; shift;;
      --install-panel) INSTALL_PANEL=1;;
      --no-panel) INSTALL_PANEL=0;;
      --panel-port) PANEL_PORT="$2"; shift;;
      *) show_argument_error_and_exit "Unknown option '$1'";;
    esac
    shift
  done
  [[ -n "$OPERATION" ]] || OPERATION='install'
  case "$OPERATION" in
    install)
      if [[ -n "$VERSION" && -n "$LOCAL_FILE" ]]; then
        show_argument_error_and_exit '--version and --local cannot be used together.'
      fi
      ;;
    *)
      [[ -z "$VERSION" ]] || show_argument_error_and_exit "--version only valid with install."
      [[ -z "$LOCAL_FILE" ]] || show_argument_error_and_exit "--local only valid with install."
      ;;
  esac
}

check_hysteria_homedir(){
  local _default="$1"
  if [[ -n "$HYSTERIA_HOME_DIR" ]]; then return; fi
  if ! is_user_exists "$HYSTERIA_USER"; then HYSTERIA_HOME_DIR="$_default"; return; fi
  HYSTERIA_HOME_DIR="$(eval echo ~"$HYSTERIA_USER")"
}

# -----------------------------
# Hysteria v2 downloader
# -----------------------------
download_hysteria(){
  local _version="$1" _dest="$2"
  # map to v2 artifact names
  local _arch_map
  case "$ARCHITECTURE" in
    amd64) _arch_map="amd64";;
    arm64) _arch_map="arm64";;
    386)   _arch_map="386";;
    arm)   _arch_map="armv7";;
    s390x) _arch_map="s390x";;
    *) error "Unsupported arch for v2: $ARCHITECTURE"; return 8;;
  esac
  local _file="hysteria-linux-$_arch_map"
  local _url
  if [[ -n "$_version" ]]; then
    _url="$REPO_URL/releases/download/$_version/$_file"
  else
    _url="$REPO_URL/releases/latest/download/$_file"
  fi
  echo "Downloading hysteria binary: $_url ..."
  if ! curl -R -H 'Cache-Control: no-cache' "$_url" -o "$_dest"; then
    error "Download failed"; return 11
  fi
  return 0
}

check_hysteria_user(){
  local _default="$1"
  if [[ -n "$HYSTERIA_USER" ]]; then return; fi
  if [[ ! -e "$SYSTEMD_SERVICES_DIR/hysteria-server.service" ]]; then HYSTERIA_USER="$_default"; return; fi
  HYSTERIA_USER="$(grep -o '^User=\w*' "$SYSTEMD_SERVICES_DIR/hysteria-server.service" | tail -1 | cut -d '=' -f 2 || true)"
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

  $(tbold)$SCRIPT_NAME$(treset) - JUE-UDP (Hysteria v2) installer with real-time stats & mini panel

  Usage:
    $0 [options]

  Install options:
    -l, --local <file>       Install specified hysteria binary instead of downloading
        --version <vX.Y.Z>   Install specific hysteria release (v2.x recommended)
        --enable-stats       Enable Traffic Stats API (default: enabled)
        --disable-stats      Disable Traffic Stats API
        --stats-port <p>     Stats listen port on 127.0.0.1 (default: 9999)
        --stats-secret <s>   Secret for Authorization header (default: auto-generate)
        --install-panel      Install mini web panel (default: on)
        --no-panel           Do not install panel
        --panel-port <p>     Panel listen on 127.0.0.1:<p> (default: 9000)

  Remove:
        --remove

  Examples:
    sudo $0 --enable-stats --stats-secret "My$uper$ecret" --install-panel --panel-port 9000

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

# -----------------------------
# DB & users
# -----------------------------
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
  # default user (can be removed later)
  local default_username="default" default_password="password"
  local exists; exists=$(sqlite3 "$USER_DB" "SELECT username FROM users WHERE username='$default_username';")
  if [[ -z "$exists" ]]; then
    sqlite3 "$USER_DB" "INSERT INTO users(username,password) VALUES('$default_username','$default_password');" || true
  fi
  echo "DB ready."
}

fetch_users(){
  local DB_PATH="$USER_DB"
  if [[ -f "$DB_PATH" ]]; then
    # returns "u1:p1,u2:p2"
    sqlite3 "$DB_PATH" "SELECT username || ':' || password FROM users;" | paste -sd, -
  fi
}

# -----------------------------
# v2 config writer (with optional trafficStats)
# -----------------------------
tpl_etc_hysteria_config_json(){
  local_users=$(fetch_users)
  mkdir -p "$CONFIG_DIR"

  [[ -n "$STATS_SECRET" ]] || STATS_SECRET="$(random_secret)"

  # make JSON array of {"username":"x","password":"y"} from "u:p,u2:p2"
  local users_json
  if [[ -n "$local_users" ]]; then
    users_json=$(echo "$local_users" | awk -F, '{
      printf "[";
      for (i=1;i<=NF;i++){
        split($i,a,":");
        printf "{\"username\":\"%s\",\"password\":\"%s\"}%s", a[1], a[2], (i<NF?",":"")
      }
      printf "]";
    }')
  else
    users_json="[]"
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

perform_install_hysteria_binary(){
  if [[ -n "$LOCAL_FILE" ]]; then
    note "Local install: $LOCAL_FILE"
    echo -ne "Installing hysteria executable ... "
    if install -Dm755 "$LOCAL_FILE" "$EXECUTABLE_INSTALL_PATH"; then echo "ok"; else exit 2; fi
    return
  fi
  local _tmp=$(mktemp)
  if ! download_hysteria "$VERSION" "$_tmp"; then rm -f "$_tmp"; exit 11; fi
  echo -ne "Installing hysteria executable ... "
  if install -Dm755 "$_tmp" "$EXECUTABLE_INSTALL_PATH"; then echo "ok"; else exit 13; fi
  rm -f "$_tmp"
}

perform_remove_hysteria_binary(){ remove_file "$EXECUTABLE_INSTALL_PATH"; }

perform_install_hysteria_example_config(){ tpl_etc_hysteria_config_json; }

perform_install_hysteria_systemd(){
  if [[ "x$FORCE_NO_SYSTEMD" == "x2" ]]; then return; fi
  install_content -Dm644 "$(tpl_hysteria_server_service)" "$SYSTEMD_SERVICES_DIR/hysteria-server.service"
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
    useradd -r -d "$HYSTERIA_HOME_DIR" -m "$HYSTERIA_USER" || true
    echo "ok"
  fi
}

perform_install_manager_script(){
  local _manager_script="/usr/local/bin/jueudp_manager.sh"
  local _symlink_path="/usr/local/bin/jueudp"
  echo "Downloading manager script..."
  curl -o "$_manager_script" "https://raw.githubusercontent.com/Juessh/Juevpnscript/main/jueudp_manager.sh"
  chmod +x "$_manager_script"
  ln -sf "$_manager_script" "$_symlink_path"
  echo "Manager script installed. Use 'jueudp' command."
}

is_hysteria_installed(){ [[ -f "$EXECUTABLE_INSTALL_PATH" || -h "$EXECUTABLE_INSTALL_PATH" ]]; }

get_running_services(){
  if [[ "x$FORCE_NO_SYSTEMD" == "x2" ]]; then return; fi
  systemctl list-units --state=active --plain --no-legend | grep -o "hysteria-server@*[^\s]*.service" || true
}

restart_running_services(){
  if [[ "x$FORCE_NO_SYSTEMD" == "x2" ]]; then return; fi
  echo "Restarting running service ..."
  for s in $(get_running_services); do
    echo -ne "Restarting $s ... "
    systemctl restart "$s"
    echo "done"
  done
}

stop_running_services(){
  if [[ "x$FORCE_NO_SYSTEMD" == "x2" ]]; then return; fi
  echo "Stopping running service ..."
  for s in $(get_running_services); do
    echo -ne "Stopping $s ... "
    systemctl stop "$s"
    echo "done"
  done
}

setup_ssl(){
  echo "Installing SSL certificates"
  openssl genrsa -out /etc/hysteria/hysteria.ca.key 2048
  openssl req -new -x509 -days 3650 -key /etc/hysteria/hysteria.ca.key -subj "/C=CN/ST=GD/L=SZ/O=Hysteria, Inc./CN=Hysteria Root CA" -out /etc/hysteria/hysteria.ca.crt
  openssl req -newkey rsa:2048 -nodes -keyout /etc/hysteria/hysteria.server.key -subj "/C=CN/ST=GD/L=SZ/O=Hysteria, Inc./CN=$DOMAIN" -out /etc/hysteria/hysteria.server.csr
  openssl x509 -req -extfile <(printf "subjectAltName=DNS:$DOMAIN,DNS:$DOMAIN") -days 3650 -in /etc/hysteria/hysteria.server.csr -CA /etc/hysteria/hysteria.ca.crt -CAkey /etc/hysteria/hysteria.ca.key -CAcreateserial -out /etc/hysteria/hysteria.server.crt
}

start_services(){
  echo "Starting AGN-UDP"
  apt update || true
  sudo debconf-set-selections <<< "iptables-persistent iptables-persistent/autosave_v4 boolean true" || true
  sudo debconf-set-selections <<< "iptables-persistent iptables-persistent/autosave_v6 boolean true" || true
  apt -y install iptables-persistent || true

  local IFACE
  IFACE="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
  iptables -t nat -C PREROUTING -i "$IFACE" -p udp --dport 10000:65000 -j DNAT --to-destination "$UDP_PORT" 2>/dev/null || \
  iptables -t nat -A PREROUTING -i "$IFACE" -p udp --dport 10000:65000 -j DNAT --to-destination "$UDP_PORT"

  ip6tables -t nat -C PREROUTING -i "$IFACE" -p udp --dport 10000:65000 -j DNAT --to-destination "$UDP_PORT" 2>/dev/null || \
  ip6tables -t nat -A PREROUTING -i "$IFACE" -p udp --dport 10000:65000 -j DNAT --to-destination "$UDP_PORT"

  sysctl net.ipv4.conf.all.rp_filter=0
  sysctl "net.ipv4.conf.$IFACE.rp_filter=0"
  echo "net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.$IFACE.rp_filter=0" > /etc/sysctl.conf
  sysctl -p || true

  sudo iptables-save > /etc/iptables/rules.v4 || true
  sudo ip6tables-save > /etc/iptables/rules.v6 || true

  systemctl enable hysteria-server.service
  systemctl restart hysteria-server.service
}

# -----------------------------
# Mini web panel (FastAPI)
# -----------------------------
install_panel_backend(){
  if [[ "$INSTALL_PANEL" != "1" ]]; then return; fi

  local _port="${PANEL_PORT:-9000}"
  local _workdir="/var/lib/juepanel"
  local _svc="/etc/systemd/system/juepanel.service"

  echo "Installing mini web panel (FastAPI) at 127.0.0.1:${_port} ..."
  useradd -r -s /usr/sbin/nologin -d "$_workdir" juepanel 2>/dev/null || true
  mkdir -p "$_workdir"
  chown -R juepanel:juepanel "$_workdir"

  has_command python3-venv || install_software python3-venv
  sudo -u juepanel python3 -m venv "$_workdir/venv"
  sudo -u juepanel "$_workdir/venv/bin/pip" install fastapi "uvicorn[standard]" httpx

  # servers.json — default to local stats (port from STATS_LISTEN)
  local _stats_port="${STATS_LISTEN##*:}"
  mkdir -p /etc/juepanel
  cat > /etc/juepanel/servers.json <<JSON
[
  {"name":"local","base":"http://127.0.0.1:${_stats_port}","secret":"${STATS_SECRET}"}
]
JSON

  cat > "$_workdir/app.py" <<'PY'
from fastapi import FastAPI
import httpx, json

app = FastAPI()
SERVERS = json.load(open("/etc/juepanel/servers.json"))

async def fetch_online(client, base, secret):
    r = await client.get(f"{base}/online", headers={"Authorization": secret}, timeout=3)
    r.raise_for_status()
    return r.json()

@app.get("/overview")
async def overview():
    out = []
    async with httpx.AsyncClient() as client:
        for s in SERVERS:
            try:
                data = await fetch_online(client, s["base"], s["secret"])
                out.append({"name": s["name"], "online_count": sum(data.values()), "detail": data})
            except Exception as e:
                out.append({"name": s["name"], "error": str(e), "online_count": 0, "detail": {}})
    total = sum(i.get("online_count",0) for i in out)
    return {"total_online": total, "servers": out}
PY
  chown -R juepanel:juepanel "$_workdir"

  cat > "$_svc" <<EOF
[Unit]
Description=Jue UDP Admin Panel (Overview)
After=network.target

[Service]
User=juepanel
Group=juepanel
WorkingDirectory=$_workdir
ExecStart=$_workdir/venv/bin/uvicorn app:app --host 127.0.0.1 --port $_port
Restart=always

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now juepanel.service
  echo "Panel running on http://127.0.0.1:${_port}/overview"
}

# -----------------------------
# Main flows
# -----------------------------
perform_install(){
  local _fresh=""
  if ! is_hysteria_installed; then _fresh=1; fi

  # Secret generation if missing
  if [[ -z "$STATS_SECRET" && "$ENABLE_STATS" == "1" ]]; then
    STATS_SECRET="$(random_secret)"
    note "Generated STATS_SECRET=$STATS_SECRET"
  fi

  perform_install_hysteria_binary
  perform_install_hysteria_example_config
  perform_install_hysteria_home_legacy
  perform_install_hysteria_systemd
  setup_ssl
  start_services
  install_panel_backend
  perform_install_manager_script

  if [[ -n "$_fresh" ]]; then
    echo
    echo -e "$(tbold)✅ JUE-UDP installed (Hysteria v2).$(treset)"
    echo -e "Stats: $(tblue)curl -H 'Authorization: $STATS_SECRET' http://127.0.0.1:${STATS_LISTEN##*:}/online$(treset)"
    echo -e "Panel: $(tblue)curl http://127.0.0.1:${PANEL_PORT}/overview$(treset)"
    echo
  else
    restart_running_services
    start_services
    echo
    echo -e "$(tbold)✅ JUE-UDP updated.$(treset)"
    echo
  fi
}

perform_remove(){
  perform_remove_hysteria_binary
  stop_running_services
  perform_remove_hysteria_systemd
  echo
  echo -e "$(tbold)Removed. Config & certs remain:$(treset)"
  echo -e "\t$(tred)rm -rf $CONFIG_DIR$(treset)"
  if [[ "x$HYSTERIA_USER" != "xroot" ]]; then
    echo -e "\t$(tred)userdel -r $HYSTERIA_USER$(treset)"
  fi
  echo
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
