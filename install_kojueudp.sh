#!/usr/bin/env bash
# JUE-UDP installer (Hysteria v2 + Stats + nginx:81/server/online)
# (c) 2023 Jue Htet — updated by ChatGPT

set -euo pipefail

# ===================== Config (defaults; can override by env or flags) =====================
DOMAIN="${DOMAIN:-eg.jueudp.com}"
PROTOCOL="${PROTOCOL:-udp}"
UDP_PORT="${UDP_PORT:-:36712}"

# OBFS (Hysteria v2 'salamander' password)
OBFS="${OBFS:-jaideevpn}"

# Auth password list
PASSWORD="${PASSWORD:-jaideevpn}"

UP_MBPS="${UP_MBPS:-100}"
DOWN_MBPS="${DOWN_MBPS:-100}"

# Stats
ENABLE_STATS="${ENABLE_STATS:-1}"
STATS_LISTEN="${STATS_LISTEN:-127.0.0.1:9999}"
STATS_SECRET="${STATS_SECRET:-}"   # auto-generate if empty

# Port 81 publish control: 0=none, 1=publish, 2=unpublish
PUBLISH_81="${PUBLISH_81:-0}"

# ===================== Paths =====================
SCRIPT_NAME="$(basename "$0")"
SCRIPT_ARGS=("$@")
EXECUTABLE_INSTALL_PATH="/usr/local/bin/hysteria"
SYSTEMD_SERVICES_DIR="/etc/systemd/system"
CONFIG_DIR="/etc/hysteria"
CONFIG_FILE="$CONFIG_DIR/config.json"
USER_DB="$CONFIG_DIR/udpusers.db"
REPO_URL="https://github.com/apernet/hysteria"
SYSTEMD_SERVICE="$SYSTEMD_SERVICES_DIR/hysteria-server.service"
CURL_FLAGS=(-L -f -q --retry 5 --retry-delay 10 --retry-max-time 60)

mkdir -p "$CONFIG_DIR"; touch "$USER_DB"

# ===================== Utils =====================
has(){ type -P "$1" >/dev/null 2>&1; }
say(){ echo -e "$*"; }
fail(){ echo -e "\e[31m$*\e[0m" >&2; exit 1; }
note(){ echo -e "\e[1m$*\e[0m"; }
rand_secret(){ head -c 32 /dev/urandom | base64 | tr -d '/+=\n'; }
curl(){ command curl "${CURL_FLAGS[@]}" "$@"; }

install_pkg(){
  local p="$1"
  if has apt-get; then apt-get update -y && apt-get install -y "$p"
  elif has dnf; then dnf install -y "$p"
  elif has yum; then yum install -y "$p"
  elif has zypper; then zypper install -y "$p"
  elif has pacman; then pacman -Sy --noconfirm "$p"
  else fail "No supported package manager to install $p"
  fi
}

as_root(){
  if [[ $EUID -ne 0 ]]; then
    exec sudo -E bash "$0" "${SCRIPT_ARGS[@]}"
  fi
}

parse_args(){
  OP="install"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --remove) OP="remove";;
      --version) VERSION="$2"; shift;;
      -l|--local) LOCAL_BIN="$2"; shift;;
      --stats-port) STATS_LISTEN="127.0.0.1:${2##*:}"; shift;;
      --stats-secret) STATS_SECRET="$2"; shift;;
      --publish-81) PUBLISH_81=1;;
      --unpublish-81) PUBLISH_81=2;;
      -h|--help) usage; exit 0;;
      *) fail "Unknown option: $1";;
    esac
    shift
  done
}

usage(){
  cat <<EOF
$SCRIPT_NAME — JUE-UDP (Hysteria v2) installer

Install / Update:
  $0 [--version vX.Y.Z] [--stats-port 9999] [--stats-secret SECRET] [--publish-81|--unpublish-81]

Examples:
  $0 --publish-81
  $0 --stats-port 9999 --stats-secret "MyStrongSecret" --publish-81

Remove:
  $0 --remove
EOF
}

# ===================== Hysteria v2 binary =====================
download_hysteria(){
  local dest="$1" arch file url
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) file="hysteria-linux-amd64";;
    aarch64|arm64) file="hysteria-linux-arm64";;
    armv7l|armv7|arm) file="hysteria-linux-armv7";;
    386|i386|i686) file="hysteria-linux-386";;
    s390x) file="hysteria-linux-s390x";;
    *) fail "Unsupported arch: $arch";;
  esac
  if [[ -n "${VERSION:-}" ]]; then
    url="$REPO_URL/releases/download/${VERSION}/$file"
  else
    url="$REPO_URL/releases/latest/download/$file"
  fi
  note "Downloading Hysteria v2: $url"
  curl -o "$dest" "$url"
}

install_hysteria(){
  if [[ -n "${LOCAL_BIN:-}" ]]; then
    install -Dm755 "$LOCAL_BIN" "$EXECUTABLE_INSTALL_PATH"
  else
    tmp="$(mktemp)"; download_hysteria "$tmp"; install -Dm755 "$tmp" "$EXECUTABLE_INSTALL_PATH"; rm -f "$tmp"
  fi
  "$EXECUTABLE_INSTALL_PATH" version || true
}

# ===================== DB (optional) =====================
setup_db(){
  has sqlite3 || install_pkg sqlite3
  [[ -f "$USER_DB" ]] || sqlite3 "$USER_DB" ".databases" || fail "Cannot create DB"
  sqlite3 "$USER_DB" <<'SQL'
CREATE TABLE IF NOT EXISTS users(
  username TEXT PRIMARY KEY,
  password TEXT NOT NULL
);
SQL
  if [[ -z "$(sqlite3 "$USER_DB" "SELECT username FROM users WHERE username='default'")" ]]; then
     sqlite3 "$USER_DB" "INSERT INTO users(username,password) VALUES('default','password')" || true
  fi
}

fetch_users_json(){
  # Convert "user:pass,user:pass" -> [{"username":"u","password":"p"},...]
  if [[ -f "$USER_DB" ]]; then
    local csv users
    csv="$(sqlite3 "$USER_DB" "SELECT username || ':' || password FROM users;" | paste -sd, -)"
    if [[ -n "$csv" ]]; then
      IFS=, read -r -a arr <<<"$csv"
      users="["
      for i in "${!arr[@]}"; do
        IFS=: read -r u p <<<"${arr[$i]}"
        users+="{\"username\":\"$u\",\"password\":\"$p\"}"
        [[ $i -lt $((${#arr[@]}-1)) ]] && users+=","
      done
      users+="]"
      echo "$users"; return
    fi
  fi
  echo "[]"
}

# ===================== Config (v2 format) =====================
write_config_v2(){
  has jq || install_pkg jq
  mkdir -p "$CONFIG_DIR"

  # Secret auto-gen
  [[ -n "$STATS_SECRET" ]] || STATS_SECRET="$(rand_secret)"

  local users_json; users_json="$(fetch_users_json)"

  cat > "$CONFIG_FILE" <<EOF
{
  "listen": "$UDP_PORT",
  "tls": {
    "cert": "/etc/hysteria/hysteria.server.crt",
    "key": "/etc/hysteria/hysteria.server.key"
  },
  "obfs": {
    "type": "salamander",
    "salamander": { "password": "$OBFS" }
  },
  "auth": {
    "mode": "password",
    "config": ["$PASSWORD"]
  },
  "bandwidth": {
    "up": "${UP_MBPS} Mbps",
    "down": "${DOWN_MBPS} Mbps"
  },
  "disable_udp": false,
  "insecure": true,
  "trafficStats": {
    "listen": "$STATS_LISTEN",
    "secret": "$STATS_SECRET"
  }
}
EOF
  note "Wrote v2 config -> $CONFIG_FILE"
}

# ===================== systemd =====================
write_systemd(){
  cat > "$SYSTEMD_SERVICE" <<'EOF'
[Unit]
Description=AGN-UDP Service (Hysteria v2)
After=network.target

[Service]
User=root
Group=root
WorkingDirectory=/etc/hysteria
ExecStart=/usr/local/bin/hysteria server --config /etc/hysteria/config.json
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable hysteria-server.service
}

# ===================== SSL (self-signed) =====================
setup_ssl(){
  note "Installing SSL certificates (self-signed)"
  openssl genrsa -out /etc/hysteria/hysteria.ca.key 2048 >/dev/null 2>&1 || true
  openssl req -new -x509 -days 3650 -key /etc/hysteria/hysteria.ca.key -subj "/C=CN/ST=GD/L=SZ/O=Hysteria, Inc./CN=Hysteria Root CA" -out /etc/hysteria/hysteria.ca.crt >/dev/null 2>&1 || true
  openssl req -newkey rsa:2048 -nodes -keyout /etc/hysteria/hysteria.server.key -subj "/C=CN/ST=GD/L=SZ/O=Hysteria, Inc./CN=$DOMAIN" -out /etc/hysteria/hysteria.server.csr >/dev/null 2>&1 || true
  openssl x509 -req -extfile <(printf "subjectAltName=DNS:$DOMAIN,DNS:$DOMAIN") -days 3650 -in /etc/hysteria/hysteria.server.csr -CA /etc/hysteria/hysteria.ca.crt -CAkey /etc/hysteria/hysteria.ca.key -CAcreateserial -out /etc/hysteria/hysteria.server.crt >/dev/null 2>&1 || true
}

# ===================== Start & network =====================
get_iface(){ ip -4 route ls | awk '/default/ {print $5; exit}'; }

start_services(){
  note "Starting Hysteria"
  has iptables || install_pkg iptables
  if has apt-get; then
    echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections || true
    echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections || true
    apt-get -y install iptables-persistent || true
  fi

  local IFACE; IFACE="$(get_iface)"
  iptables -t nat -C PREROUTING -i "$IFACE" -p udp --dport 10000:65000 -j DNAT --to-destination "$UDP_PORT" 2>/dev/null || \
  iptables -t nat -A PREROUTING -i "$IFACE" -p udp --dport 10000:65000 -j DNAT --to-destination "$UDP_PORT" || true
  ip6tables -t nat -C PREROUTING -i "$IFACE" -p udp --dport 10000:65000 -j DNAT --to-destination "$UDP_PORT" 2>/dev/null || \
  ip6tables -t nat -A PREROUTING -i "$IFACE" -p udp --dport 10000:65000 -j DNAT --to-destination "$UDP_PORT" || true

  sysctl net.ipv4.conf.all.rp_filter=0 || true
  sysctl "net.ipv4.conf.$IFACE.rp_filter=0" || true
  printf "net.ipv4.ip_forward=1\nnet.ipv4.conf.all.rp_filter=0\nnet.ipv4.conf.%s.rp_filter=0\n" "$IFACE" >/etc/sysctl.conf
  sysctl -p || true

  iptables-save >/etc/iptables/rules.v4 || true
  ip6tables-save >/etc/iptables/rules.v6 || true

  systemctl restart hysteria-server.service
  sleep 1
  systemctl --no-pager -n 20 status hysteria-server.service || true
}

# ===================== Nginx 81 publish =====================
publish_81(){
  has nginx || install_pkg nginx
  has jq || install_pkg jq
  local PORT SECRET
  PORT="$(jq -r '.trafficStats.listen' "$CONFIG_FILE" | awk -F: '{print $NF}')"
  SECRET="$(jq -r '.trafficStats.secret' "$CONFIG_FILE")"
  [[ -n "$PORT" && "$PORT" != "null" && -n "$SECRET" && "$SECRET" != "null" ]] || fail "trafficStats not enabled"

  cat > /etc/nginx/conf.d/jue-online-81.conf <<EOF
# auto-generated
server {
    listen 81 default_server;
    server_name _;

    location /server/ {
        proxy_set_header Authorization "$SECRET";
        proxy_pass http://127.0.0.1:${PORT}/;
        proxy_http_version 1.1;
        proxy_read_timeout 5s;
        add_header Cache-Control "no-store";
    }
}
EOF
  nginx -t
  systemctl reload nginx || systemctl restart nginx
  if has ufw; then ufw allow 81/tcp || true; fi
  if has firewall-cmd; then firewall-cmd --add-port=81/tcp --permanent || true && firewall-cmd --reload || true; fi

  local IP; IP="$(curl -s http://ifconfig.me || hostname -I | awk '{print $1}')"
  say "Online Users URL:  http://${IP}:81/server/online"
}

unpublish_81(){
  rm -f /etc/nginx/conf.d/jue-online-81.conf
  if has nginx; then nginx -t && systemctl reload nginx || true; fi
  say "Unpublished port 81 mapping."
}

# ===================== Main ops =====================
install_flow(){
  setup_db
  install_hysteria
  write_config_v2
  write_systemd
  setup_ssl
  start_services

  if [[ "$PUBLISH_81" -eq 1 ]]; then publish_81; fi
  if [[ "$PUBLISH_81" -eq 2 ]]; then unpublish_81; fi

  # quick local test (best-effort)
  if [[ "$ENABLE_STATS" == "1" ]]; then
    local p s; p="${STATS_LISTEN##*:}"; s="$STATS_SECRET"
    say "Test on server:  curl -H 'Authorization: $s' http://127.0.0.1:${p}/online"
  fi
  say "✅ JUE-UDP (Hysteria v2) installed/updated."
}

remove_flow(){
  systemctl stop hysteria-server.service || true
  systemctl disable hysteria-server.service || true
  rm -f "$EXECUTABLE_INSTALL_PATH" "$SYSTEMD_SERVICE"
  systemctl daemon-reload || true
  say "✅ Removed. Config left at $CONFIG_DIR"
}

# ===================== Entrypoint =====================
as_root
parse_args "$@"

case "${OP}" in
  install)   install_flow ;;
  remove)    remove_flow ;;
  *)         fail "Unknown op: $OP" ;;
esac
