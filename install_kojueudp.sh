#!/usr/bin/env bash
# JUE-UDP installer (Hysteria v2 + Stats + nginx:81/server/online)
# Auto-publish link after install
set -euo pipefail

# =============== Defaults ===============
DOMAIN="${DOMAIN:-eg.jueudp.com}"
UDP_PORT="${UDP_PORT:-:36712}"

# v2 OBFS
OBFS="${OBFS:-jaideevpn}"
# Simple password auth
PASSWORD="${PASSWORD:-jaideevpn}"

UP_MBPS="${UP_MBPS:-100}"
DOWN_MBPS="${DOWN_MBPS:-100}"

# Stats API (auto)
ENABLE_STATS="${ENABLE_STATS:-1}"
STATS_LISTEN="${STATS_LISTEN:-127.0.0.1:9999}"
STATS_SECRET="${STATS_SECRET:-}"   # will autogen if empty

# Always publish 81 by default
PUBLISH_81="${PUBLISH_81:-1}"

# =============== Paths ===============
EXECUTABLE_INSTALL_PATH="/usr/local/bin/hysteria"
CONFIG_DIR="/etc/hysteria"
CONFIG_FILE="$CONFIG_DIR/config.json"
SYSTEMD_SERVICES_DIR="/etc/systemd/system"
SYSTEMD_SERVICE="$SYSTEMD_SERVICES_DIR/hysteria-server.service"
CURL_FLAGS=(-L -f -q --retry 5 --retry-delay 2 --retry-max-time 30)
REPO_URL="https://github.com/apernet/hysteria"

mkdir -p "$CONFIG_DIR"

# =============== Utils ===============
has(){ type -P "$1" >/dev/null 2>&1; }
say(){ echo -e "$*"; }
warn(){ echo -e "\e[33m$*\e[0m"; }
fail(){ echo -e "\e[31m$*\e[0m" >&2; exit 1; }
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

as_root(){ [[ $EUID -eq 0 ]] || exec sudo -E bash "$0" "$@"; }

# =============== Hysteria v2 ===============
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
  url="$REPO_URL/releases/latest/download/$file"
  say "Downloading Hysteria v2 …"
  curl -o "$dest" "$url"
}

install_hysteria(){
  tmp="$(mktemp)"; download_hysteria "$tmp"
  install -Dm755 "$tmp" "$EXECUTABLE_INSTALL_PATH"; rm -f "$tmp"
  "$EXECUTABLE_INSTALL_PATH" version || true
}

# =============== SSL (self-signed) ===============
setup_ssl(){
  say "Installing SSL certificates (self-signed)"
  openssl genrsa -out /etc/hysteria/hysteria.ca.key 2048 >/dev/null 2>&1 || true
  openssl req -new -x509 -days 3650 -key /etc/hysteria/hysteria.ca.key -subj "/C=CN/ST=GD/L=SZ/O=Hysteria, Inc./CN=Hysteria Root CA" -out /etc/hysteria/hysteria.ca.crt >/dev/null 2>&1 || true
  openssl req -newkey rsa:2048 -nodes -keyout /etc/hysteria/hysteria.server.key -subj "/C=CN/ST=GD/L=SZ/O=Hysteria, Inc./CN=$DOMAIN" -out /etc/hysteria/hysteria.server.csr >/dev/null 2>&1 || true
  openssl x509 -req -extfile <(printf "subjectAltName=DNS:$DOMAIN,DNS:$DOMAIN") -days 3650 -in /etc/hysteria/hysteria.server.csr -CA /etc/hysteria/hysteria.ca.crt -CAkey /etc/hysteria/hysteria.ca.key -CAcreateserial -out /etc/hysteria/hysteria.server.crt >/dev/null 2>&1 || true
}

# =============== Config (v2 JSON) ===============
write_config_v2(){
  has jq || install_pkg jq
  [[ -n "$STATS_SECRET" ]] || STATS_SECRET="$(rand_secret)"
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
    "type": "password",
    "password": ["$PASSWORD"]
  },
  "bandwidth": { "up": "${UP_MBPS} Mbps", "down": "${DOWN_MBPS} Mbps" },
  "disable_udp": false,
  "insecure": true,
  "trafficStats": { "listen": "$STATS_LISTEN", "secret": "$STATS_SECRET" }
}
EOF
}

# =============== systemd ===============
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

# =============== network & start ===============
get_iface(){ ip -4 route ls | awk '/default/ {print $5; exit}'; }

start_services(){
  say "Starting Hysteria"
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

  systemctl restart hysteria-server.service
  sleep 1
}

# =============== nginx publish (81) ===============
publish_81(){
  has nginx || install_pkg nginx
  has jq || install_pkg jq
  local PORT SECRET
  PORT="$(jq -r '.trafficStats.listen' "$CONFIG_FILE" | awk -F: '{print $NF}')"
  SECRET="$(jq -r '.trafficStats.secret' "$CONFIG_FILE")"
  [[ -n "$PORT" && "$PORT" != "null" && -n "$SECRET" && "$SECRET" != "null" ]] || fail "trafficStats not enabled"

  cat > /etc/nginx/conf.d/jue-online-81.conf <<EOF
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
}

# =============== Health check & print link ===============
print_link(){
  local IP; IP="$(curl -s http://ifconfig.me || hostname -I | awk '{print $1}')"
  echo "==============================================="
  echo " Online Users URL:"
  echo "   http://${IP}:81/server/online"
  echo "==============================================="
}

wait_stats_ready(){
  local p s i
  p="${STATS_LISTEN##*:}"
  s="$STATS_SECRET"
  for i in {1..15}; do
    if curl -s -H "Authorization: $s" "http://127.0.0.1:${p}/online" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  return 1
}

# =============== Main ===============
main(){
  as_root "$@"

  case "${1:-install}" in
    --remove)
      systemctl stop hysteria-server.service || true
      systemctl disable hysteria-server.service || true
      rm -f "$EXECUTABLE_INSTALL_PATH" "$SYSTEMD_SERVICE" /etc/nginx/conf.d/jue-online-81.conf
      systemctl daemon-reload || true
      has nginx && systemctl reload nginx || true
      say "Removed (configs left at $CONFIG_DIR)"; exit 0;;
  esac

  install_hysteria
  setup_ssl
  write_config_v2
  write_systemd
  start_services

  # Auto publish 81
  publish_81

  # Wait until stats API is up (best-effort)
  if wait_stats_ready; then
    say "Stats API is up."
  else
    warn "Stats API not responding yet, but nginx is configured. It should come up shortly if service is healthy."
  fi

  # Always print the link
  print_link

  systemctl --no-pager -n 15 status hysteria-server.service || true
  echo "Done."
}

main "$@"
