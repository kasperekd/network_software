#!/bin/sh

set -e

echo "[CLIENT SCRIPT] Starting..."

echo "[CLIENT SCRIPT] Starting udhcpc in background for interface eth0..."
udhcpc -i eth0 -b -p /var/run/udhcpc.eth0.pid -S

echo "[CLIENT SCRIPT] Waiting for IP address on eth0..."
attempts=0
while ! ip addr show eth0 | grep -q 'inet '; do
  attempts=$((attempts+1))
  if [ "$attempts" -gt 30 ]; then
    echo "[CLIENT SCRIPT] ERROR: Failed to get IP address on eth0 in time!"
    echo "[CLIENT SCRIPT] Current interface status:"
    ip addr show eth0
    exit 1
  fi
  sleep 1
done

CLIENT_IP=$(ip addr show eth0 | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
ROUTER_IP=$(ip route | grep default | awk '{print $3}' || echo "not_found")

echo "[CLIENT SCRIPT] Successfully obtained IP: $CLIENT_IP"
echo "[CLIENT SCRIPT] Gateway: $ROUTER_IP"
echo "[CLIENT SCRIPT] Full interface configuration (eth0):"
ip addr show eth0
echo "[CLIENT SCRIPT] Routing table:"
ip route

echo "[CLIENT SCRIPT] Testing network connectivity..."

if [ "$ROUTER_IP" != "not_found" ]; then
  echo "[CLIENT SCRIPT] Pinging gateway $ROUTER_IP..."
  if ping -c 3 "$ROUTER_IP"; then
    echo "[CLIENT SCRIPT] Ping to gateway $ROUTER_IP successful!"
  else
    echo "[CLIENT SCRIPT] WARNING: Ping to gateway $ROUTER_IP failed!"
  fi
else
  echo "[CLIENT SCRIPT] WARNING: Could not determine gateway to ping."
fi

echo "[CLIENT SCRIPT] Pinging google.com (testing DNS and external connectivity)..."
if ping -c 3 google.com; then
  echo "[CLIENT SCRIPT] Ping to google.com successful!"
else
  echo "[CLIENT SCRIPT] WARNING: Ping to google.com failed! Check DNS or external connectivity."
fi
tail -f /dev/null