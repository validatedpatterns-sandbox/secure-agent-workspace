#!/usr/bin/env bash
# Runs as root before the Docker gateway starts. Keep sandbox TCP traffic
# within the VM uplink MTU without deleting existing networks or sandboxes.
set -euo pipefail

uplink="$(ip -j route show default | python3 -c 'import json,sys; routes=json.load(sys.stdin); print(next(r["dev"] for r in routes if "dev" in r))')"
mtu="$(ip -j link show dev "${uplink}" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["mtu"])')"
[[ "${mtu}" =~ ^[0-9]+$ ]] && (( mtu >= 1280 && mtu <= 65535 ))
network=openshell-docker
if ! docker network inspect "${network}" >/dev/null 2>&1; then
  docker network create --driver bridge --opt "com.docker.network.driver.mtu=${mtu}" "${network}" >/dev/null
fi
network_json="$(docker network inspect "${network}")"
bridge="$(printf '%s' "${network_json}" | python3 -c 'import json,sys; n=json.load(sys.stdin)[0]; assert n["Driver"] == "bridge"; print(n.get("Options", {}).get("com.docker.network.bridge.name") or "br-"+n["Id"][:12])')"
ip link set dev "${bridge}" mtu "${mtu}"

# Docker network options are immutable. Existing networks may still assign
# MTU 1500 to future container interfaces. Clamp SYN and SYN-ACK MSS in both
# directions so both peers send segments that fit this bridge/uplink.
mss=$((mtu - 40))
for direction in outbound inbound; do
  in_dev="${bridge}"; out_dev="${uplink}"
  if [[ "${direction}" == inbound ]]; then in_dev="${uplink}"; out_dev="${bridge}"; fi
  rule=(-i "${in_dev}" -o "${out_dev}" -p tcp --tcp-flags SYN,RST SYN -m tcpmss --mss "$((mss + 1)):65535" -j TCPMSS --set-mss "${mss}")
  iptables -w 5 -t mangle -C FORWARD "${rule[@]}" 2>/dev/null || iptables -w 5 -t mangle -A FORWARD "${rule[@]}"
done

while IFS= read -r container; do
  [[ -n "${container}" ]] || continue
  pid="$(docker inspect "${container}" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["State"]["Pid"])')"
  (( pid > 0 )) || continue
  # Only reconcile the interface attached to this network, not other networks.
  address="$(docker inspect "${container}" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["NetworkSettings"]["Networks"]["openshell-docker"]["IPAddress"])')"
  iface="$(nsenter -t "${pid}" -n ip -j addr | python3 -c 'import json,sys; address=sys.argv[1]; print(next(i["ifname"] for i in json.load(sys.stdin) if any(a.get("local")==address for a in i.get("addr_info",[]))))' "${address}")"
  nsenter -t "${pid}" -n ip link set dev "${iface}" mtu "${mtu}"
done < <(docker ps --filter "network=${network}" -q)
echo "Sandbox network ${network}: uplink=${uplink}, MTU=${mtu}, TCP MSS=${mss}"
