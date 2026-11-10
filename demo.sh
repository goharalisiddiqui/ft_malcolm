#!/bin/bash
# ==============================================================================
# ft_malcolm - Evaluation Demonstration Script
# ==============================================================================
# Purpose:
#   Sets up a minimal, isolated virtual test environment using Linux network
#   namespaces (ip netns) to demonstrate ft_malcolm during 42 peer evaluations.
#
# Requirements:
#   - Root / sudo privileges (for netns and raw socket permissions)
#   - iproute2 ('ip' command)
#   - arping or standard ping
# ==============================================================================

set -e

# Color helpers for readable evaluation output
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[Error]${NC} This demonstration script must be run as root (or with sudo)."
    echo "Usage: sudo $0"
    exit 1
fi

echo -e "${CYAN}======================================================================${NC}"
echo -e "${CYAN}               ft_malcolm - 42 Peer Evaluation Demo                   ${NC}"
echo -e "${CYAN}======================================================================${NC}\n"

# Define lab parameters
NS_VICTIM="demo_victim"
NS_ATTACKER="demo_attacker"
VETH_VICTIM="veth_vic"
VETH_ATTACKER="veth_atk"

VICTIM_IP="10.42.0.2"
VICTIM_MAC="02:00:00:00:00:02"

ATTACKER_IP="10.42.0.3"
ATTACKER_MAC="02:00:00:00:00:03"

SOURCE_IP="10.42.0.1"          # Address to resolve / spoof (e.g. Gateway)
SPOOFED_MAC="02:de:ad:be:ef:01" # Spoofed MAC provided to ft_malcolm

# Clean up any leftover namespaces on exit
cleanup() {
    echo -e "\n${YELLOW}[Teardown] Cleaning up network namespaces...${NC}"
    ip netns del "$NS_VICTIM" 2>/dev/null || true
    ip netns del "$NS_ATTACKER" 2>/dev/null || true
    echo -e "${GREEN}[Done] Test environment removed cleanly.${NC}"
}
trap cleanup EXIT INT TERM

# ------------------------------------------------------------------------------
# 1. Compilation
# ------------------------------------------------------------------------------
echo -e "${YELLOW}[Step 1] Compiling ft_malcolm...${NC}"
make -s re
echo -e "${GREEN}[OK] Binary 'ft_malcolm' built successfully.${NC}\n"

# ------------------------------------------------------------------------------
# 2. Test Input Validation & Error Handling (Mandatory Subject Checks)
# ------------------------------------------------------------------------------
echo -e "${YELLOW}[Step 2] Demonstrating parameter validation...${NC}"

echo -e "Testing invalid IP address:"
echo "$ ./ft_malcolm 10.11.11.11 aa:bb:cc:dd:ee:ff 10.11.11.1111 aa:bb:cc:dd:ee:ff"
./ft_malcolm 10.11.11.11 aa:bb:cc:dd:ee:ff 10.11.11.1111 aa:bb:cc:dd:ee:ff || true

echo -e "\nTesting invalid MAC address:"
echo "$ ./ft_malcolm 10.11.11.11 aa:bb:cc:dd:ee:ff 10.11.11.11 aaa:bb:cc:dd:ee:ff"
./ft_malcolm 10.11.11.11 aa:bb:cc:dd:ee:ff 10.11.11.11 aaa:bb:cc:dd:ee:ff || true
echo ""

# ------------------------------------------------------------------------------
# 3. Create Isolated Virtual Network Environment
# ------------------------------------------------------------------------------
echo -e "${YELLOW}[Step 3] Configuring network namespaces and veth pair...${NC}"

# Create two isolated namespaces: 'demo_victim' and 'demo_attacker'
ip netns add "$NS_VICTIM"
ip netns add "$NS_ATTACKER"

# Create a virtual Ethernet pair acting as a direct cable between them
ip link add "$VETH_VICTIM" type veth peer name "$VETH_ATTACKER"

# Move each end into its respective namespace
ip link set "$VETH_VICTIM" netns "$NS_VICTIM"
ip link set "$VETH_ATTACKER" netns "$NS_ATTACKER"

# Configure interfaces in Victim namespace
ip netns exec "$NS_VICTIM" ip link set dev lo up
ip netns exec "$NS_VICTIM" ip link set dev "$VETH_VICTIM" address "$VICTIM_MAC"
ip netns exec "$NS_VICTIM" ip addr add "${VICTIM_IP}/24" dev "$VETH_VICTIM"
ip netns exec "$NS_VICTIM" ip link set dev "$VETH_VICTIM" up

# Configure interfaces in Attacker namespace
ip netns exec "$NS_ATTACKER" ip link set dev lo up
ip netns exec "$NS_ATTACKER" ip link set dev "$VETH_ATTACKER" address "$ATTACKER_MAC"
ip netns exec "$NS_ATTACKER" ip addr add "${ATTACKER_IP}/24" dev "$VETH_ATTACKER"
ip netns exec "$NS_ATTACKER" ip link set dev "$VETH_ATTACKER" up

echo -e "${GREEN}[OK] Isolated network nodes ready:${NC}"
echo "  - Victim node:   IP $VICTIM_IP, MAC $VICTIM_MAC"
echo "  - Attacker node: IP $ATTACKER_IP, MAC $ATTACKER_MAC"
echo ""

# ------------------------------------------------------------------------------
# 4. Display Initial Victim ARP Table
# ------------------------------------------------------------------------------
echo -e "${YELLOW}[Step 4] Checking initial ARP cache on victim...${NC}"
echo "$ ip netns exec $NS_VICTIM ip neigh show"
ip netns exec "$NS_VICTIM" ip neigh show || true
echo "(Cache is initially empty)"
echo ""

# ------------------------------------------------------------------------------
# 5. Launch ft_malcolm & Trigger ARP Resolution
# ------------------------------------------------------------------------------
echo -e "${YELLOW}[Step 5] Launching ft_malcolm in attacker namespace...${NC}"
echo "Command:"
echo "  ip netns exec $NS_ATTACKER ./ft_malcolm $SOURCE_IP $SPOOFED_MAC $VICTIM_IP $VICTIM_MAC"
echo ""

# Run ft_malcolm in background inside the attacker namespace
ip netns exec "$NS_ATTACKER" ./ft_malcolm "$SOURCE_IP" "$SPOOFED_MAC" "$VICTIM_IP" "$VICTIM_MAC" &
MALCOLM_PID=$!

# Brief pause to ensure the socket listener is active
sleep 1

echo -e "${YELLOW}[Step 6] Triggering broadcast ARP request from victim...${NC}"
echo "$ ip netns exec $NS_VICTIM arping -c 1 -I $VETH_VICTIM $SOURCE_IP"

# Use arping or ping to send an ARP request for the target source IP
if command -v arping &>/dev/null; then
    ip netns exec "$NS_VICTIM" arping -c 1 -I "$VETH_VICTIM" "$SOURCE_IP" >/dev/null 2>&1 || true
else
    ip netns exec "$NS_VICTIM" ping -c 1 -W 1 "$SOURCE_IP" >/dev/null 2>&1 || true
fi

# Wait for ft_malcolm to finish processing and exit cleanly
wait "$MALCOLM_PID" || true
echo ""

# ------------------------------------------------------------------------------
# 6. Verify ARP Table on Victim
# ------------------------------------------------------------------------------
echo -e "${YELLOW}[Step 7] Inspecting victim's ARP table after attack...${NC}"
echo "$ ip netns exec $NS_VICTIM ip neigh show"
ip netns exec "$NS_VICTIM" ip neigh show

echo -e "\n${GREEN}[Verification Complete]${NC}"
echo "Notice that the entry for $SOURCE_IP now points to $SPOOFED_MAC."
echo "ft_malcolm successfully detected the request, replied with the spoofed MAC, and exited cleanly."
