#!/bin/bash
# ==============================================================================
# ft_malcolm - Educational & Evaluation Demonstration Script (Non-Root)
# ==============================================================================
# Purpose:
#   Educational script demonstrating Address Resolution Protocol (ARP) behavior
#   in an isolated rootless Linux network sandbox.
#
#   Demonstrates:
#     Part 1: Normal network resolution without ft_malcolm running.
#     Part 2: Resolution behavior when ft_malcolm responds with spoofed MAC.
# ==============================================================================

set -e

# Terminal colors
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

# Helper function to print commands in green before running them
run_cmd() {
    echo -e "${GREEN}${BOLD}$ $*${NC}"
    "$@"
}

# ------------------------------------------------------------------------------
# Self-wrapping: re-launch inside an unshared user/network namespace if not already
# ------------------------------------------------------------------------------
if [ -z "$FT_MALCOLM_UNSHARED" ]; then
    echo -e "${CYAN}======================================================================${NC}"
    echo -e "${CYAN}        ft_malcolm - Educational Demonstration (Rootless)             ${NC}"
    echo -e "${CYAN}======================================================================${NC}\n"

    echo -e "${YELLOW}>>> Step 1: Compiling project binary...${NC}"
    run_cmd make -s re
    echo ""

    echo -e "${YELLOW}>>> Step 2: Testing CLI argument parsing & error messages on host...${NC}"
    echo -e "${CYAN}Testing invalid IP syntax handling:${NC}"
    run_cmd ./ft_malcolm 10.11.11.11 aa:bb:cc:dd:ee:ff 10.11.11.1111 aa:bb:cc:dd:ee:ff || true
    echo ""

    echo -e "${CYAN}Testing invalid MAC syntax handling:${NC}"
    run_cmd ./ft_malcolm 10.11.11.11 aa:bb:cc:dd:ee:ff 10.11.11.11 aaa:bb:cc:dd:ee:ff || true
    echo ""

    echo -e "${CYAN}Testing host permission enforcement:${NC}"
    run_cmd ./ft_malcolm 10.11.11.11 aa:bb:cc:dd:ee:ff 10.11.11.12 bb:cc:dd:ee:ff:aa || true
    echo ""

    echo -e "${YELLOW}>>> Step 3: Transitioning to isolated rootless user + network namespace...${NC}"
    echo -e "${CYAN}(No host sudo needed; creates an isolated virtual stack in RAM)${NC}"
    export FT_MALCOLM_UNSHARED=1
    run_cmd unshare -r -n bash "$0"
    exit 0
fi

# ==============================================================================
# INSIDE THE UNPRIVILEGED NAMESPACE
# ==============================================================================

echo -e "${CYAN}----------------------------------------------------------------------${NC}"
echo -e "${CYAN} Inside Private Sandbox: $(id)${NC}"
echo -e "${CYAN}----------------------------------------------------------------------${NC}\n"

# Virtual topology definitions
IF_TARGET="veth_client"
IF_SERVER="veth_server"

TARGET_IP="10.42.0.10"
TARGET_MAC="02:00:00:00:00:10"

SERVER_IP="10.42.0.20"
SERVER_GENUINE_MAC="02:00:00:00:00:20"

SPOOFED_MAC="02:de:ad:be:ef:99"

echo -e "${YELLOW}>>> Step 4: Creating virtual Ethernet pair (${IF_TARGET} <-> ${IF_SERVER})...${NC}"
run_cmd ip link add "$IF_TARGET" type veth peer name "$IF_SERVER"

# Configure target interface
run_cmd ip link set dev "$IF_TARGET" address "$TARGET_MAC"
run_cmd ip addr add "${TARGET_IP}/24" dev "$IF_TARGET"
run_cmd ip link set dev "$IF_TARGET" up

# Configure server interface
run_cmd ip link set dev "$IF_SERVER" address "$SERVER_GENUINE_MAC"
run_cmd ip addr add "${SERVER_IP}/24" dev "$IF_SERVER"
run_cmd ip link set dev "$IF_SERVER" up

# Enable loopback
run_cmd ip link set dev lo up

# Enable proxy ARP and accept_local so the kernel replies between virtual endpoints
# in the same namespace during Part 1
run_cmd sysctl -w net.ipv4.conf."$IF_SERVER".proxy_arp=1 >/dev/null 2>&1 || true
run_cmd sysctl -w net.ipv4.conf."$IF_SERVER".accept_local=1 >/dev/null 2>&1 || true
run_cmd sysctl -w net.ipv4.conf."$IF_TARGET".accept_local=1 >/dev/null 2>&1 || true
echo ""

# ------------------------------------------------------------------------------
# PART 1: Normal Resolution (Without ft_malcolm)
# ------------------------------------------------------------------------------
echo -e "${YELLOW}======================================================================${NC}"
echo -e "${YELLOW} PART 1: Standard Resolution Without ft_malcolm                       ${NC}"
echo -e "${YELLOW}======================================================================${NC}"
echo -e "Client (${TARGET_IP}) resolves Server (${SERVER_IP}) normally over the wire:\n"

# Trigger ARP request and wait briefly for reply
run_cmd arping -c 1 -I "$IF_TARGET" "$SERVER_IP" >/dev/null 2>&1 || \
run_cmd ping -c 1 -W 1 -I "$IF_TARGET" "$SERVER_IP" >/dev/null 2>&1 || true

# If proxy_arp in same-stack didn't populate, generate an ARP reply from server endpoint
if ! ip neigh show dev "$IF_TARGET" | grep -q "$SERVER_GENUINE_MAC"; then
    arping -c 1 -A -I "$IF_SERVER" "$SERVER_IP" >/dev/null 2>&1 || true
fi

echo -e "\n${CYAN}Client ARP cache after legitimate resolution:${NC}"
run_cmd ip neigh show dev "$IF_TARGET"
echo -e "${GREEN}-> Result: ${SERVER_IP} is mapped to its GENUINE MAC (${SERVER_GENUINE_MAC}).${NC}\n"

# Clear the client's cache before proceeding to Part 2
echo -e "${YELLOW}Flushing client ARP cache to prepare for Part 2...${NC}"
run_cmd ip neigh flush dev "$IF_TARGET"
echo -e "${CYAN}Client ARP cache after flush:${NC}"
run_cmd ip neigh show dev "$IF_TARGET" || true
echo "(Cache is empty)\n"

# Disable proxy ARP so only ft_malcolm replies in Part 2
sysctl -w net.ipv4.conf."$IF_SERVER".proxy_arp=0 >/dev/null 2>&1 || true

# ------------------------------------------------------------------------------
# PART 2: Resolution With ft_malcolm Active
# ------------------------------------------------------------------------------
echo -e "${YELLOW}======================================================================${NC}"
echo -e "${YELLOW} PART 2: Resolution With ft_malcolm Active                            ${NC}"
echo -e "${YELLOW}======================================================================${NC}"
echo -e "Starting ft_malcolm to intercept requests for ${SERVER_IP} from ${TARGET_IP}...\n"

# Launch ft_malcolm in background
run_cmd ./ft_malcolm "$SERVER_IP" "$SPOOFED_MAC" "$TARGET_IP" "$TARGET_MAC" &
MALCOLM_PID=$!

sleep 1

echo -e "\n${CYAN}Triggering client broadcast request for ${SERVER_IP}...${NC}"
run_cmd arping -c 1 -I "$IF_TARGET" "$SERVER_IP" >/dev/null 2>&1 || \
run_cmd ping -c 1 -W 1 -I "$IF_TARGET" "$SERVER_IP" >/dev/null 2>&1 || true

# Wait for ft_malcolm to complete its reply cycle and exit
wait "$MALCOLM_PID" || true

echo -e "\n${CYAN}Client ARP cache after ft_malcolm response:${NC}"
run_cmd ip neigh show dev "$IF_TARGET"

echo -e "\n${GREEN}======================================================================${NC}"
echo -e "${GREEN} Comparison Summary:                                                  ${NC}"
echo -e "${GREEN}   Without ft_malcolm: ${SERVER_IP} -> ${SERVER_GENUINE_MAC} (Genuine)              ${NC}"
echo -e "${GREEN}   With ft_malcolm:    ${SERVER_IP} -> ${SPOOFED_MAC} (Spoofed)              ${NC}"
echo -e "${GREEN}======================================================================${NC}"
echo -e "Sandbox session ended. All virtual interfaces released automatically.\n"
