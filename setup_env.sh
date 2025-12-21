#!/bin/bash
# CTAE Environment Setup Script
# Target: Ubuntu 22.04/24.04 LTS
# Purpose: Install all dependencies for kernel module development and benchmarking

set -e  # Exit on error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}CTAE Environment Setup${NC}"
echo -e "${GREEN}========================================${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Error: This script must be run as root (use sudo)${NC}"
    exit 1
fi

# Detect Ubuntu version
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
    VER=$VERSION_ID
    echo -e "${YELLOW}Detected OS: $OS $VER${NC}"
else
    echo -e "${RED}Error: Cannot detect OS version${NC}"
    exit 1
fi

# Update package lists
echo -e "${YELLOW}[1/6] Updating package lists...${NC}"
apt-get update -qq

# Install kernel development headers
echo -e "${YELLOW}[2/6] Installing kernel headers and build tools...${NC}"
KERNEL_VERSION=$(uname -r)
apt-get install -y \
    linux-headers-${KERNEL_VERSION} \
    linux-headers-generic \
    build-essential \
    gcc \
    make \
    git \
    kmod

# Install hardware locality tools
echo -e "${YELLOW}[3/6] Installing hardware topology tools...${NC}"
apt-get install -y \
    hwloc \
    libhwloc-dev \
    libnuma-dev \
    numactl

# Install performance monitoring and benchmarking tools
echo -e "${YELLOW}[4/6] Installing performance tools...${NC}"
apt-get install -y \
    linux-tools-common \
    linux-tools-generic \
    linux-tools-${KERNEL_VERSION} \
    sysbench \
    stress-ng \
    perf-tools-unstable

# Install debugging and analysis tools
echo -e "${YELLOW}[5/6] Installing debugging tools...${NC}"
apt-get install -y \
    gdb \
    strace \
    ltrace \
    valgrind \
    sysstat

# Install netlink development libraries (for future user-space communication)
echo -e "${YELLOW}[6/6] Installing netlink libraries...${NC}"
apt-get install -y \
    libnl-3-dev \
    libnl-genl-3-dev \
    libnl-route-3-dev

# Verify installations
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Verification${NC}"
echo -e "${GREEN}========================================${NC}"

echo -e "${YELLOW}GCC Version:${NC}"
gcc --version | head -n 1

echo -e "${YELLOW}Kernel Headers:${NC}"
ls -d /lib/modules/$(uname -r)/build 2>/dev/null && echo "✓ Present" || echo "✗ Missing"

echo -e "${YELLOW}hwloc (lstopo):${NC}"
which lstopo && lstopo --version || echo "✗ Missing"

echo -e "${YELLOW}perf:${NC}"
which perf && perf --version || echo "✗ Missing"

echo -e "${YELLOW}sysbench:${NC}"
which sysbench && sysbench --version || echo "✗ Missing"

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Setup Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "You can now build the CTAE kernel module."
echo -e "Run: ${YELLOW}cd core && make${NC}"