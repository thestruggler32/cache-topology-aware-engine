#!/bin/bash
echo "========================================="
echo "CTAE Phase 2 - PMU Monitoring Demo"
echo "========================================="
echo ""
echo "Step 1: Baseline stats (idle system)"
sudo cat /sys/kernel/debug/ctae/stats | head -20

echo ""
echo "Step 2: Generating heavy cache pressure..."
stress-ng --cpu 12 --cache 8 --timeout 10s > /dev/null 2>&1 &
sleep 11

echo ""
echo "Step 3: Stats during/after stress test"
sudo cat /sys/kernel/debug/ctae/stats | grep -E "CPU|Contention|Miss Rate" | head -40

echo ""
echo "Step 4: Contention detection log"
sudo dmesg | grep "Detected contention" | tail -5

echo ""
echo "========================================="
echo "Phase 2 Complete! ✓"
echo "========================================="
