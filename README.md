# Cache-Topology-Aware Execution Engine (CTAE)

![Platform](https://img.shields.io/badge/platform-Linux%20Kernel-black)
![Language](https://img.shields.io/badge/language-C-blue)
![Status](https://img.shields.io/badge/status-Research%20Prototype-orange)

## ⚡ Overview
**CTAE** is a custom Linux Kernel Module (LKM) designed to solve the "Noisy Neighbor" problem in multicore processors.

Standard operating system schedulers (like Linux CFS) prioritize fairness and load balancing but often ignore **micro-architectural topology**. This leads to **Last-Level Cache (LLC) contention**, where threads executing on adjacent cores destroy each other's cache lines, significantly degrading IPC (Instructions Per Cycle).

CTAE bridges this gap by introducing a **dynamic feedback loop** into the OS kernel. It continuously monitors hardware signals and physically rebinds threads to optimal "Cache Domains" in real-time.

## 🚀 Key Features
* **Topology Discovery:** Automatically maps the CPU hierarchy to identify which logical cores share L1, L2, and L3 caches.
* **Hardware Profiling:** Uses the **PMU (Performance Monitoring Unit)** to track LLC Misses and cache coherence traffic with negligible overhead.
* **Dynamic Migration:** Intelligently migrates "cache-thrashing" threads to isolated cores to preserve data locality.
* **Kernel-Level Execution:** Runs entirely in Ring 0 for maximum performance and direct hardware access.

## 🛠️ Architecture
The system is composed of three main subsystems:

```text
[ Hardware Layer (CPU Cores & L3 Cache) ]
           ^
           | (PMU Signals)
[ Monitor Subsystem ] <--- Reads Cache Misses per PID
           |
[ Policy Engine ] <------- "Should we move this thread?"
           |
[ Migration Mechanism ] -> Calls set_cpus_allowed_ptr()