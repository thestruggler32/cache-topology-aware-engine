/* CTAE Monitor Module Header
 * Cache-Topology-Aware Execution Engine - PMU Monitoring
 * 
 * Purpose: Track LLC misses and cache contention using Performance Monitoring
 * Architecture: x86_64 Intel Performance Monitoring Counters (PMC)
 * Kernel: Linux 5.15+
 */

#ifndef _CTAE_MONITOR_H
#define _CTAE_MONITOR_H

#include <linux/types.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

/* Module metadata */
#define CTAE_MONITOR_VERSION "0.1.0"

/* Performance counter event types */
#define CTAE_PMU_LLC_MISSES       0  /* Last Level Cache misses */
#define CTAE_PMU_LLC_REFERENCES   1  /* LLC references (hits + misses) */
#define CTAE_PMU_INSTRUCTIONS     2  /* Instructions retired */
#define CTAE_PMU_CYCLES           3  /* CPU cycles */

#define CTAE_PMU_MAX_EVENTS       4

/* Monitoring sample period (in milliseconds) */
#define CTAE_MONITOR_PERIOD_MS    100

/* Contention thresholds */
#define CTAE_LLC_MISS_RATE_THRESHOLD  50  /* 50 per 1000 (5%) triggers alert */
#define CTAE_HIGH_CONTENTION_THRESHOLD 100000 /* Delta misses per sample */

/* Per-CPU performance statistics */
struct ctae_pmu_stats {
	u64 llc_misses;           /* Total LLC misses */
	u64 llc_references;       /* Total LLC references */
	u64 instructions;         /* Instructions retired */
	u64 cycles;               /* CPU cycles */
	
	/* Derived metrics */
	u64 llc_miss_rate;        /* Misses per 1000 references */
	u64 ipc;                  /* Instructions per cycle (x1000) */
	
	/* Delta counters (since last sample) */
	u64 delta_llc_misses;
	u64 delta_llc_references;
	
	/* Timestamps */
	u64 last_sample_time;     /* nanoseconds */
	u64 sample_count;
	
	/* Contention detection */
	bool high_contention;     /* Exceeds threshold */
};

/* Per-CPU monitoring context */
struct ctae_cpu_monitor {
	unsigned int cpu_id;
	struct perf_event *events[CTAE_PMU_MAX_EVENTS];
	struct ctae_pmu_stats stats;
	struct ctae_pmu_stats prev_stats;  /* Previous sample for deltas */
	spinlock_t lock;
};

/* Global monitoring state */
struct ctae_monitor_state {
	struct ctae_cpu_monitor __percpu *cpu_monitors;
	struct timer_list sampling_timer;
	unsigned int monitoring_enabled;
	unsigned int sample_period_ms;
	spinlock_t lock;
};

/* Global monitor instance */
extern struct ctae_monitor_state *ctae_global_monitor;

/* Function prototypes */

/* Initialization and cleanup */
int ctae_monitor_init(void);
void ctae_monitor_cleanup(void);

/* Monitoring control */
int ctae_monitor_start(void);
int ctae_monitor_stop(void);

/* PMU event setup */
int ctae_pmu_setup_events(unsigned int cpu);
void ctae_pmu_cleanup_events(unsigned int cpu);

/* Sampling and statistics */
void ctae_pmu_sample_all(void);
void ctae_pmu_sample_cpu(unsigned int cpu);
void ctae_pmu_update_stats(unsigned int cpu);

/* Contention detection */
bool ctae_detect_contention(unsigned int cpu);
void ctae_check_all_contention(void);

/* Statistics access */
int ctae_get_cpu_stats(unsigned int cpu, struct ctae_pmu_stats *stats);
void ctae_print_stats(unsigned int cpu);
void ctae_print_all_stats(void);

/* Helper: Read performance counter */
static inline u64 ctae_read_perf_counter(struct perf_event *event)
{
	u64 count = 0;
	u64 enabled, running;
	
	if (!event)
		return 0;
	
	count = perf_event_read_value(event, &enabled, &running);
	
	/* Adjust for scaling if counter was not always running */
	if (running && running < enabled) {
		count = (count * enabled) / running;
	}
	
	return count;
}

#endif /* _CTAE_MONITOR_H */