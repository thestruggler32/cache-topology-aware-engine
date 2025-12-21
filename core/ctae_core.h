/* CTAE Core Module Header
 * Cache-Topology-Aware Execution Engine
 * 
 * Purpose: Define cache topology data structures and API
 * Architecture: x86_64
 * Kernel: Linux 5.15+
 */

#ifndef _CTAE_CORE_H
#define _CTAE_CORE_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/cpumask.h>
#include <linux/spinlock.h>

/* Module metadata */
#define CTAE_VERSION "0.1.0"
#define CTAE_MODULE_NAME "ctae_core"

/* Cache level definitions */
#define CTAE_CACHE_L1D 1
#define CTAE_CACHE_L1I 2
#define CTAE_CACHE_L2  3
#define CTAE_CACHE_L3  4

/* Maximum cache domains we expect */
#define CTAE_MAX_CACHE_DOMAINS 64

/* Cache topology node
 * Represents a single cache domain (e.g., one L3 cache)
 * Contains a list of CPU cores that share this cache
 */
struct ctae_cache_domain {
	struct list_head list;           /* Kernel linked list node */
	unsigned int domain_id;          /* Unique domain identifier */
	unsigned int cache_level;        /* Cache level (L2=3, L3=4) */
	unsigned int cache_size_kb;      /* Cache size in KB */
	unsigned int cache_line_size;    /* Cache line size in bytes */
	unsigned int associativity;      /* N-way associativity */
	cpumask_var_t cpu_mask;          /* CPUs sharing this cache */
	unsigned int num_cpus;           /* Number of CPUs in domain */
	struct list_head cpu_list;       /* List of ctae_cpu_node */
};

/* Per-CPU node within a cache domain */
struct ctae_cpu_node {
	struct list_head list;           /* List linkage */
	unsigned int cpu_id;             /* Logical CPU ID */
	unsigned int apic_id;            /* APIC ID from hardware */
	unsigned int socket_id;          /* Physical socket */
	unsigned int core_id;            /* Physical core ID */
	unsigned int thread_id;          /* SMT thread ID */
	struct ctae_cache_domain *parent_domain; /* Backpointer */
};

/* Global topology state */
struct ctae_topology {
	struct list_head cache_domains;  /* List of cache domains */
	unsigned int num_domains;        /* Total cache domains */
	unsigned int num_cpus;           /* Total logical CPUs */
	bool initialized;                /* Topology discovered */
	spinlock_t lock;                 /* Protects topology data */
};

/* Global topology instance (defined in ctae_core.c) */
extern struct ctae_topology *ctae_global_topology;

/* Function prototypes */
int ctae_topology_init(void);
void ctae_topology_cleanup(void);
int ctae_discover_cache_topology(void);
void ctae_print_topology(void);

/* Cache domain lookup functions */
struct ctae_cache_domain *ctae_find_domain_by_cpu(unsigned int cpu_id);
struct ctae_cache_domain *ctae_find_domain_by_id(unsigned int domain_id);

/* CPU information extraction from CPUID */
int ctae_get_cpu_apic_id(unsigned int cpu, unsigned int *apic_id);
int ctae_get_cpu_topology_info(unsigned int cpu, unsigned int *socket,
                                unsigned int *core, unsigned int *thread);

/* Cache information from CPUID leaf 0x4 (Deterministic Cache Parameters) */
struct ctae_cache_info {
	unsigned int level;
	unsigned int type;
	unsigned int size_kb;
	unsigned int line_size;
	unsigned int associativity;
	unsigned int num_sharing;
};

int ctae_get_cache_info(unsigned int cpu, unsigned int cache_level,
                        struct ctae_cache_info *info);

#endif /* _CTAE_CORE_H */