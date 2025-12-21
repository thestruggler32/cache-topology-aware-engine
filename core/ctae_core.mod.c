#include <linux/module.h>
#include <linux/export-internal.h>
#include <linux/compiler.h>

MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

KSYMTAB_DATA(ctae_global_topology, "", "");
KSYMTAB_FUNC(ctae_get_cpu_apic_id, "", "");
KSYMTAB_FUNC(ctae_get_cpu_topology_info, "", "");
KSYMTAB_FUNC(ctae_get_cache_info, "", "");
KSYMTAB_FUNC(ctae_discover_cache_topology, "", "");
KSYMTAB_FUNC(ctae_print_topology, "", "");
KSYMTAB_FUNC(ctae_find_domain_by_cpu, "", "");
KSYMTAB_FUNC(ctae_find_domain_by_id, "", "");

SYMBOL_CRC(ctae_global_topology, 0xc1e90c72, "");
SYMBOL_CRC(ctae_get_cpu_apic_id, 0xbbb7337a, "");
SYMBOL_CRC(ctae_get_cpu_topology_info, 0xb2624169, "");
SYMBOL_CRC(ctae_get_cache_info, 0x8fc7e9fd, "");
SYMBOL_CRC(ctae_discover_cache_topology, 0x7851be11, "");
SYMBOL_CRC(ctae_print_topology, 0xd272d446, "");
SYMBOL_CRC(ctae_find_domain_by_cpu, 0x8d184670, "");
SYMBOL_CRC(ctae_find_domain_by_id, 0x93d8ec0f, "");

static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xd272d446, "__fentry__" },
	{ 0xd272d446, "__x86_return_thunk" },
	{ 0xb1ad3f2f, "cpu_info" },
	{ 0x5ae9ee26, "__per_cpu_offset" },
	{ 0x1a972197, "cpu_sibling_map" },
	{ 0xf296206e, "nr_cpu_ids" },
	{ 0x3a645690, "__bitmap_weight" },
	{ 0x90a48d82, "__ubsan_handle_out_of_bounds" },
	{ 0xde338d9a, "_raw_spin_lock" },
	{ 0xde338d9a, "_raw_spin_unlock" },
	{ 0xe4de56b4, "__ubsan_handle_load_invalid_value" },
	{ 0xe8213e80, "_printk" },
	{ 0xcb8b6ec6, "kfree" },
	{ 0x02b7fa5b, "free_cpumask_var" },
	{ 0x318e45ff, "filp_open" },
	{ 0x4cd313ad, "kernel_read" },
	{ 0xdb9a5310, "filp_close" },
	{ 0x2182515b, "__num_online_cpus" },
	{ 0xbd03ed67, "random_kmalloc_seed" },
	{ 0xfed1e3bc, "kmalloc_caches" },
	{ 0x70db3fe4, "__kmalloc_cache_noprof" },
	{ 0xf2aabb37, "alloc_cpumask_var_node" },
	{ 0xb5c51982, "__cpu_online_mask" },
	{ 0x86632fd6, "_find_next_bit" },
	{ 0x173ec8da, "sscanf" },
	{ 0xd272d446, "__stack_chk_fail" },
	{ 0xfab79d64, "init_uts_ns" },
	{ 0xba157484, "module_layout" },
};

static const u32 ____version_ext_crcs[]
__used __section("__version_ext_crcs") = {
	0xd272d446,
	0xd272d446,
	0xb1ad3f2f,
	0x5ae9ee26,
	0x1a972197,
	0xf296206e,
	0x3a645690,
	0x90a48d82,
	0xde338d9a,
	0xde338d9a,
	0xe4de56b4,
	0xe8213e80,
	0xcb8b6ec6,
	0x02b7fa5b,
	0x318e45ff,
	0x4cd313ad,
	0xdb9a5310,
	0x2182515b,
	0xbd03ed67,
	0xfed1e3bc,
	0x70db3fe4,
	0xf2aabb37,
	0xb5c51982,
	0x86632fd6,
	0x173ec8da,
	0xd272d446,
	0xfab79d64,
	0xba157484,
};
static const char ____version_ext_names[]
__used __section("__version_ext_names") =
	"__fentry__\0"
	"__x86_return_thunk\0"
	"cpu_info\0"
	"__per_cpu_offset\0"
	"cpu_sibling_map\0"
	"nr_cpu_ids\0"
	"__bitmap_weight\0"
	"__ubsan_handle_out_of_bounds\0"
	"_raw_spin_lock\0"
	"_raw_spin_unlock\0"
	"__ubsan_handle_load_invalid_value\0"
	"_printk\0"
	"kfree\0"
	"free_cpumask_var\0"
	"filp_open\0"
	"kernel_read\0"
	"filp_close\0"
	"__num_online_cpus\0"
	"random_kmalloc_seed\0"
	"kmalloc_caches\0"
	"__kmalloc_cache_noprof\0"
	"alloc_cpumask_var_node\0"
	"__cpu_online_mask\0"
	"_find_next_bit\0"
	"sscanf\0"
	"__stack_chk_fail\0"
	"init_uts_ns\0"
	"module_layout\0"
;

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "465AF18A8D1C736FC531BC9");
