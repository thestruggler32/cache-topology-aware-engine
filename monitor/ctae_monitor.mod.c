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

KSYMTAB_DATA(ctae_global_monitor, "", "");
KSYMTAB_FUNC(ctae_pmu_setup_events, "", "");
KSYMTAB_FUNC(ctae_pmu_cleanup_events, "", "");
KSYMTAB_FUNC(ctae_pmu_sample_cpu, "", "");
KSYMTAB_FUNC(ctae_pmu_update_stats, "", "");
KSYMTAB_FUNC(ctae_pmu_sample_all, "", "");
KSYMTAB_FUNC(ctae_detect_contention, "", "");
KSYMTAB_FUNC(ctae_check_all_contention, "", "");
KSYMTAB_FUNC(ctae_get_cpu_stats, "", "");
KSYMTAB_FUNC(ctae_print_stats, "", "");
KSYMTAB_FUNC(ctae_print_all_stats, "", "");
KSYMTAB_FUNC(ctae_monitor_start, "", "");
KSYMTAB_FUNC(ctae_monitor_stop, "", "");

SYMBOL_CRC(ctae_global_monitor, 0x7c6a7924, "");
SYMBOL_CRC(ctae_pmu_setup_events, 0x47559d93, "");
SYMBOL_CRC(ctae_pmu_cleanup_events, 0x5fb56b29, "");
SYMBOL_CRC(ctae_pmu_sample_cpu, 0x5fb56b29, "");
SYMBOL_CRC(ctae_pmu_update_stats, 0x5fb56b29, "");
SYMBOL_CRC(ctae_pmu_sample_all, 0xd272d446, "");
SYMBOL_CRC(ctae_detect_contention, 0x724a72ea, "");
SYMBOL_CRC(ctae_check_all_contention, 0xd272d446, "");
SYMBOL_CRC(ctae_get_cpu_stats, 0xadc9db83, "");
SYMBOL_CRC(ctae_print_stats, 0x5fb56b29, "");
SYMBOL_CRC(ctae_print_all_stats, 0xd272d446, "");
SYMBOL_CRC(ctae_monitor_start, 0x7851be11, "");
SYMBOL_CRC(ctae_monitor_stop, 0x7851be11, "");

static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xd272d446, "__fentry__" },
	{ 0x5ae9ee26, "__per_cpu_offset" },
	{ 0xe1e1f979, "_raw_spin_lock_irqsave" },
	{ 0x81a1a811, "_raw_spin_unlock_irqrestore" },
	{ 0xd272d446, "__x86_return_thunk" },
	{ 0x90a48d82, "__ubsan_handle_out_of_bounds" },
	{ 0xf296206e, "nr_cpu_ids" },
	{ 0x4e808bc3, "perf_event_create_kernel_counter" },
	{ 0x3b5d7a5d, "perf_event_enable" },
	{ 0xe8213e80, "_printk" },
	{ 0xd272d446, "__stack_chk_fail" },
	{ 0x3b5d7a5d, "perf_event_disable" },
	{ 0xd69caeff, "perf_event_release_kernel" },
	{ 0xb5c51982, "__cpu_online_mask" },
	{ 0x86632fd6, "_find_next_bit" },
	{ 0x534ed5f3, "__msecs_to_jiffies" },
	{ 0x058c185a, "jiffies" },
	{ 0x32feeafc, "mod_timer" },
	{ 0x2352b148, "timer_delete_sync" },
	{ 0x003b23f9, "single_open" },
	{ 0xe4de56b4, "__ubsan_handle_load_invalid_value" },
	{ 0xf2c4f3f1, "seq_printf" },
	{ 0x690cdb06, "free_percpu" },
	{ 0xcb8b6ec6, "kfree" },
	{ 0x2656c3dc, "debugfs_remove" },
	{ 0x97065e7f, "perf_event_read_value" },
	{ 0x97acb853, "ktime_get" },
	{ 0xbd03ed67, "random_kmalloc_seed" },
	{ 0xfed1e3bc, "kmalloc_caches" },
	{ 0x70db3fe4, "__kmalloc_cache_noprof" },
	{ 0x23e7cd4a, "pcpu_alloc_noprof" },
	{ 0xb5c51982, "__cpu_possible_mask" },
	{ 0x02f9bbf0, "init_timer_key" },
	{ 0x28b4e1ee, "debugfs_create_dir" },
	{ 0x151b3730, "debugfs_create_file_full" },
	{ 0xfc8fa4ce, "seq_lseek" },
	{ 0xbd4e501f, "seq_read" },
	{ 0xcb077514, "single_release" },
	{ 0xba157484, "module_layout" },
};

static const u32 ____version_ext_crcs[]
__used __section("__version_ext_crcs") = {
	0xd272d446,
	0x5ae9ee26,
	0xe1e1f979,
	0x81a1a811,
	0xd272d446,
	0x90a48d82,
	0xf296206e,
	0x4e808bc3,
	0x3b5d7a5d,
	0xe8213e80,
	0xd272d446,
	0x3b5d7a5d,
	0xd69caeff,
	0xb5c51982,
	0x86632fd6,
	0x534ed5f3,
	0x058c185a,
	0x32feeafc,
	0x2352b148,
	0x003b23f9,
	0xe4de56b4,
	0xf2c4f3f1,
	0x690cdb06,
	0xcb8b6ec6,
	0x2656c3dc,
	0x97065e7f,
	0x97acb853,
	0xbd03ed67,
	0xfed1e3bc,
	0x70db3fe4,
	0x23e7cd4a,
	0xb5c51982,
	0x02f9bbf0,
	0x28b4e1ee,
	0x151b3730,
	0xfc8fa4ce,
	0xbd4e501f,
	0xcb077514,
	0xba157484,
};
static const char ____version_ext_names[]
__used __section("__version_ext_names") =
	"__fentry__\0"
	"__per_cpu_offset\0"
	"_raw_spin_lock_irqsave\0"
	"_raw_spin_unlock_irqrestore\0"
	"__x86_return_thunk\0"
	"__ubsan_handle_out_of_bounds\0"
	"nr_cpu_ids\0"
	"perf_event_create_kernel_counter\0"
	"perf_event_enable\0"
	"_printk\0"
	"__stack_chk_fail\0"
	"perf_event_disable\0"
	"perf_event_release_kernel\0"
	"__cpu_online_mask\0"
	"_find_next_bit\0"
	"__msecs_to_jiffies\0"
	"jiffies\0"
	"mod_timer\0"
	"timer_delete_sync\0"
	"single_open\0"
	"__ubsan_handle_load_invalid_value\0"
	"seq_printf\0"
	"free_percpu\0"
	"kfree\0"
	"debugfs_remove\0"
	"perf_event_read_value\0"
	"ktime_get\0"
	"random_kmalloc_seed\0"
	"kmalloc_caches\0"
	"__kmalloc_cache_noprof\0"
	"pcpu_alloc_noprof\0"
	"__cpu_possible_mask\0"
	"init_timer_key\0"
	"debugfs_create_dir\0"
	"debugfs_create_file_full\0"
	"seq_lseek\0"
	"seq_read\0"
	"single_release\0"
	"module_layout\0"
;

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "436119EB3EEB882B8510B8E");
