// fx-bootstrap.c
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/kernel.h>
#include <linux/io.h>
#include <linux/kprobes.h>
#include <linux/stddef.h>          // offsetof
#include <linux/sched.h>
#include <linux/sched/signal.h>    // struct task_struct, TASK_COMM_LEN
#include <linux/errno.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/preempt.h>

#include <asm/special_insns.h>   /* __read_cr3/read_cr3, native_read_cr4 */
#include <asm/processor.h>       /* read_cr3(), in alcuni kernel */
#include <asm/page_types.h>      /* PAGE_OFFSET / __PAGE_OFFSET_BASE */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Simone Conti");
MODULE_DESCRIPTION("FX bootstrap one-shot: sends kernel layout info to VMM then self-unloads");

/************************************************
 * Device IDs / BAR
 ************************************************/
#define VENDOR_ID   0x1234
#define DEVICE_ID   0x0609
#define BAR         0

/************************************************
 * Hypercall ABI (must match host side)
 ************************************************/
#define HYPERCALL_OFFSET                0x80
#define BOOTSTRAP_INFO_HYPERCALL        13

/************************************************
 * Payload sent to VMM
 ************************************************/
struct fx_bootstrap_info {
    u64 init_task_addr;      // address of init_task symbol

    /* task_struct layout */
    u32 off_tasks;           // offsetof(task_struct, tasks)
    u32 off_pid;             // offsetof(task_struct, pid)
    u32 off_comm;            // offsetof(task_struct, comm)
    u32 comm_len;            // TASK_COMM_LEN

    /* paging context hints (for VA->PA translation / mapping) */
    u64 kernel_cr3_pa;       // native_read_cr3() masked to 4K base
    u64 kernel_cr4;          // native_read_cr4()
    u32 la57;                // CR4.LA57 (0/1)
    u32 pcid;                // CR4.PCIDE (0/1)

    /* best-effort sanity checks / constants */
    u64 init_task_pa;        // __pa(init_task_addr) best-effort
    u64 physmap_base_va;     // __PAGE_OFFSET_BASE (direct map base)

    /* guest memory size hint (for mapping physmap fully) */
    u64 physmap_size;        // max_pfn << PAGE_SHIFT (best effort)

    /* kernel image mapping (VA->PA without guest page tables) */
    u64 kernel_text_va;      // _stext VA
    u64 kernel_text_pa;     // _stext PA (phys_base + offset)
    u64 kernel_end_va;       // _end VA

    /* vmalloc area (range only; not linearly translatable) */
    u64 vmalloc_start;
    u64 vmalloc_end;

    u32 task_struct_size;    // sizeof(struct task_struct)
} __packed;

/************************************************
 * Minimal kprobe trick to get kallsyms_lookup_name
 ************************************************/
static unsigned long kln_addr;
static unsigned long (*kallsyms_lookup_name_ptr)(const char *name);

static int __kprobes pre0(struct kprobe *p, struct pt_regs *regs)
{
    /* double-kprobe trick: grab kallsyms_lookup_name address */
    kln_addr = (--regs->ip);
    return 0;
}

static int __kprobes pre1(struct kprobe *p, struct pt_regs *regs)
{
    return 0;
}

static int init_kallsyms_lookup_name(void)
{
    int ret;
    static struct kprobe kp0 = {
        .symbol_name = "kallsyms_lookup_name",
        .pre_handler = pre0,
    };
    static struct kprobe kp1 = {
        .symbol_name = "kallsyms_lookup_name",
        .pre_handler = pre1,
    };

    ret = register_kprobe(&kp0);
    if (ret)
        return ret;

    ret = register_kprobe(&kp1);
    if (ret) {
        unregister_kprobe(&kp0);
        return ret;
    }

    unregister_kprobe(&kp0);
    unregister_kprobe(&kp1);

    if (!kln_addr)
        return -ENOENT;

    kallsyms_lookup_name_ptr = (void *)kln_addr;
    return 0;
}

/************************************************
 * MMIO base (BAR mapping)
 ************************************************/
static void __iomem *mmio;

/************************************************
 * Hypercall primitive 
 ************************************************/
static void generic_hypercall(unsigned int type, void *addr, unsigned int size, unsigned int flag)
{
    __asm__ volatile(
        "mfence\n\t"
        "mov %0, %%r8\n\t"
        "movl %1, %%r9d\n\t"
        "mov %2, %%r10\n\t"
        "mov %3, %%r11\n\t"
        "movl %4, %%r12d\n\t"
        "movq $1, (%%r11)\n\t"
        :
        : "r"(addr),
          "r"(size),
          "r"((unsigned long)type),
          "r"(mmio + HYPERCALL_OFFSET),
          "r"(flag)
        : "r8", "r9", "r10", "r11", "r12", "memory");
}


static inline u64 fx_read_cr3_raw(void)
{
    /*
     * Kernel-API differences:
     * - some expose read_cr3()
     * - others expose __read_cr3()
     */
#if defined(read_cr3)
    return (u64)read_cr3();
#else
    return (u64)__read_cr3();
#endif
}

static inline u64 fx_page_offset_base(void)
{
#ifdef __PAGE_OFFSET_BASE
    return (u64)__PAGE_OFFSET_BASE;
#elif defined(PAGE_OFFSET)
    return (u64)PAGE_OFFSET;
#else
    return 0; /* best-effort fallback, should not happen on x86_64 */
#endif
}



/************************************************
 * One-shot init: collect -> send -> cleanup -> self-unload
 ************************************************/
static int __init fx_bootstrap_init(void)
{
    int ret;
    struct pci_dev *pdev = NULL;
    void __iomem *bar = NULL;

    struct fx_bootstrap_info info;
    unsigned long init_task_sym;
    unsigned long sym;
    u64 tmp;
    memset(&info, 0, sizeof(info));

    /* 1) Resolve kallsyms_lookup_name */
    ret = init_kallsyms_lookup_name();
    if (ret) {
        //pr_err("fx-bootstrap: failed to init kallsyms_lookup_name (%d)\n", ret);
        return ret;
    }

    /* 2) Resolve init_task symbol address */
    init_task_sym = kallsyms_lookup_name_ptr("init_task");
    if (!init_task_sym) {
        //pr_err("fx-bootstrap: kallsyms_lookup_name(\"init_task\") failed\n");
        return -ENOENT;
    }

    /* 3) Fill bootstrap info (layout) */
    info.init_task_addr   = (u64)init_task_sym;
    info.off_tasks        = (u32)offsetof(struct task_struct, tasks);
    info.off_pid          = (u32)offsetof(struct task_struct, pid);
    info.off_comm         = (u32)offsetof(struct task_struct, comm);
    info.comm_len         = (u32)TASK_COMM_LEN;

        /* paging context (best effort) */
    preempt_disable();
    {
        u64 cr3 = fx_read_cr3_raw();
        u64 cr4 = native_read_cr4();

        info.kernel_cr3_pa = cr3 & ~0xfffULL;
        info.kernel_cr4    = cr4;

    #ifdef X86_CR4_LA57
        info.la57 = !!(cr4 & X86_CR4_LA57);
    #else
        info.la57 = 0;
    #endif

    #ifdef X86_CR4_PCIDE
        info.pcid = !!(cr4 & X86_CR4_PCIDE);
    #else
        info.pcid = 0;
    #endif
    }
    preempt_enable();

    info.init_task_pa  = (u64)__pa((void *)info.init_task_addr);
    info.physmap_base_va = fx_page_offset_base();
    info.task_struct_size = (u32)sizeof(struct task_struct);
    /*
     * Extra layout info for hyper-owned page tables (bootstrap is trusted):
     *  - physmap_size: used to map direct-map fully without using guest CR3
     *  - kernel image mapping: _stext/_end + phys_base
     *  - vmalloc range: guardrail / future work
     */

    /* physmap_size from max_pfn (best effort via kallsyms) */
    sym = kallsyms_lookup_name_ptr("max_pfn");
    if (sym) {
        /* max_pfn is usually unsigned long */
        tmp = *(unsigned long *)sym;
        info.physmap_size = tmp << PAGE_SHIFT;
    } else {
        info.physmap_size = 0;
    }

    /* kernel image VA range: _stext .. _end */
    sym = kallsyms_lookup_name_ptr("_stext");
    info.kernel_text_va = sym ? (u64)sym : 0;
    sym = kallsyms_lookup_name_ptr("_end");
    info.kernel_end_va  = sym ? (u64)sym : 0;


    /*
     * Robust kernel image PA anchor:
     * Use __pa_symbol(_stext) instead of phys_base.
     */
    if (info.kernel_text_va) {
        info.kernel_text_pa = (u64)__pa_symbol((void *)info.kernel_text_va);
    } else {
        info.kernel_text_pa = 0;
    }

    /* vmalloc range macros (x86_64) */
#ifdef VMALLOC_START
    info.vmalloc_start = (u64)VMALLOC_START;
#else
    info.vmalloc_start = 0;
#endif
#ifdef VMALLOC_END
    info.vmalloc_end   = (u64)VMALLOC_END;
#else
    info.vmalloc_end   = 0;
#endif
    /* 4) Locate FX device and map BAR */
    pdev = pci_get_device(VENDOR_ID, DEVICE_ID, NULL);
    if (!pdev) {
        //pr_err("fx-bootstrap: FX device %04x:%04x not found\n", VENDOR_ID, DEVICE_ID);
        return -ENODEV;
    }
    
    ret = pci_enable_device(pdev);
    if (ret) {
        //pr_err("fx-bootstrap: pci_enable_device failed (%d)\n", ret);
        pci_dev_put(pdev);
        return ret;
    }

    ret = pci_request_region(pdev, BAR, "fx-bootstrap");
    if (ret) {
        //pr_err("fx-bootstrap: pci_request_region failed (%d)\n", ret);
        pci_disable_device(pdev);
        pci_dev_put(pdev);
        return ret;
    }

    bar = pci_iomap(pdev, BAR, pci_resource_len(pdev, BAR));
    if (!bar) {
        //pr_err("fx-bootstrap: pci_iomap failed\n");
        pci_release_region(pdev, BAR);
        pci_disable_device(pdev);
        pci_dev_put(pdev);
        return -ENOMEM;
    }

    mmio = bar;

    /* 5) Send to VMM */

    //print the struct we send
    pr_info("Information sent to VMM: init_task_addr=0x%llx off_tasks=0x%x off_pid=0x%x off_comm=0x%x comm_len=0x%x kernel_cr3_pa=0x%llx kernel_cr4=0x%llx la57=0x%x pcid=0x%x init_task_pa=0x%llx physmap_base_va=0x%llx physmap_size=0x%llx kernel_text_va=0x%llx kernel_end_va=0x%llx kernel_text_pa=0x%llx\n",
             info.init_task_addr, info.off_tasks, info.off_pid, info.off_comm, info.comm_len,
             info.kernel_cr3_pa, info.kernel_cr4, info.la57, info.pcid, info.init_task_pa,
             info.physmap_base_va, info.physmap_size, info.kernel_text_va, info.kernel_end_va,
             info.kernel_text_pa);
    generic_hypercall(BOOTSTRAP_INFO_HYPERCALL, &info, sizeof(info), 0);

    /* 6) Cleanup (leave no handlers/threads) */
    pci_iounmap(pdev, bar);
    pci_release_region(pdev, BAR);
    pci_disable_device(pdev);
    pci_dev_put(pdev);
	
	
	return 0;
}

static void __exit fx_bootstrap_exit(void)
{
}


module_init(fx_bootstrap_init);
module_exit(fx_bootstrap_exit);
