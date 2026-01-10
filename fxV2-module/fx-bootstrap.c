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
    u32 off_tasks;           // offsetof(task_struct, tasks)
    u32 off_pid;             // offsetof(task_struct, pid)
    u32 off_comm;            // offsetof(task_struct, comm)
    u32 comm_len;            // TASK_COMM_LEN
    u32 task_struct_size;    // sizeof(struct task_struct)
    u32 abi;                 // versioning
    u32 reserved;
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
    pr_info("[FX] generic_hypercall: type=%u addr=%px size=0x%x flag=0x%x\n",
            type, addr, size, flag);
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

    memset(&info, 0, sizeof(info));

    /* 1) Resolve kallsyms_lookup_name */
    ret = init_kallsyms_lookup_name();
    if (ret) {
        pr_err("fx-bootstrap: failed to init kallsyms_lookup_name (%d)\n", ret);
        return ret;
    }

    /* 2) Resolve init_task symbol address */
    init_task_sym = kallsyms_lookup_name_ptr("init_task");
    if (!init_task_sym) {
        pr_err("fx-bootstrap: kallsyms_lookup_name(\"init_task\") failed\n");
        return -ENOENT;
    }

    /* 3) Fill bootstrap info (layout) */
    info.init_task_addr   = (u64)init_task_sym;
    info.off_tasks        = (u32)offsetof(struct task_struct, tasks);
    info.off_pid          = (u32)offsetof(struct task_struct, pid);
    info.off_comm         = (u32)offsetof(struct task_struct, comm);
    info.comm_len         = (u32)TASK_COMM_LEN;
    info.task_struct_size = (u32)sizeof(struct task_struct);
    info.abi              = 1;

    /* 4) Locate FX device and map BAR */
    pdev = pci_get_device(VENDOR_ID, DEVICE_ID, NULL);
    if (!pdev) {
        pr_err("fx-bootstrap: FX device %04x:%04x not found\n", VENDOR_ID, DEVICE_ID);
        return -ENODEV;
    }

    /*if(pci_enable_device(pdev) < 0){
        dev_err(&(pdev->dev), "error in pci_enable_device\n");
        return -1;
    }

    if(pci_request_region(pdev, BAR, "myregion0")){
		dev_err(&(pdev->dev), "error in pci_request_region\n");
		return -1;
	}

    mmio = pci_iomap(pdev, BAR, pci_resource_len(pdev, BAR));
    if (!mmio) {
        dev_err(&(pdev->dev), "error in pci_iomap\n");
        pci_release_region(pdev, BAR);
        return -1;
    }*/
    
    ret = pci_enable_device(pdev);
    if (ret) {
        pr_err("fx-bootstrap: pci_enable_device failed (%d)\n", ret);
        pci_dev_put(pdev);
        return ret;
    }

    ret = pci_request_region(pdev, BAR, "fx-bootstrap");
    if (ret) {
        pr_err("fx-bootstrap: pci_request_region failed (%d)\n", ret);
        pci_disable_device(pdev);
        pci_dev_put(pdev);
        return ret;
    }

    bar = pci_iomap(pdev, BAR, pci_resource_len(pdev, BAR));
    if (!bar) {
        pr_err("fx-bootstrap: pci_iomap failed\n");
        pci_release_region(pdev, BAR);
        pci_disable_device(pdev);
        pci_dev_put(pdev);
        return -ENOMEM;
    }

    mmio = bar;

    /* 5) Send to VMM */
    pr_info("fx-bootstrap: sending init_task=%px off_tasks=0x%x off_pid=0x%x off_comm=0x%x\n",
            (void *)info.init_task_addr, info.off_tasks, info.off_pid, info.off_comm);

    generic_hypercall(BOOTSTRAP_INFO_HYPERCALL, &info, sizeof(info), 0);

    /* 6) Cleanup (leave no handlers/threads) */
    pci_iounmap(pdev, bar);
    pci_release_region(pdev, BAR);
    pci_disable_device(pdev);
    pci_dev_put(pdev);

    /*
     * 7) Self-unload: return an error from init
     * Kernel will free module automatically -> no residual module loaded.
     */
    return -EAGAIN;
}

module_init(fx_bootstrap_init);
