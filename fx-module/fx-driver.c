#include <linux/module.h>
#include <linux/pci.h>
#include <linux/kernel.h>
#include <asm/desc.h>
#include <linux/irq.h>
#include <linux/interrupt.h> 
#include <linux/kprobes.h>
#include <linux/kernel.h>
#include <linux/sched/signal.h>
#include <linux/pgtable.h>
#include <asm/msr.h>

#include <linux/init.h>
#include <linux/sched.h> 
#include <linux/rcupdate.h>
#include <linux/fdtable.h>
#include <linux/fs.h> 
#include <linux/fs_struct.h>
#include <linux/dcache.h>
#include <linux/slab.h>
#include <linux/net.h>
#include <linux/workqueue.h>
#include <linux/atomic.h>
#include <net/sock.h>
#include <linux/io.h>
#include <linux/uaccess.h>
#include <linux/memremap.h>
#include <linux/nospec.h>

MODULE_AUTHOR("Simone Conti");
MODULE_LICENSE("GPL");

/* Debug macro: metti a 0 per disattivare le stampe */
#define FX_DEBUG 1
#if FX_DEBUG
#define FX_DBG(fmt, ...) pr_info("fx: " fmt, ##__VA_ARGS__)
#else
#define FX_DBG(fmt, ...) do { } while (0)
#endif


#define VAULT_DBG 1
#if VAULT_DBG
#define VDBG(fmt, ...) FX_DBG("vault: " fmt, ##__VA_ARGS__)
#else
#define VDBG(fmt, ...) do {} while (0)
#endif
/************************************************
*    PCI constants
************************************************/
#define VENDOR_ID   0x1234
#define DEVICE_ID   0x0609
#define BAR         0

#define ID_REGISTER                 0x00
#define CARD_LIVENESS_REGISTER      0x04
#define SCHEDULE_NEXT_REGISTER      0x08
#define INTERRUPT_STATUS_REGISTER   0x24
#define START_THREAD_REGISTER       0x30
#define INTERRUPT_RAISE_REGISTER    0x60
#define INTERRUPT_ACK_REGISTER      0x64

#define VAULT_OPID_REGISTER          0xA0
#define VAULT_CMD_REGISTER           0xA4
#define VAULT_STATUS_REGISTER        0xA8
#define VAULT_LAST_OPID_REGISTER     0xAC
#define VAULT_SIZE_REGISTER          0xB0
#define VAULT_DATA_RESET_REGISTER    0xB4
#define VAULT_DATA_REGISTER          0xB8
#define VAULT_DLEN_REGISTER          0xBC
#define VAULT_ERR_REGISTER           0xC0  /* read-only */

#define VAULT_MAGIC                  0x30544C56u /* 'V''L''T''0' */
#define VAULT_HDR_SIZE               16
#define VAULT_MAX_PAYLOAD            2048

#define VAULT_CMD_PREPARE            0x1
#define VAULT_CMD_DONE               0x2
#define VAULT_CMD_FAIL               0x3   /* Step 2: explicit fail notification */
#define VAULT_CMD_RESET              0x4   /* Step 3.x: recovery to IDLE */


#define VAULT_STATUS_STATE_MASK      0x3
#define VAULT_STATUS_STATE_IDLE      0x0
#define VAULT_STATUS_STATE_READY     0x1
#define VAULT_STATUS_STATE_ERROR     0x2
#define VAULT_STATUS_BLOB_PRESENT    (1u << 2)
#define VAULT_STATUS_BUSY            (1u << 3)

/* Step 5 (virtio-mem): fixed GPA must match QEMU memaddr */
#define VAULT_MEMADDR_GPA            0x100000000ULL
#define VAULT_VMEM_BLOCK_SIZE        (2 * 1024 * 1024UL)
#define VAULT_MAP_MAX                (2 * 1024 * 1024UL) /* map 2MB at a time (enough for our blob) */

/***********************************************/


/************************************************
*   HYPERCALL constants
*************************************************/
#define HYPERCALL_OFFSET            0x80

#define AGENT_HYPERCALL             1   /* deprecated? */
#define PROTECT_MEMORY_HYPERCALL    2
#define SAVE_MEMORY_HYPERCALL       3
#define COMPARE_MEMORY_HYPERCALL    4
#define SET_IRQ_LINE_HYPERCALL      5
#define START_MONITOR_HYPERCALL     6
#define END_RECORDING_HYPERCALL     7
#define SET_PROCESS_LIST_HYPERCALL  8
#define PROCESS_LIST_HYPERCALL      9
#define START_TIMER_HYPERCALL       10
#define EMPTY_HYPERCALL             11
#define STOP_TIMER_HYPERCALL        12

static void generic_hypercall(unsigned int type, 
                                void *addr, 
                                unsigned int size,
                                unsigned int flag);

#define PROCESS_LIST_SIZE 8192
static char *process_list;
/***********************************************/


/************************************************
*    Kprobes, for accessing all kernel code
************************************************/
#define KPROBE_PRE_HANDLER(fname) \
    static int __kprobes fname(struct kprobe *p, struct pt_regs *regs)
/* kallsym_loop_name address*/
long unsigned kln_addr = 0; 
 /* kallsym_loop_name function pointer */
unsigned long (*kln_pointer)(const char* name);
/* irq_to_desc function pointer */
struct irq_desc *(*i2d_pointer)(int irq); 
/* double-kprobe technique */
static struct kprobe kp0, kp1;

KPROBE_PRE_HANDLER(handler_pre0)
{
  kln_addr = (--regs->ip);
  FX_DBG("handler_pre0: got kallsyms_lookup_name address %px\n",
         (void *)kln_addr);
  return 0;
}

KPROBE_PRE_HANDLER(handler_pre1)
{
  FX_DBG("handler_pre1: second kprobe hit\n");
  return 0;
}
/***********************************************/

static int do_register_kprobe(struct kprobe *kp, char *symbol_name, void *handler)
{
  int ret;
  
  kp->symbol_name = symbol_name;
  kp->pre_handler = handler;
  
  ret = register_kprobe(kp);
  if (ret < 0) 
    pr_err("register_probe() for symbol %s failed, returned %d\n", 
                symbol_name, ret);
  else
    FX_DBG("do_register_kprobe: registered kprobe on %s\n", symbol_name);

  return ret;
}


/************************************************
*    Interrupt handling variables 
************************************************/
static struct pci_dev *pdev; /* PCI device */
static void __iomem *mmio; /* memory mapped I/O */
/* Step 3.1: move heavy logic out of IRQ */
static struct work_struct monitoring_work;
/* 0 = idle, 1 = work scheduled/running */
static atomic_t monitoring_work_inflight = ATOMIC_INIT(0);
static int pci_irq;
static struct irq_desc *irq_desc_pci;
static struct irqaction *irqaction_pci;

static struct pci_device_id pci_ids[] = {
    { PCI_DEVICE(VENDOR_ID, DEVICE_ID), },
    { 0, }
};
MODULE_DEVICE_TABLE(pci, pci_ids);
/***********************************************/

struct vault_hdr {
    u32 magic;
    u32 opid;
    u32 len;
    u32 reserved;
} __packed;



/************************************************
 *  Prototypes
************************************************/
static irqreturn_t fx_irq_handler(int irq, void *dev);
static int pci_probe(struct pci_dev *dev,
                        const struct pci_device_id *id);
static void pci_remove(struct pci_dev *dev);
static void generic_hypercall(unsigned int type, 
                                void *addr, 
                                unsigned int size,
                                unsigned int flag);
static void agent_hypercall(void);
static void walk_irqactions(int irq);
static void list_processes(void);
static void hide_module(void);
static void walk_page_tables_hypercall(unsigned long);
static int init_kallsyms_lookup_name(void);
static void pin_idt_register(void);
static int vault_prepare_v1(u32 opid, u32 want_len);
static void vault_done_v1(void);
static void vault_fail_v1(void);
static int vault_validate_v1(u32 opid, u32 want_len);
static void monitoring_work_fn(struct work_struct *work);
static void vault_reset_v1(void);


static inline u32 vault_status_raw(void)
{
    return ioread32(mmio + VAULT_STATUS_REGISTER);
}

static inline u32 vault_state(void)
{
    return vault_status_raw() & VAULT_STATUS_STATE_MASK;
}

static inline u32 vault_err(void)
{
    return ioread32(mmio + VAULT_ERR_REGISTER);
}

static void vault_dump_status(const char *tag)
{
    u32 st = ioread32(mmio + VAULT_STATUS_REGISTER);
    u32 e  = ioread32(mmio + VAULT_ERR_REGISTER);
    FX_DBG("vault: STATUS[%s]=0x%08x state=%u blob=%u busy=%u ERR=%u\n",
           tag,
           st,
           st & VAULT_STATUS_STATE_MASK,
           !!(st & VAULT_STATUS_BLOB_PRESENT),
           !!(st & VAULT_STATUS_BUSY),
           e);
}

/***********************************************/

static atomic_t vault_opid = ATOMIC_INIT(1);


static irqreturn_t fx_irq_handler(int irq, void *dev)
{
    u32 irq_status;

    FX_DBG("fx_irq_handler: entered, irq=%d\n", irq);

    irq_status = ioread32(mmio + INTERRUPT_STATUS_REGISTER);
    FX_DBG("fx_irq_handler: INTERRUPT_STATUS_REGISTER=0x%x\n", irq_status);

    iowrite32(irq_status, mmio + INTERRUPT_ACK_REGISTER);
    FX_DBG("fx_irq_handler: acknowledged interrupt\n");

    /*
     * Step 3.1: schedule heavy logic in process context.
     * Avoid re-entrancy: if already scheduled/running, skip.
     */
    if (atomic_cmpxchg(&monitoring_work_inflight, 0, 1) == 0) {
        schedule_work(&monitoring_work);
        FX_DBG("fx_irq_handler: scheduled monitoring_work\n");
    } else {
        FX_DBG("fx_irq_handler: monitoring_work already inflight, skipping\n");
    }

    return IRQ_HANDLED;
}

static void monitoring_work_fn(struct work_struct *work)
{
    int vrc;
    u32 opid;
    u32 want_len = 64; /* payload size for now */

    FX_DBG("monitoring_work: start\n");

    /* Step 2: vault gating (fail-closed) */
    opid = (u32)atomic_inc_return(&vault_opid);

    vrc = vault_validate_v1(opid, want_len);
    if (vrc == 0) {
        FX_DBG("vault step2: validation OK (opid=%u)\n", opid);

        list_processes();
        FX_DBG("monitoring_work: list_processes() completed\n"); 
    }else {
        FX_DBG("vault step2: validation FAILED (opid=%u rc=%d). Monitoring blocked.\n", opid, vrc);
        vault_fail_v1();
        /* IMPORTANT: do not run list_processes() */
    }

    /* Keep legacy flow (as before), but now in process context */
    generic_hypercall(END_RECORDING_HYPERCALL, NULL, 0, 0);
    FX_DBG("monitoring_work: END_RECORDING_HYPERCALL issued\n");

    /* schedule next cycle */
    iowrite32(0x1, mmio + SCHEDULE_NEXT_REGISTER);

    /* allow next IRQ to schedule work again */
    atomic_set(&monitoring_work_inflight, 0);

    FX_DBG("monitoring_work: end\n");
}



static int pci_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
    u8 val;
    // unsigned int i;
    pdev = dev;

    FX_DBG("pci_probe: called for device %04x:%04x\n",
           dev->vendor, dev->device);

    if(pci_enable_device(pdev) < 0){
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
    }
    FX_DBG("pci_probe: mmio mapped at %px\n", mmio);
    INIT_WORK(&monitoring_work, monitoring_work_fn);
    atomic_set(&monitoring_work_inflight, 0);
	/* IRQ setup */
	pci_read_config_byte(dev, PCI_INTERRUPT_LINE, &val);
	pci_irq = val;
    FX_DBG("pci_probe: PCI_INTERRUPT_LINE=%d\n", pci_irq);

	if (request_irq(pci_irq, 
                    fx_irq_handler, 
                    0, 
                    "fx_irq_handler", 
                    NULL) < 0) {
		dev_err(&(dev->dev), "request_irq\n");
        pci_iounmap(pdev, mmio);
        pci_release_region(pdev, BAR);
		return -1;
	}

    iowrite32(0x1, mmio + START_THREAD_REGISTER);

    return 0;
}


static void pci_remove(struct pci_dev *dev)
{
	FX_DBG("pci_remove: called for device %04x:%04x\n",
           dev->vendor, dev->device);
    pci_release_region(dev, BAR);
}


static struct pci_driver pci_driver = { 
    .name = "fx_pci",
    .id_table = pci_ids, 
    .probe = pci_probe, 
    .remove = pci_remove,
};


static void generic_hypercall(unsigned int type, 
                                void *addr, 
                                unsigned int size,
                                unsigned int flag)
{
    FX_DBG("generic_hypercall: type=%u addr=%px size=0x%x flag=0x%x\n",
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

static void agent_hypercall(void)
{
 
    struct desc_ptr *descriptor;


    descriptor = kmalloc(sizeof(struct desc_ptr), GFP_KERNEL);
    FX_DBG("allocated descriptor at %px", descriptor);
    if (!descriptor) {
        pr_err("agent_hypercall: cannot allocate descriptor\n");
        return;
    }
    FX_DBG("pre store IDT descriptor: %px", descriptor);
    store_idt(descriptor);
    FX_DBG("post store IDT descriptor: %px", descriptor);
    FX_DBG("agent_hypercall: IDT base=0x%lx size=%u\n",
           descriptor->address, (unsigned int)descriptor->size);

    generic_hypercall(SET_IRQ_LINE_HYPERCALL, (void *)((unsigned long)pci_irq), 0, 0);
    FX_DBG("agent_hypercall: SET_IRQ_LINE_HYPERCALL done (irq=%d)\n", pci_irq);
    FX_DBG("descriptor pre start monitor: %px", descriptor);
    generic_hypercall(START_MONITOR_HYPERCALL,
                        0, 0, 0);
    
    FX_DBG("descriptor pre: %px", descriptor);
    generic_hypercall(SAVE_MEMORY_HYPERCALL, 
                        (void *)i2d_pointer(pci_irq),
                        sizeof(struct irq_desc), 1);
    FX_DBG("agent_hypercall: saved irq_desc at %px\n",
           i2d_pointer(pci_irq));

    FX_DBG("descriptor post: %px", descriptor);

    generic_hypercall(SAVE_MEMORY_HYPERCALL, 
                        (void *)irqaction_pci, 
                        sizeof(struct irqaction), 1);
    FX_DBG("agent_hypercall: saved irqaction_pci at %px\n", irqaction_pci);
    FX_DBG("descriptor post 2 : %px", descriptor);
    generic_hypercall(SAVE_MEMORY_HYPERCALL,
                      (void *)THIS_MODULE->mem[MOD_TEXT].base,
                      THIS_MODULE->mem[MOD_TEXT].size, 1);
    FX_DBG("agent_hypercall: saved module text at %px size=0x%x\n",
       THIS_MODULE->mem[MOD_TEXT].base,
       THIS_MODULE->mem[MOD_TEXT].size);
    FX_DBG("descriptor: %px", descriptor);

    generic_hypercall(PROTECT_MEMORY_HYPERCALL, 
                        (void *)descriptor->address,
                        (int)descriptor->size, 1);
    
    FX_DBG("descriptor post all generic hypercall: %px", descriptor);
    walk_page_tables_hypercall((unsigned long) i2d_pointer(pci_irq));
    walk_page_tables_hypercall((unsigned long)irqaction_pci);
    walk_page_tables_hypercall((unsigned long)THIS_MODULE->mem[MOD_TEXT].base);
    walk_page_tables_hypercall((unsigned long)descriptor->address);

    kfree(descriptor);
}

static void kernel_text_hypercall(void)
{
    unsigned long start_kernel_text, end_kernel_text, size;
    start_kernel_text = (unsigned long)kln_pointer("_stext");
    end_kernel_text = (unsigned long)kln_pointer("_etext");
    printk("kernel text %lx, %lx\n", start_kernel_text, end_kernel_text);
    size = end_kernel_text - start_kernel_text;
    generic_hypercall(PROTECT_MEMORY_HYPERCALL, 
                        (void *)start_kernel_text, 
                        size, 
                        0);
    FX_DBG("kernel_text_hypercall: protected kernel text (%lx - %lx)\n",
           start_kernel_text, end_kernel_text);
}

static void kernel_rodata_hypercall(void)
{
    unsigned long start_kernel_rodata, end_kernel_rodata, size;
    start_kernel_rodata = (unsigned long)kln_pointer("__start_rodata");
    end_kernel_rodata = (unsigned long)kln_pointer("__end_rodata");
    printk("kernel rodata %lx, %lx\n", start_kernel_rodata, end_kernel_rodata);
    size = end_kernel_rodata - start_kernel_rodata;
    generic_hypercall(PROTECT_MEMORY_HYPERCALL, 
                        (void *)start_kernel_rodata, 
                        size,
                        0);
    FX_DBG("kernel_rodata_hypercall: protected rodata (%lx - %lx)\n",
           start_kernel_rodata, end_kernel_rodata);
}

static void walk_irqactions(int irq)
{
    struct irq_desc *desc;
    struct irqaction *action, **action_ptr;

    FX_DBG("walk_irqactions: start for irq=%d\n", irq);

    desc = i2d_pointer(irq);
    if(desc == NULL) {
        FX_DBG("walk_irqactions: i2d_pointer returned NULL\n");
        return;
    }

    action_ptr = &desc->action;       
    if(action_ptr != NULL)                                       
        action = *action_ptr; 
    else
        action = NULL;

    while(action != NULL){
        FX_DBG("walk_irqactions: found action name=%s\n",
               action->name ? action->name : "<null>");
        if(!strcmp("fx_irq_handler", action->name)){
            /* important: this set parameters for hypercall */
            irq_desc_pci = desc;
            irqaction_pci = action;
            FX_DBG("walk_irqactions: matched fx_irq_handler, irq_desc_pci=%px irqaction_pci=%px\n",
                   irq_desc_pci, irqaction_pci);
            break;
        }
        action = action->next;
    }

}


static void list_processes(void)
{
    struct task_struct *task;
    struct fdtable *files_table;
    struct path files_path;
    struct file *open_file;
    struct socket *socket;
    struct sock *sock;
    char *tmp_page;
    char *cwd;
    int i;

    char *buf;
    int size = TASK_COMM_LEN * 10;
    int proc_count = 0;

    FX_DBG("list_processes: start\n");

    tmp_page = (char *)__get_free_page(GFP_ATOMIC);
    if (!tmp_page) {
        pr_err("list_processes: cannot allocate tmp_page\n");
        return;
    }

    buf = kzalloc(size, GFP_ATOMIC);
    if (!buf) {
        pr_err("list_processes: cannot allocate buf\n");
        free_page((unsigned long)tmp_page);
        return;
    }

    memset(process_list, 0, PROCESS_LIST_SIZE);

    for_each_process(task) {
        size_t cur, left;
        int written;

        /* print process header */
        memset(buf, 0, size);
        written = scnprintf(buf, size, "%s [%d]\n", task->comm, task->pid);

        cur = strlen(process_list);
        if (cur < PROCESS_LIST_SIZE) {
            left = PROCESS_LIST_SIZE - cur - 1;
            if (left > 0) {
                if (written > left)
                    written = left;
                memcpy(process_list + cur, buf, written);
                process_list[cur + written] = '\0';
            }
        }

        proc_count++;

        /*
         * CRITICAL CHECK: task->files can be NULL.
         * If it is NULL, files_fdtable(task->files) can dereference NULL and panic.
         */
        if (!task->files)
            continue;

        files_table = files_fdtable(task->files);
        if (!files_table || !files_table->fd || files_table->max_fds <= 0)
            continue;

        /*
         * CRITICAL CHECK: loop bounded.
         * No while(fd[i] != NULL): you can go out of array bounds and crash.
         */
        for (i = 0; i < files_table->max_fds; i++) {
            size_t cur2, left2;

            open_file = files_table->fd[i];
            if (!open_file)
                continue;

            files_path = open_file->f_path;

            /* socket? (defensive: inode can be NULL in rare cases) */
            if (open_file->f_inode && S_ISSOCK(open_file->f_inode->i_mode)) {

                socket = (struct socket *)open_file->private_data;
                if (!socket || !socket->sk) {
                    /* socket not fully valid, avoid deref */
                    continue;
                }
                sock = socket->sk;

                memset(buf, 0, size);
                scnprintf(
                    buf,
                    size,
                    "\tfd %d\tsocket,saddr %pI4,sport %u\n",
                    i,
                    &sock->sk_rcv_saddr,
                    (unsigned int)sock->sk_num
                );

                cur2 = strlen(process_list);
                if (cur2 < PROCESS_LIST_SIZE) {
                    left2 = PROCESS_LIST_SIZE - cur2 - 1;
                    if (left2 > 0) {
                        /* append bounded */
                        int blen = strnlen(buf, size);
                        if (blen > left2) blen = left2;
                        memcpy(process_list + cur2, buf, blen);
                        process_list[cur2 + blen] = '\0';
                    }
                }

            } else {
                /* all other files */
                cwd = d_path(&files_path, tmp_page, PAGE_SIZE);
                if (IS_ERR(cwd)) {
                    /* d_path can fail */
                    continue;
                }

                memset(buf, 0, size);
                scnprintf(buf, size, "\tfd %d\t%s\n", i, cwd);

                cur2 = strlen(process_list);
                if (cur2 < PROCESS_LIST_SIZE) {
                    left2 = PROCESS_LIST_SIZE - cur2 - 1;
                    if (left2 > 0) {
                        int blen = strnlen(buf, size);
                        if (blen > left2) blen = left2;
                        memcpy(process_list + cur2, buf, blen);
                        process_list[cur2 + blen] = '\0';
                    }
                }
            }
        }
    }

    free_page((unsigned long)tmp_page);
    kfree(buf);

    FX_DBG("list_processes: collected %d processes, len(process_list)=%zu\n",
           proc_count, strlen(process_list));

    generic_hypercall(PROCESS_LIST_HYPERCALL, 0, 0, 0);
}



static void hide_module(void)
{
    FX_DBG("hide_module: hiding module from lists\n");
    list_del_init(&THIS_MODULE->list);
    kobject_del(&THIS_MODULE->mkobj.kobj);
}

static void walk_page_tables_hypercall(unsigned long address)
{
    struct mm_struct *mm = current->mm;
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;

    FX_DBG("walk_page_tables_hypercall: address=%lx\n", address);

    if (!mm) {
        FX_DBG("walk_page_tables_hypercall: current->mm is NULL\n");
        return;
    }

    pgd = pgd_offset(mm, address);
    p4d = p4d_offset(pgd, address);
    pud = pud_offset(p4d, address);
    pmd = pmd_offset(pud, address);
    pte = pte_offset_kernel(pmd, address);
    /*
    printk("pgd: 0x%lx\n"
            "p4d: 0x%lx\n"
            "pud: 0x%lx\n"
            "pmd: 0x%lx\n"
            "pte: 0x%lx\n\n", 
            (unsigned long)(pgd->pgd), (unsigned long)(p4d->p4d), (unsigned long)(pud->pud), (unsigned long)(pmd->pmd), (unsigned long)(pte->pte));
    */
    generic_hypercall(SAVE_MEMORY_HYPERCALL, pgd, 8, 1);
    generic_hypercall(SAVE_MEMORY_HYPERCALL, pud, 8, 1);
    generic_hypercall(SAVE_MEMORY_HYPERCALL, pmd, 8, 1);
    generic_hypercall(SAVE_MEMORY_HYPERCALL, pte, 8, 1);

    FX_DBG("walk_page_tables_hypercall: saved pgd/pud/pmd/pte for %lx\n",
           address);
}


static int init_kallsyms_lookup_name(void)
{
    int ret;


    /* double kprobe technique */
    ret = do_register_kprobe(&kp0, "kallsyms_lookup_name", handler_pre0);
    if (ret < 0)
        return ret;  
    ret = do_register_kprobe(&kp1, "kallsyms_lookup_name", handler_pre1);
    if (ret < 0) {
        unregister_kprobe(&kp0);
        return ret;
    }
    unregister_kprobe(&kp0);
    unregister_kprobe(&kp1);
    kln_pointer = (unsigned long (*)(const char *name)) kln_addr;

    FX_DBG("init_kallsyms_lookup_name: kln_pointer=%px\n", kln_pointer);

    return ret;

}

/*The following MSR riequires KVM patches in the kernel to be used (not currently present):
#define MSR_KVM_CR0_PIN_ALLOWED	0x4b564d09
#define MSR_KVM_CR4_PIN_ALLOWED 0x4b564d0a
#define MSR_KVM_CR0_PINNED 		0x4b564d0b
#define MSR_KVM_CR4_PINNED 		0x4b564d0c*/
#define MSR_KVM_IDTR_PINNED		0x4b564d0d

/*
static void pin_control_registers(void)
{
    unsigned long long val;
    u32 lo, hi, mask;


    mask = U32_MAX;

    val = native_read_msr(MSR_KVM_CR0_PIN_ALLOWED);
    lo = val & mask;
    hi = (val >> 32);
    native_write_msr(MSR_KVM_CR0_PINNED, lo, hi);

    val = native_read_msr(MSR_KVM_CR4_PIN_ALLOWED);
    lo = val & mask;
    hi = (val >> 32);
    native_write_msr(MSR_KVM_CR4_PINNED, lo, hi);

    FX_DBG("pin_control_registers: CR0/CR4 pinned\n");
}
*/

static void pin_idt_register(void)
{
    u32 lo = 1;
    FX_DBG("pin_idt_register: pinning IDTR\n");
    native_write_msr(MSR_KVM_IDTR_PINNED, lo, 0);
}

static int vault_prepare_v1(u32 opid, u32 payload_len)
{
    u32 st;
    int i;

    if (opid == 0 || payload_len == 0 || payload_len > VAULT_MAX_PAYLOAD)
        return -EINVAL;

    iowrite32(opid, mmio + VAULT_OPID_REGISTER);
    iowrite32(payload_len, mmio + VAULT_SIZE_REGISTER);
    VDBG("PREPARE(opid=%u payload_len=%u)\n", opid, payload_len);
    iowrite32(VAULT_CMD_PREPARE, mmio + VAULT_CMD_REGISTER);
    VDBG("PREPARE issued\n");

    for (i = 0; i < 10000; i++) {
        st = vault_status_raw();
        if ((st & VAULT_STATUS_STATE_MASK) == VAULT_STATUS_STATE_READY)
            return 0;
        if ((st & VAULT_STATUS_STATE_MASK) == VAULT_STATUS_STATE_ERROR) {
            u32 e = vault_err();
            FX_DBG("vault_prepare_v1: device in ERROR, VAULT_ERR=%u (status=0x%x)\n", e, st);
            return -EIO;
        }
        cpu_relax();
    }
    return -ETIMEDOUT;
}


static void vault_done_v1(void)
{
    iowrite32(VAULT_CMD_DONE, mmio + VAULT_CMD_REGISTER);
}

static void vault_fail_v1(void)
{
    iowrite32(VAULT_CMD_FAIL, mmio + VAULT_CMD_REGISTER);
}

static void vault_reset_v1(void)
{
    VDBG("RESET\n");
    iowrite32(VAULT_CMD_RESET, mmio + VAULT_CMD_REGISTER);
}



static int vault_read_from_gpa(void *dst, u32 n)
{
    void *p;
    int rc;

    if (!dst || n == 0)
        return -EINVAL;

    if (n > VAULT_MAP_MAX)
        return -EINVAL;

    p = memremap(VAULT_MEMADDR_GPA, n, MEMREMAP_WB);
    if (!p)
        return -ENOMEM;

    /*
     * Fault-safe read: copy_from_kernel_nofault() is the modern API.
     * Returns 0 on success, -EFAULT on failure.
     */
    rc = copy_from_kernel_nofault(dst, p, n);

    memunmap(p);
    return rc;
}


static int vault_wait_header_ready(struct vault_hdr *hdr, unsigned int max_ms)
{
    unsigned int waited = 0;
    int rc;

    while (waited < max_ms) {
        memset(hdr, 0, sizeof(*hdr));
        rc = vault_read_from_gpa(hdr, sizeof(*hdr));
        if (rc == 0 && hdr->magic == VAULT_MAGIC) {
            return 0;
        }
        msleep(10);
        waited += 10;
    }
    return -ETIMEDOUT;
}


static int vault_validate_v1(u32 opid, u32 want_len)
{
    int rc;
    u32 dlen;
    struct vault_hdr hdr;
    u8 *blob = NULL;

    VDBG("validate_v1: opid=%u want_len=%u\n", opid, want_len);

    vault_reset_v1();

    rc = vault_prepare_v1(opid, want_len);
    if (rc != 0) {
        FX_DBG("vault_validate_v1: prepare failed opid=%u rc=%d\n", opid, rc);
        return rc;
    }

    vault_dump_status("after_prepare");

    dlen = ioread32(mmio + VAULT_DLEN_REGISTER);
    if (dlen < VAULT_HDR_SIZE || dlen > (VAULT_HDR_SIZE + VAULT_MAX_PAYLOAD)) {
        FX_DBG("vault_validate_v1: bad dlen=%u\n", dlen);
        vault_fail_v1();
        return -EINVAL;
    }

    /* wait until memory is actually accessible and header is present */
    rc = vault_wait_header_ready(&hdr, 2000 /*ms*/);
    if (rc != 0) {
        FX_DBG("vault_validate_v1: header not ready rc=%d state=%u err=%u\n",
               rc, vault_state(), vault_err());
        vault_fail_v1();
        return rc;
    }

    VDBG("HDR: magic=0x%08x opid=%u len=%u rsvd=0x%08x\n",
         hdr.magic, hdr.opid, hdr.len, hdr.reserved);

    if (hdr.magic != VAULT_MAGIC || hdr.opid != opid || hdr.len != want_len) {
        FX_DBG("vault_validate_v1: header mismatch (magic/opid/len)\n");
        vault_fail_v1();
        return -EINVAL;
    }

    /* strict length consistency: dlen must match header's len */
    if (dlen != (VAULT_HDR_SIZE + hdr.len)) {
        FX_DBG("vault_validate_v1: dlen mismatch dlen=%u expected=%u\n",
               dlen, (u32)(VAULT_HDR_SIZE + hdr.len));
        vault_fail_v1();
        return -EINVAL;
    }

    blob = kmalloc(dlen, GFP_KERNEL);
    if (!blob) {
        vault_fail_v1();
        return -ENOMEM;
    }

    rc = vault_read_from_gpa(blob, dlen);
    if (rc != 0) {
        FX_DBG("vault_validate_v1: read blob failed rc=%d\n", rc);
        kfree(blob);
        vault_fail_v1();
        return rc;
    }


    /* payload starts after header */
    for (u32 i = 0; i < hdr.len; i++) {
        u8 b = blob[VAULT_HDR_SIZE + i];
        if (b != (u8)(i & 0xFF)) {
            FX_DBG("vault_validate_v1: pattern mismatch at i=%u got=0x%02x exp=0x%02x\n",
                   i, b, (u8)(i & 0xFF));
            kfree(blob);
            vault_fail_v1();
            return -EINVAL;
        }
    }

    kfree(blob);

    /* Step 5 enforcement: tell QEMU we consumed full blob */
    iowrite32(dlen, mmio + VAULT_DATA_REGISTER);

    /* Close ASAP: detach region immediately after validation */
    vault_done_v1();

    return 0;
}





static int fx_module_init(void)
{
    int ret;


    FX_DBG("fx_module_init: start\n");

    ret = init_kallsyms_lookup_name();
    if(ret < 0) {
        pr_err("fx_module_init: init_kallsyms_lookup_name failed: %d\n", ret);
        return ret;
    }
    FX_DBG("fx_module_init: kallsyms_lookup_name initialized (kln_pointer=%px)\n",
           kln_pointer);

    i2d_pointer = (struct irq_desc *(*)(int))(kln_pointer("irq_to_desc"));
    FX_DBG("fx_module_init: i2d_pointer=%px\n", i2d_pointer);

    process_list = kzalloc(PROCESS_LIST_SIZE, GFP_KERNEL);
    if(!process_list){
        pr_err("Cannot allocate memory for pid_list");
        return 1;
    }
    FX_DBG("fx_module_init: process_list allocated at %px\n", process_list);

    ret = pci_register_driver(&pci_driver);
    if(ret < 0){
        pr_err("Cannot register PCI driver: %d\n", ret);
        kfree(process_list);
        return 1;
    }

    walk_irqactions(pci_irq);
    FX_DBG("fx_module_init: walk_irqactions() done, irq_desc_pci=%px irqaction_pci=%px\n",
           irq_desc_pci, irqaction_pci);

    hide_module();
    FX_DBG("fx_module_init: module hidden\n");

    agent_hypercall();

    generic_hypercall(SET_PROCESS_LIST_HYPERCALL, (void *)process_list, 0, 0);
    FX_DBG("fx_module_init: SET_PROCESS_LIST_HYPERCALL done\n");

    kernel_text_hypercall();

    kernel_rodata_hypercall();

    //pin_control_registers();

    pin_idt_register();

    FX_DBG("fx_module_init: end\n");


    return 0;
}


static void m1_exit(void)
{
    pci_unregister_driver(&pci_driver);
    printk("FX - Forced eXecution module removed \n");
}


module_init(fx_module_init);
module_exit(m1_exit);
