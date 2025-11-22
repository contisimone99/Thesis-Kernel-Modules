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
#include <net/sock.h>

MODULE_AUTHOR("Lorenzo Susini");
MODULE_LICENSE("GPL");

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
  return 0;
}

KPROBE_PRE_HANDLER(handler_pre1)
{
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
  return ret;
}


/************************************************
*    Interrupt handling variables 
************************************************/
static struct pci_dev *pdev; /* PCI device */
static void __iomem *mmio; /* memory mapped I/O */
static int pci_irq;
static struct irq_desc *irq_desc_pci;
static struct irqaction *irqaction_pci;

static struct pci_device_id pci_ids[] = {
    { PCI_DEVICE(VENDOR_ID, DEVICE_ID), },
    { 0, }
};
MODULE_DEVICE_TABLE(pci, pci_ids);
/***********************************************/


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
/***********************************************/


static irqreturn_t fx_irq_handler(int irq, void *dev)
{
    u32 irq_status;
    printk("Got an interrupt\n");
    irq_status = ioread32(mmio + INTERRUPT_STATUS_REGISTER);
    iowrite32(irq_status, mmio + INTERRUPT_ACK_REGISTER);

    list_processes();
    generic_hypercall(END_RECORDING_HYPERCALL, NULL, 0, 0);


    iowrite32(0x1, mmio + SCHEDULE_NEXT_REGISTER);

    return IRQ_HANDLED;
}


static int pci_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
    u8 val;
    // unsigned int i;
    pdev = dev;

    if(pci_enable_device(pdev) < 0){
        dev_err(&(pdev->dev), "error in pci_enable_device\n");
        return -1;
    }
    if(pci_request_region(pdev, BAR, "myregion0")){
		dev_err(&(pdev->dev), "error in pci_request_region\n");
		return -1;
	}
    mmio = pci_iomap(pdev, BAR, pci_resource_len(pdev, BAR));

	/* IRQ setup */
	pci_read_config_byte(dev, PCI_INTERRUPT_LINE, &val);
	pci_irq = val;
	if (request_irq(pci_irq, 
                    fx_irq_handler, 
                    0, 
                    "fx_irq_handler", 
                    NULL) < 0) {
		dev_err(&(dev->dev), "request_irq\n");
		return -1;
	}

    /* TEST 
    generic_hypercall(START_TIMER_HYPERCALL, 0, 0, 0);
    // test hypercall times 
    for(i = 0; i < 100000; i++)
        generic_hypercall(EMPTY_HYPERCALL, 0, 0, 0);
    generic_hypercall(STOP_TIMER_HYPERCALL, 0, 0, 0);
    */

    /* starting the thread in the emulated device */
    iowrite32(0x1, mmio + START_THREAD_REGISTER);

    return 0;
}


static void pci_remove(struct pci_dev *dev)
{
	pr_info("pci_remove\n");
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
    printk("hypercall\n");
    
    __asm__ volatile(
        "mfence;"
        "mov %0, %%r8;"
        "movl %1, %%r9d;" 
        "mov %2, %%r10;"
        "mov %3, %%r11;"
        "movl %4, %%r12d;"
        "movq $1, (%%r11);"
        ::  "r"(addr), 
            "r"(size), 
            "r"((unsigned long)type),
            "r"(mmio + HYPERCALL_OFFSET),
            "r"(flag));
}

static void agent_hypercall(void)
{
 
    struct desc_ptr *descriptor;
    descriptor = kmalloc(sizeof(struct desc_ptr), GFP_KERNEL);
    store_idt(descriptor);

    generic_hypercall(SET_IRQ_LINE_HYPERCALL, 
                        (void *)((unsigned long)pci_irq), 0, 0);
    
    generic_hypercall(START_MONITOR_HYPERCALL,
                        0, 0, 0);
    
    
    generic_hypercall(SAVE_MEMORY_HYPERCALL, 
                        (void *)i2d_pointer(pci_irq),
                        sizeof(struct irq_desc), 1);
    generic_hypercall(SAVE_MEMORY_HYPERCALL, 
                        (void *)irqaction_pci, 
                        sizeof(struct irqaction), 1);
    generic_hypercall(SAVE_MEMORY_HYPERCALL, 
                        (void *)THIS_MODULE->core_layout.base, 
                        THIS_MODULE->core_layout.size, 1);
    generic_hypercall(PROTECT_MEMORY_HYPERCALL, 
                        (void *)descriptor->address,
                        (int)descriptor->size, 1);

    walk_page_tables_hypercall((unsigned long) i2d_pointer(pci_irq));
    walk_page_tables_hypercall((unsigned long)irqaction_pci);
    walk_page_tables_hypercall((unsigned long)THIS_MODULE->core_layout.base);
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
}

static void walk_irqactions(int irq)
{
    struct irq_desc *desc;
    struct irqaction *action, **action_ptr;

    desc = i2d_pointer(irq);
    if(desc == NULL)
        return;
    action_ptr = &desc->action;       
    if(action_ptr != NULL)                                       
        action = *action_ptr; 
    else
        action = NULL;

    while(action != NULL){
        if(!strcmp("fx_irq_handler", action->name)){
            /* important: this set parameters for hypercall */
            irq_desc_pci = desc;
            irqaction_pci = action;
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
    char  *tmp_page;
    char *cwd;
    int i;

    char *buf;
    int size = TASK_COMM_LEN * 10;

	tmp_page = (char*)__get_free_page(GFP_ATOMIC);
    buf = kzalloc(size, GFP_KERNEL);
    memset(process_list, 0, PROCESS_LIST_SIZE);

    for_each_process(task) {
        memset(buf, 0, size);
        snprintf(buf, size, "%s [%d]\n", task->comm, task->pid);
        strncat(process_list, buf, PROCESS_LIST_SIZE - strlen(process_list) - 1);

        files_table = files_fdtable(task->files);
        i = 0;
        while(files_table->fd[i] != NULL){
            memset(buf, 0, size);
            open_file = files_table->fd[i];
            files_path = open_file->f_path;
			/* check if open_file refers to a socket */
			if(S_ISSOCK(file_inode(open_file)->i_mode)){

				socket = (struct socket *)open_file->private_data;
				sock = socket->sk;

				snprintf(
                    buf, 
                    size,
					"\tfd %d\tsocket," 
					"saddr %pI4," 
					"sport %u\n", 
					i,
					&sock->sk_rcv_saddr, 
					(unsigned int)sock->sk_num
				);
                strncat(process_list, buf, PROCESS_LIST_SIZE - strlen(process_list) - 1);
			}

			/* all other files */
			else {
    			cwd = d_path(&files_path, tmp_page, PAGE_SIZE);
				snprintf(buf, size, "\tfd %d\t%s\n", i, cwd);
                strncat(process_list, buf, PROCESS_LIST_SIZE - strlen(process_list) - 1);
			}

			i++;

        }
    }
    free_page((unsigned long)tmp_page);
    generic_hypercall(PROCESS_LIST_HYPERCALL, 0, 0, 0);
}


static void hide_module(void)
{
    list_del_init(&THIS_MODULE->list);
    kobject_del(&THIS_MODULE->mkobj.kobj);
}

/*
static void test_hypercalls(void)
{
    void *prova1, *prova2, *prova3;
    char *dirty;
    prova1 = kmalloc(0x100, GFP_KERNEL);
    prova2 = kmalloc(0x10, GFP_KERNEL);
    generic_hypercall(SAVE_MEMORY_HYPERCALL, prova1, 0x100, 0);
    generic_hypercall(SAVE_MEMORY_HYPERCALL, prova2, 0x10, 0);
    dirty = (char *)prova1;
    *(dirty + 10) = 'A';
    generic_hypercall(COMPARE_MEMORY_HYPERCALL, prova1, 0x100, 0);
    generic_hypercall(COMPARE_MEMORY_HYPERCALL, prova2, 0x10, 0);
    prova3 = kmalloc(256, GFP_KERNEL);
    generic_hypercall(PROTECT_MEMORY_HYPERCALL, prova3, 256, 0);
    dirty = (char *)prova3;
    *(dirty + 10) = 'A';
    *(dirty + 300) = 'A';
    //kfree(prova3);
}
*/

static void walk_page_tables_hypercall(unsigned long address)
{
    struct mm_struct *mm = current->mm;
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;

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

    return ret;

}


#define MSR_KVM_CR0_PIN_ALLOWED	0x4b564d08
#define MSR_KVM_CR4_PIN_ALLOWED 0x4b564d09
#define MSR_KVM_CR0_PINNED 		0x4b564d0a
#define MSR_KVM_CR4_PINNED 		0x4b564d0b
#define MSR_KVM_IDTR_PINNED		0x4b564d0c

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
}

static void pin_idt_register(void)
{
    u32 lo = 1;
    native_write_msr(MSR_KVM_IDTR_PINNED, lo, 0);
}


static int fx_module_init(void)
{
    int ret;

    printk("FX - Forced eXecution module started \n");

    ret = init_kallsyms_lookup_name();
    if(ret < 0)
        return ret;
    i2d_pointer = (struct irq_desc *(*)(int))(kln_pointer("irq_to_desc"));

    process_list = kzalloc(PROCESS_LIST_SIZE, GFP_KERNEL);
    if(!process_list){
        pr_err("Cannot allocate memory for pid_list");
        return 1;
    }

    if(pci_register_driver(&pci_driver) < 0){
        pr_err("Cannot register PCI driver");
        return 1;
    }

    walk_irqactions(pci_irq);

    hide_module();

    agent_hypercall();
    generic_hypercall(SET_PROCESS_LIST_HYPERCALL, (void *)process_list, 0, 0);
    kernel_text_hypercall();
    kernel_rodata_hypercall();
    pin_control_registers();
    pin_idt_register();

    /*
    printk(
        "**************************************************\n"
        "current pgd %px -> 0x%lx\n"
        "irq_action address %px -> 0x%lx\n"
        "irqdesc %px -> 0x%lx\n"
        "handle_fast_eoi_irq %px -> 0x%lx\n"
        "irq handler %px -> 0x%lx\n"
        "generic handle irq %px -> 0x%lx\n"
        "common interrupt %px -> 0x%lx\n"
        "**************************************************\n",
        (void *)current->mm->pgd, __pa(current->mm->pgd),
        (void *)irqaction_pci, __pa(irqaction_pci),
        (void *)irq_desc_pci, __pa(irq_desc_pci), 
        (void *)kln_pointer("handle_fasteoi_irq"), __pa(kln_pointer("handle_fasteoi_irq")),
        (void *)fx_irq_handler, __pa(fx_irq_handler),
        (void *)kln_pointer("generic_handle_irq"), __pa(kln_pointer("generic_handle_irq")),
        (void *)kln_pointer("__common_interrupt"),__pa(kln_pointer("__common_interrupt"))
        );

    */

    return 0;
}

/*
static void m1_exit(void)
{
    pci_unregister_driver(&pci_driver);
    printk("FX - Forced eXecution module removed \n");
}
*/

module_init(fx_module_init);
//module_exit(m1_exit);
