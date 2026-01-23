.intel_syntax noprefix
.text
.global payload_start

/*
 * ABI (set by VMM before entering vault):
 *  RDI = init_task_addr (VA)
 *  RSI = off_tasks      (u32/u64 ok)
 *  RDX = off_pid
 *  RCX = off_comm
 *  R8  = comm_len
 *  R9  = outbuf_va      (VA, MUST be RW)
 *  R10 = magic_port     (u16 in r10w)
 *
 * Output format (repeated):
 *   u32 pid
 *   comm_len bytes (raw)
 * Terminator:
 *   u32 0xFFFFFFFF
 */

payload_start:
    push rbp
    mov  rbp, rsp

    push rbx
    push r12
    push r13
    push r14
    push r15

    /* save params */
    mov  r12, rsi        /* off_tasks */
    mov  r13, rdx        /* off_pid   */
    mov  r14, rcx        /* off_comm  */
    mov  r15d, r8d       /* comm_len  */

    /* out buffer */
    mov  rbx, r9         /* outbuf VA */

    /* init_task must be non-null */
    test rdi, rdi
    jz   error_exit

    /* sanity comm_len: 1..256 */
    test r15d, r15d
    jz   error_exit
    cmp  r15d, 256
    ja   error_exit

    /* keep init_task on stack for loop termination check */
    mov  rax, rdi        /* current task base */
    push rdi             /* [rsp] = init_task */

loop_tasks:
    /* rax = current task base (may be init_task initially) */

    /* next = task->tasks.next */
    mov  rax, [rax + r12]
    test rax, rax
    jz   done            /* broken list -> stop */

    /* convert list_head* to task_struct* base */
    sub  rax, r12
    test rax, rax
    jz   done

    /* reached init_task again? */
    cmp  rax, [rsp]
    je   done

    /* pid */
    mov  ecx, [rax + r13]
    mov  [rbx], ecx
    add  rbx, 4

    /* comm bytes */
    lea  rsi, [rax + r14]  /* src */
    mov  rdi, rbx          /* dst */
    mov  ecx, r15d
    rep  movsb
    add  rbx, r15

    jmp  loop_tasks

done:
    add  rsp, 8            /* pop saved init_task */

    /* terminator */
    mov  dword ptr [rbx], 0xFFFFFFFF

    /* signal VMM */
    mov  dx, r10w
    mov  al, 1
    out  dx, al
    hlt

error_exit:
    /* try to write terminator if outbuf is usable */
    mov  dword ptr [rbx], 0xFFFFFFFF
    mov  dx, r10w
    mov  al, 1
    out  dx, al
    hlt
