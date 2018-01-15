/*
 * Copyright (c) 1988 University of Utah.
 * Copyright (c) 1992, 1993
 *      The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * the Systems Programming Group of the University of Utah Computer
 * Science Department and Ralph Campbell.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * from: Utah $Hdr: vm_machdep.c 1.21 91/04/06$
 *
 *      @(#)vm_machdep.c        8.3 (Berkeley) 1/4/94
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/malloc.h>
#include <sys/buf.h>
#include <sys/vnode.h>
#include <sys/user.h>

#include <vm/vm.h>
#include <vm/vm_kern.h>
#include <vm/vm_page.h>

#include <machine/pte.h>
#include <machine/cpu.h>

/*
 * Finish a fork operation, with process p2 nearly set up.
 * Copy and update the kernel stack and pcb, making the child
 * ready to run, and marking it so that it can return differently
 * than the parent.  Returns 1 in the child process, 0 in the parent.
 * We currently double-map the user area so that the stack is at the same
 * address in each process; in the future we will probably relocate
 * the frame pointers on the stack after copying.
 */
int
cpu_fork(p1, p2)
    register struct proc *p1, *p2;
{
    register struct user *up = p2->p_addr;
    register pt_entry_t *pte;
    register int i;

    p2->p_md.md_regs = up->u_pcb.pcb_regs;
    p2->p_md.md_flags = p1->p_md.md_flags & MDP_FPUSED;

    /*
     * Cache the PTEs for the user area in the machine dependent
     * part of the proc struct so cpu_switch() can quickly map in
     * the user struct and kernel stack. Note: if the virtual address
     * translation changes (e.g. swapout) we have to update this.
     */
    pte = kvtopte(up);
    for (i = 0; i < UPAGES; i++) {
        p2->p_md.md_upte[i] = pte->pt_entry & ~PG_G;
        pte++;
    }

    /*
     * Copy pcb and stack from proc p1 to p2.
     * We do this as cheaply as possible, copying only the active
     * part of the stack.  The stack and pcb need to agree;
     */
    p2->p_addr->u_pcb = p1->p_addr->u_pcb;
    /* cache segtab for ULTBMiss() */
    p2->p_addr->u_pcb.pcb_segtab = (void *)p2->p_vmspace->vm_pmap.pm_segtab;

    /*
     * Arrange for a non-local goto when the new process
     * is started, to resume here, returning nonzero from setjmp.
     */
#ifdef DIAGNOSTIC
    if (p1 != curproc)
        panic("cpu_fork: curproc");
#endif
    if (copykstack(up)) {
        /*
         * Return 1 in child.
         */
        return (1);
    }
    return (0);
}

/*
 * Finish a swapin operation.
 * We neded to update the cached PTEs for the user area in the
 * machine dependent part of the proc structure.
 */
void
cpu_swapin(p)
    register struct proc *p;
{
    register struct user *up = p->p_addr;
    register pt_entry_t *pte;
    register int i;

    /*
     * Cache the PTEs for the user area in the machine dependent
     * part of the proc struct so cpu_switch() can quickly map in
     * the user struct and kernel stack.
     */
    pte = kvtopte(up);
    for (i = 0; i < UPAGES; i++) {
        p->p_md.md_upte[i] = pte->pt_entry & ~PG_G;
        pte++;
    }
}

/*
 * cpu_exit is called as the last action during exit.
 * We release the address space and machine-dependent resources,
 * including the memory for the user structure and kernel stack.
 * Once finished, we call switch_exit, which switches to a temporary
 * pcb and stack and never returns.  We block memory allocation
 * until switch_exit has made things safe again.
 */
void
cpu_exit(p)
    struct proc *p;
{
    vmspace_free(p->p_vmspace);

    /* No running processes - activate swapper. */
    if (whichqs == 0)
        wakeup((caddr_t)&proc0);

    (void) splhigh();
    kmem_free(kernel_map, (vm_offset_t)p->p_addr, ctob(UPAGES));
    switch_exit();
    /* NOTREACHED */
}

/*
 * Dump the machine specific header information at the start of a core dump.
 */
int
cpu_coredump(p, vp, cred)
    struct proc *p;
    struct vnode *vp;
    struct ucred *cred;
{
    return vn_rdwr(UIO_WRITE, vp, (caddr_t)p->p_addr, ctob(UPAGES),
        (off_t)0, UIO_SYSSPACE, IO_NODELOCKED|IO_UNIT, cred, (int *)NULL, p);
}

/*
 * Move pages from one kernel virtual address to another.
 * Both addresses are assumed to reside in the Sysmap,
 * and size must be a multiple of CLSIZE.
 */
void
pagemove(from, to, size)
    register caddr_t from, to;
    int size;
{
    register pt_entry_t *fpte, *tpte;
//printf("%s: from=%08x, to=%08x, size=%u\n", __func__, from, to, size);

    if (size % CLBYTES)
        panic("pagemove");
    fpte = kvtopte(from);
    tpte = kvtopte(to);
    while (size > 0) {
        *tpte = *fpte;
        fpte->pt_entry &= PG_G;

        /* Replicate G bit to paired even/odd entry. */
        if ((unsigned) tpte & (1 << sizeof(*tpte)))
            tpte[-1].pt_entry |= PG_G;
        else
            tpte[1].pt_entry |= PG_G;

        tlb_flush_addr((unsigned) from, fpte->pt_entry);
        tlb_update((unsigned) to, tpte);
        fpte++;
        tpte++;
        size -= NBPG;
        from += NBPG;
        to += NBPG;
    }
}

extern vm_map_t phys_map;

/*
 * Map an IO request into kernel virtual address space.  Requests fall into
 * one of five catagories:
 *
 *      B_PHYS|B_UAREA: User u-area swap.
 *                      Address is relative to start of u-area (p_addr).
 *      B_PHYS|B_PAGET: User page table swap.
 *                      Address is a kernel VA in usrpt (Usrptmap).
 *      B_PHYS|B_DIRTY: Dirty page push.
 *                      Address is a VA in proc2's address space.
 *      B_PHYS|B_PGIN:  Kernel pagein of user pages.
 *                      Address is VA in user's address space.
 *      B_PHYS:         User "raw" IO request.
 *                      Address is VA in user's address space.
 *
 * All requests are (re)mapped into kernel VA space via the phys_map
 */
void
vmapbuf(bp, len)
    register struct buf *bp;
    vm_size_t len;
{
    register caddr_t addr;
    struct proc *p;
    int off;
    vm_offset_t kva;
    register vm_offset_t pa;

    if ((bp->b_flags & B_PHYS) == 0)
        panic("vmapbuf");
    addr = bp->b_saveaddr = bp->b_un.b_addr;
    off = (int)addr & PGOFSET;
    p = bp->b_proc;
    len = round_page(len + off);
    kva = kmem_alloc_wait(phys_map, len);
    bp->b_un.b_addr = (caddr_t) (kva + off);
    len = atop(len);
    while (len--) {
        pa = pmap_extract(vm_map_pmap(&p->p_vmspace->vm_map),
            (vm_offset_t)addr);
        if (pa == 0)
            panic("vmapbuf: null page frame");
        pmap_enter(vm_map_pmap(phys_map), kva, trunc_page(pa),
            VM_PROT_READ|VM_PROT_WRITE, TRUE);
        addr += PAGE_SIZE;
        kva += PAGE_SIZE;
    }
}

/*
 * Free the io map PTEs associated with this IO operation.
 * We also invalidate the TLB entries and restore the original b_addr.
 */
void
vunmapbuf(bp, len)
    register struct buf *bp;
    vm_size_t len;
{
    register caddr_t addr = bp->b_un.b_addr;
    vm_offset_t kva;

    if ((bp->b_flags & B_PHYS) == 0)
        panic("vunmapbuf");
    len = round_page(len + ((int)addr & PGOFSET));
    kva = (vm_offset_t)((int)addr & ~PGOFSET);
    kmem_free_wakeup(phys_map, kva, len);
    bp->b_un.b_addr = bp->b_saveaddr;
    bp->b_saveaddr = NULL;
}
