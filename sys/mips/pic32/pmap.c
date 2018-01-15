/*
 * Copyright (c) 1992, 1993
 *      The Regents of the University of California.  All rights reserved.
 * Copyright (c) 2014 Serge Vakulenko
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
 *      @(#)pmap.c      8.5 (Berkeley) 6/2/95
 */

/*
 * Manages physical address maps.
 *
 * In addition to hardware address maps, this
 * module is called upon to provide software-use-only
 * maps which may or may not be stored in the same
 * form as hardware maps.  These pseudo-maps are
 * used to store intermediate results from copy
 * operations to and from address spaces.
 *
 * Since the information managed by this module is
 * also stored by the logical address mapping module,
 * this module may throw away valid virtual-to-physical
 * mappings at almost any time.  However, invalidations
 * of virtual-to-physical mappings must be done as
 * requested.
 *
 * In order to cope with hardware architectures which
 * make virtual-to-physical map invalidates expensive,
 * this module may delay invalidate or reduced protection
 * operations until such time as they are actually
 * necessary.  This module is given full information as
 * to which processors are currently using which maps,
 * and to when physical maps must be made correct.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/malloc.h>
#include <sys/user.h>
#include <sys/buf.h>
#include <sys/msgbuf.h>
#ifdef SYSVSHM
#include <sys/shm.h>
#endif

#include <vm/vm_kern.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>

#include <machine/machConst.h>
#include <machine/pte.h>
#include <machine/cpu.h>

extern vm_page_t vm_page_alloc1 __P((void));
extern void vm_page_free1 __P((vm_page_t));

/*
 * For each vm_page_t, there is a list of all currently valid virtual
 * mappings of that page.  An entry is a pv_entry_t, the list is pv_table.
 * XXX really should do this as a part of the higher level code.
 */
typedef struct pv_entry {
    struct pv_entry *pv_next;       /* next pv_entry */
    struct pmap     *pv_pmap;       /* pmap where mapping lies */
    vm_offset_t     pv_va;          /* virtual address for mapping */
} *pv_entry_t;

pv_entry_t      pv_table;       /* array of entries, one per page */
extern void     pmap_remove_pv();

#define pa_index(pa)            atop((pa) - first_phys_addr)
#define pa_to_pvh(pa)           (&pv_table[pa_index(pa)])

struct pmap     kernel_pmap_store;

vm_offset_t     avail_start;    /* PA of first available physical page */
vm_offset_t     avail_end;      /* PA of last available physical page */
vm_size_t       mem_size;       /* memory size in bytes */
vm_offset_t     virtual_avail;  /* VA of first avail page (after kernel bss)*/
vm_offset_t     virtual_end;    /* VA of last avail page (end of kernel AS) */
#ifdef ATTR
char            *pmap_attributes;       /* reference and modify bits */
#endif
struct segtab   *free_segtab;           /* free list kept locally */
u_int           tlbpid_gen = 1;         /* TLB PID generation count */
int             tlbpid_cnt = 2;         /* next available TLB PID */
pt_entry_t      *Sysmap;                /* kernel pte table */
u_int           Sysmapsize;             /* number of pte's in Sysmap */

/*
 *      Bootstrap the system enough to run with virtual memory.
 *      firstaddr is the first unused kseg0 address (not page aligned).
 */
void
pmap_bootstrap(firstaddr)
    vm_offset_t firstaddr;
{
    int pv_tabsz;
    vm_offset_t start = firstaddr;

#define valloc(name, type, num) \
        (name) = (type *)firstaddr; firstaddr = (vm_offset_t)((name)+(num))
    /*
     * Allocate a PTE table for the kernel.
     * The '256' comes from PAGER_MAP_SIZE in vm_pager_init().
     * This should be kept in sync.
     * We also reserve space for kmem_alloc_pageable() for vm_fork().
     */
    Sysmapsize = (VM_KMEM_SIZE + VM_MBUF_SIZE + VM_PHYS_SIZE +
        nbuf * MAXBSIZE) / NBPG + 256 + 128;
#ifdef SYSVSHM
    Sysmapsize += shminfo.shmall;
#endif
    valloc(Sysmap, pt_entry_t, Sysmapsize);

#ifdef ATTR
    valloc(pmap_attributes, char, physmem);
#endif

    /*
     * Allocate memory for pv_table.
     * This will allocate more entries than we really need.
     * We could do this in pmap_init when we know the actual
     * phys_start and phys_end but its better to use kseg0 addresses
     * rather than kernel virtual addresses mapped through the TLB.
     */
    pv_tabsz = physmem - mips_btop(MACH_VIRT_TO_PHYS(firstaddr)) -
        btoc(sizeof(struct msgbuf));
    valloc(pv_table, struct pv_entry, pv_tabsz);

    /*
     * Clear allocated memory.
     */
    firstaddr = mips_round_page(firstaddr);
    bzero((caddr_t)start, firstaddr - start);

    avail_start = MACH_VIRT_TO_PHYS(firstaddr);
    avail_end = mips_ptob(physmem - btoc(sizeof(struct msgbuf)));
    mem_size = avail_end - avail_start;

    virtual_avail = VM_MIN_KERNEL_ADDRESS;
    virtual_end = VM_MIN_KERNEL_ADDRESS + Sysmapsize * NBPG;
    /* XXX need to decide how to set cnt.v_page_size */

    simple_lock_init(&kernel_pmap_store.pm_lock);
    kernel_pmap_store.pm_count = 1;
}

/*
 * Bootstrap memory allocator. This function allows for early dynamic
 * memory allocation until the virtual memory system has been bootstrapped.
 * After that point, either kmem_alloc or malloc should be used. This
 * function works by stealing pages from the (to be) managed page pool,
 * stealing virtual address space, then mapping the pages and zeroing them.
 *
 * It should be used from pmap_bootstrap till vm_page_startup, afterwards
 * it cannot be used, and will generate a panic if tried. Note that this
 * memory will never be freed, and in essence it is wired down.
 */
void *
pmap_bootstrap_alloc(size)
    int size;
{
    vm_offset_t val;
    extern boolean_t vm_page_startup_initialized;

    if (vm_page_startup_initialized)
        panic("pmap_bootstrap_alloc: called after startup initialized");

    val = MACH_PHYS_TO_UNCACHED(avail_start);
//printf("--- %s: %d bytes at %x\n", __func__, size, val);
    avail_start += size;

    bzero((caddr_t)val, size);
    return ((void *)val);
}

/*
 *      Initialize the pmap module.
 *      Called by vm_init, to initialize any structures that the pmap
 *      system needs to map virtual memory.
 */
void
pmap_init(phys_start, phys_end)
    vm_offset_t phys_start, phys_end;
{
}

/*
 *      Create and return a physical map.
 *
 *      If the size specified for the map
 *      is zero, the map is an actual physical
 *      map, and may be referenced by the
 *      hardware.
 *
 *      If the size specified is non-zero,
 *      the map will be used in software only, and
 *      is bounded by that size.
 */
pmap_t
pmap_create(size)
    vm_size_t size;
{
    register pmap_t pmap;

    /*
     * Software use map does not need a pmap
     */
    if (size)
        return (NULL);

    /* XXX: is it ok to wait here? */
    pmap = (pmap_t) malloc(sizeof *pmap, M_VMPMAP, M_WAITOK);
#ifdef notifwewait
    if (pmap == NULL)
        panic("pmap_create: cannot allocate a pmap");
#endif
    bzero(pmap, sizeof(*pmap));
    pmap_pinit(pmap);
    return (pmap);
}

/*
 * Initialize a preallocated and zeroed pmap structure,
 * such as one in a vmspace structure.
 */
void
pmap_pinit(pmap)
    register struct pmap *pmap;
{
    register int i;
    int s;
    extern struct vmspace vmspace0;
    extern struct user *proc0paddr;

    simple_lock_init(&pmap->pm_lock);
    pmap->pm_count = 1;
    if (free_segtab) {
        s = splimp();
        pmap->pm_segtab = free_segtab;
        free_segtab = *(struct segtab **)free_segtab;
        pmap->pm_segtab->seg_tab[0] = NULL;
        splx(s);
    } else {
        register struct segtab *stp;
        vm_page_t mem;

        mem = vm_page_alloc1();
        pmap_zero_page(VM_PAGE_TO_PHYS(mem));
        pmap->pm_segtab = stp = (struct segtab *)
            MACH_PHYS_TO_UNCACHED(VM_PAGE_TO_PHYS(mem));
        i = NBPG / sizeof(struct segtab);
        s = splimp();
        while (--i != 0) {
            stp++;
            *(struct segtab **)stp = free_segtab;
            free_segtab = stp;
        }
        splx(s);
    }
#ifdef DIAGNOSTIC
    for (i = 0; i < PMAP_SEGTABSIZE; i++)
        if (pmap->pm_segtab->seg_tab[i] != 0)
            panic("pmap_pinit: pm_segtab != 0");
#endif
    if (pmap == &vmspace0.vm_pmap) {
        /*
         * The initial process has already been allocated a TLBPID
         * in mach_init().
         */
        pmap->pm_tlbpid = 1;
        pmap->pm_tlbgen = tlbpid_gen;
        proc0paddr->u_pcb.pcb_segtab = (void *)pmap->pm_segtab;
    } else {
        pmap->pm_tlbpid = 0;
        pmap->pm_tlbgen = 0;
    }
}

/*
 *      Retire the given physical map from service.
 *      Should only be called if the map contains
 *      no valid mappings.
 */
void
pmap_destroy(pmap)
    register pmap_t pmap;
{
    int count;

    if (pmap == NULL)
        return;

    simple_lock(&pmap->pm_lock);
    count = --pmap->pm_count;
    simple_unlock(&pmap->pm_lock);
    if (count == 0) {
        pmap_release(pmap);
        free((caddr_t)pmap, M_VMPMAP);
    }
}

/*
 * Release any resources held by the given physical map.
 * Called when a pmap initialized by pmap_pinit is being released.
 * Should only be called if the map contains no valid mappings.
 */
void
pmap_release(pmap)
    register pmap_t pmap;
{
    if (pmap->pm_segtab) {
        register pt_entry_t *pte;
        register int i;
        int s;
#ifdef DIAGNOSTIC
        register int j;
#endif

        for (i = 0; i < PMAP_SEGTABSIZE; i++) {
            /* get pointer to segment map */
            pte = pmap->pm_segtab->seg_tab[i];
            if (!pte)
                continue;
            vm_page_free1(
                PHYS_TO_VM_PAGE(MACH_VIRT_TO_PHYS(pte)));
#ifdef DIAGNOSTIC
            for (j = 0; j < NPTEPG; j++) {
                if (pte->pt_entry)
                    panic("pmap_release: segmap not empty");
            }
#endif
            pmap->pm_segtab->seg_tab[i] = NULL;
        }
        s = splimp();
        *(struct segtab **)pmap->pm_segtab = free_segtab;
        free_segtab = pmap->pm_segtab;
        splx(s);
        pmap->pm_segtab = NULL;
    }
}

/*
 *      Add a reference to the specified pmap.
 */
void
pmap_reference(pmap)
    pmap_t pmap;
{
    if (pmap != NULL) {
        simple_lock(&pmap->pm_lock);
        pmap->pm_count++;
        simple_unlock(&pmap->pm_lock);
    }
}

/*
 *      Remove the given range of addresses from the specified map.
 *
 *      It is assumed that the start and end are properly
 *      rounded to the page size.
 */
void
pmap_remove(pmap, sva, eva)
    register pmap_t pmap;
    vm_offset_t sva, eva;
{
    register vm_offset_t nssva;
    register pt_entry_t *pte;
    unsigned entry;

    if (pmap == NULL)
        return;

    if (!pmap->pm_segtab) {
        register pt_entry_t *pte;

        /* remove entries from kernel pmap */
#ifdef DIAGNOSTIC
        if (sva < VM_MIN_KERNEL_ADDRESS || eva > virtual_end)
            panic("pmap_remove: kva not in range");
#endif
        pte = kvtopte(sva);
        for (; sva < eva; sva += NBPG, pte++) {
            entry = pte->pt_entry;
            if (!(entry & PG_V))
                continue;
            if (entry & PG_WIRED)
                pmap->pm_stats.wired_count--;
            pmap->pm_stats.resident_count--;
            pmap_remove_pv(pmap, sva, PG_FRAME(entry));
#ifdef ATTR
            pmap_attributes[atop(PG_FRAME(entry))] = 0;
#endif
            pte->pt_entry = PG_G;
            /*
             * Flush the TLB for the given address.
             */
            tlb_flush_addr(sva, PG_G);
        }
        return;
    }

#ifdef DIAGNOSTIC
    if (eva > VM_MAXUSER_ADDRESS)
        panic("pmap_remove: uva not in range");
#endif
    while (sva < eva) {
        nssva = mips_trunc_seg(sva) + NBSEG;
        if (nssva == 0 || nssva > eva)
            nssva = eva;
        /*
         * If VA belongs to an unallocated segment,
         * skip to the next segment boundary.
         */
        if (!(pte = pmap_segmap(pmap, sva))) {
            sva = nssva;
            continue;
        }
        /*
         * Invalidate every valid mapping within this segment.
         */
        pte += (sva >> PGSHIFT) & (NPTEPG - 1);
        for (; sva < nssva; sva += NBPG, pte++) {
            entry = pte->pt_entry;
            if (!(entry & PG_V))
                continue;
            if (entry & PG_WIRED)
                pmap->pm_stats.wired_count--;
            pmap->pm_stats.resident_count--;
            pmap_remove_pv(pmap, sva, PG_FRAME(entry));
#ifdef ATTR
            pmap_attributes[atop(PG_FRAME(entry))] = 0;
#endif
            pte->pt_entry = 0;
            /*
             * Flush the TLB for the given address.
             */
            if (pmap->pm_tlbgen == tlbpid_gen) {
                tlb_flush_addr(sva | pmap->pm_tlbpid, 0);
            }
        }
    }
}

/*
 *      pmap_page_protect:
 *
 *      Lower the permission for all mappings to a given page.
 */
void
pmap_page_protect(pa, prot)
    vm_offset_t pa;
    vm_prot_t prot;
{
    register pv_entry_t pv;
    register vm_offset_t va;
    int s;

    if (!IS_VM_PHYSADDR(pa))
        return;

    switch (prot) {
    case VM_PROT_READ|VM_PROT_WRITE:
    case VM_PROT_ALL:
        break;

    /* copy_on_write */
    case VM_PROT_READ:
    case VM_PROT_READ|VM_PROT_EXECUTE:
        pv = pa_to_pvh(pa);
        s = splimp();
        /*
         * Loop over all current mappings setting/clearing as appropos.
         */
        if (pv->pv_pmap != NULL) {
            for (; pv; pv = pv->pv_next) {
                extern vm_offset_t pager_sva, pager_eva;

                va = pv->pv_va;

                /*
                 * XXX don't write protect pager mappings
                 */
                if (va >= pager_sva && va < pager_eva)
                    continue;
                pmap_protect(pv->pv_pmap, va, va + PAGE_SIZE,
                    prot);
            }
        }
        splx(s);
        break;

    /* remove_all */
    default:
        pv = pa_to_pvh(pa);
        s = splimp();
        while (pv->pv_pmap != NULL) {
            pmap_remove(pv->pv_pmap, pv->pv_va,
                    pv->pv_va + PAGE_SIZE);
        }
        splx(s);
    }
}

/*
 *      Set the physical protection on the
 *      specified range of this map as requested.
 */
void
pmap_protect(pmap, sva, eva, prot)
    register pmap_t pmap;
    vm_offset_t sva, eva;
    vm_prot_t prot;
{
    register vm_offset_t nssva;
    register pt_entry_t *pte;
    register unsigned entry;
    u_int p;

    if (pmap == NULL)
        return;

    if ((prot & VM_PROT_READ) == VM_PROT_NONE) {
        pmap_remove(pmap, sva, eva);
        return;
    }

    p = (prot & VM_PROT_WRITE) ? PG_D : 0;

    if (!pmap->pm_segtab) {
        /*
         * Change entries in kernel pmap.
         * This will trap if the page is writeable (in order to set
         * the dirty bit) even if the dirty bit is already set. The
         * optimization isn't worth the effort since this code isn't
         * executed much. The common case is to make a user page
         * read-only.
         */
#ifdef DIAGNOSTIC
        if (sva < VM_MIN_KERNEL_ADDRESS || eva > virtual_end)
            panic("pmap_protect: kva not in range");
#endif
        pte = kvtopte(sva);
        for (; sva < eva; sva += NBPG, pte++) {
            entry = pte->pt_entry;
            if (!(entry & PG_V))
                continue;
            entry = (entry & ~PG_D) | p;
            pte->pt_entry = entry;
            /*
             * Update the TLB if the given address is in the cache.
             */
            tlb_update(sva, pte);
        }
        return;
    }

#ifdef DIAGNOSTIC
    if (eva > VM_MAXUSER_ADDRESS)
        panic("pmap_protect: uva not in range");
#endif
    while (sva < eva) {
        nssva = mips_trunc_seg(sva) + NBSEG;
        if (nssva == 0 || nssva > eva)
            nssva = eva;
        /*
         * If VA belongs to an unallocated segment,
         * skip to the next segment boundary.
         */
        if (!(pte = pmap_segmap(pmap, sva))) {
            sva = nssva;
            continue;
        }
        /*
         * Change protection on every valid mapping within this segment.
         */
        pte += (sva >> PGSHIFT) & (NPTEPG - 1);
        for (; sva < nssva; sva += NBPG, pte++) {
            entry = pte->pt_entry;
            if (!(entry & PG_V))
                continue;
            entry = (entry & ~PG_D) | p;
            pte->pt_entry = entry;
            /*
             * Update the TLB if the given address is in the cache.
             */
            if (pmap->pm_tlbgen == tlbpid_gen)
                tlb_update(sva | pmap->pm_tlbpid, pte);
        }
    }
}

/*
 *      Insert the given physical page (p) at
 *      the specified virtual address (v) in the
 *      target physical map with the protection requested.
 *
 *      If specified, the page will be wired down, meaning
 *      that the related pte can not be reclaimed.
 *
 *      NB:  This is the only routine which MAY NOT lazy-evaluate
 *      or lose information.  That is, this routine must actually
 *      insert this page into the given map NOW.
 */
void
pmap_enter(pmap, va, pa, prot, wired)
    register pmap_t pmap;
    vm_offset_t va;
    register vm_offset_t pa;
    vm_prot_t prot;
    boolean_t wired;
{
    register pt_entry_t *pte;
    register u_int npte;
    vm_page_t mem;

#ifdef DIAGNOSTIC
    if (!pmap)
        panic("pmap_enter: pmap");
    if (!pmap->pm_segtab) {
        if (va < VM_MIN_KERNEL_ADDRESS || va >= virtual_end)
            panic("pmap_enter: kva");
    } else {
        if (va >= VM_MAXUSER_ADDRESS)
            panic("pmap_enter: uva");
    }
    if (pa & 0x80000000)
        panic("pmap_enter: pa");
    if (!(prot & VM_PROT_READ))
        panic("pmap_enter: prot");
#endif

    if (IS_VM_PHYSADDR(pa)) {
        register pv_entry_t pv, npv;
        int s;

        npte = 0;
        if (prot & VM_PROT_WRITE) {
            register vm_page_t mem;

            mem = PHYS_TO_VM_PAGE(pa);
            if ((int)va < 0) {
                /*
                 * Don't bother to trap on kernel writes,
                 * just record page as dirty.
                 */
                npte = PG_D;
                mem->flags &= ~PG_CLEAN;
            } else if (
#ifdef ATTR
                (pmap_attributes[atop(pa)] & PMAP_ATTR_MOD) ||
#endif
                !(mem->flags & PG_CLEAN)) {

                npte = PG_D;
                mem->flags &= ~PG_CLEAN;
            }
        }

        /*
         * Enter the pmap and virtual address into the
         * physical to virtual map table.
         */
        pv = pa_to_pvh(pa);
        s = splimp();
        if (pv->pv_pmap == NULL) {
            /*
             * No entries yet, use header as the first entry
             */
            pv->pv_va = va;
            pv->pv_pmap = pmap;
            pv->pv_next = NULL;
        } else {
            /*
             * There is at least one other VA mapping this page.
             * Place this entry after the header.
             *
             * Note: the entry may already be in the table if
             * we are only changing the protection bits.
             */
            for (npv = pv; npv; npv = npv->pv_next) {
                if (pmap == npv->pv_pmap && va == npv->pv_va) {
#ifdef DIAGNOSTIC
                    unsigned entry;

                    if (!pmap->pm_segtab)
                        entry = kvtopte(va)->pt_entry;
                    else {
                        pte = pmap_segmap(pmap, va);
                        if (pte) {
                            pte += (va >> PGSHIFT) &
                                (NPTEPG - 1);
                            entry = pte->pt_entry;
                        } else
                            entry = 0;
                    }
                    if (!(entry & PG_V) ||
                        (PG_FRAME(entry)) != pa)
                        printf(
            "pmap_enter: found va %x pa %x in pv_table but != %x\n",
                            va, pa, entry);
#endif
                    goto fnd;
                }
            }
            /* can this cause us to recurse forever? */
            npv = (pv_entry_t)
                malloc(sizeof *npv, M_VMPVENT, M_NOWAIT);
            if (! npv)
                panic("pmap_enter: malloc failed");
            npv->pv_va = va;
            npv->pv_pmap = pmap;
            npv->pv_next = pv->pv_next;
            pv->pv_next = npv;
        fnd:
            ;
        }
        splx(s);
    } else {
        /*
         * Assumption: if it is not part of our managed memory
         * then it must be device memory which may be volatile.
         */
        npte = 0;
        if (prot & VM_PROT_WRITE)
            npte |= PG_D;
    }

    /*
     * The only time we need to flush the cache is if we
     * execute from a physical address and then change the data.
     * This is the best place to do this.
     * pmap_protect() and pmap_remove() are mostly used to switch
     * between R/W and R/O pages.
     * NOTE: we only support cache flush for read only text.
     */
    if (prot == (VM_PROT_READ | VM_PROT_EXECUTE))
        mips_flush_icache(MACH_PHYS_TO_UNCACHED(pa), PAGE_SIZE);

    if (!pmap->pm_segtab) {
        /* enter entries into kernel pmap */
        pte = kvtopte(va);
        npte |= PG_PFNUM(pa) | PG_V | PG_G | PG_UNCACHED;
        if (wired) {
            pmap->pm_stats.wired_count += 1;
            npte |= PG_WIRED;
        }
        if (!(pte->pt_entry & PG_V)) {
            pmap->pm_stats.resident_count++;
        } else if (npte != pte->pt_entry) {
#ifdef DIAGNOSTIC
            if (pte->pt_entry & PG_WIRED)
                panic("pmap_enter: kernel wired");
#endif
        }
        pte->pt_entry = npte;

        /* Replicate G bit to paired even/odd entry. */
        if (va & (1 << PGSHIFT))
            pte[-1].pt_entry |= PG_G;
        else
            pte[1].pt_entry |= PG_G;

        /*
         * Update the same virtual address entry.
         */
//printf ("--- %s(pa = %08x) update tlb: va = %08x, npte = %08x \n", __func__, pa, va, npte);
        tlb_update(va, pte);
        return;
    }

    pte = pmap_segmap(pmap, va);
    if (! pte) {
        mem = vm_page_alloc1();
        pmap_zero_page(VM_PAGE_TO_PHYS(mem));
        pte = (pt_entry_t *) MACH_PHYS_TO_UNCACHED(VM_PAGE_TO_PHYS(mem));
        pmap_segmap(pmap, va) = pte;
    }
    pte += (va >> PGSHIFT) & (NPTEPG - 1);
    if (!(pte->pt_entry & PG_V))
        pmap->pm_stats.resident_count++;

    /*
     * Now validate mapping with desired protection/wiring.
     * Assume uniform modified and referenced status for all
     * MIPS pages in a MACH page.
     */
    npte |= PG_PFNUM(pa) | PG_V | PG_UNCACHED;
    if (wired) {
        pmap->pm_stats.wired_count += 1;
        npte |= PG_WIRED;
    }
    pte->pt_entry = npte;
    if (pmap->pm_tlbgen == tlbpid_gen)
        tlb_update(va | pmap->pm_tlbpid, pte);
}

/*
 *      Routine:        pmap_change_wiring
 *      Function:       Change the wiring attribute for a map/virtual-address
 *                      pair.
 *      In/out conditions:
 *                      The mapping must already exist in the pmap.
 */
void
pmap_change_wiring(pmap, va, wired)
    register pmap_t pmap;
    vm_offset_t va;
    boolean_t wired;
{
    register pt_entry_t *pte;
    u_int p;

    if (pmap == NULL)
        return;

    p = wired ? PG_WIRED : 0;

    /*
     * Don't need to flush the TLB since PG_WIRED is only in software.
     */
    if (!pmap->pm_segtab) {
        /* change entries in kernel pmap */
#ifdef DIAGNOSTIC
        if (va < VM_MIN_KERNEL_ADDRESS || va >= virtual_end)
            panic("pmap_change_wiring");
#endif
        pte = kvtopte(va);
    } else {
        if (!(pte = pmap_segmap(pmap, va)))
            return;
        pte += (va >> PGSHIFT) & (NPTEPG - 1);
    }

    if (!(pte->pt_entry & PG_WIRED) && wired)
        pmap->pm_stats.wired_count += 1;
    else if ((pte->pt_entry & PG_WIRED) && !wired)
        pmap->pm_stats.wired_count -= 1;

    if (pte->pt_entry & PG_V) {
        pte->pt_entry &= ~PG_WIRED;
        pte->pt_entry |= p;
    }
}

/*
 *      Routine:        pmap_extract
 *      Function:
 *              Extract the physical page address associated
 *              with the given map/virtual_address pair.
 */
vm_offset_t
pmap_extract(pmap, va)
    register pmap_t pmap;
    vm_offset_t va;
{
    register vm_offset_t pa;

    if (!pmap->pm_segtab) {
#ifdef DIAGNOSTIC
        if (va < VM_MIN_KERNEL_ADDRESS || va >= virtual_end)
            panic("pmap_extract");
#endif
        pa = PG_FRAME(kvtopte(va)->pt_entry);
    } else {
        register pt_entry_t *pte;

        if (!(pte = pmap_segmap(pmap, va)))
            pa = 0;
        else {
            pte += (va >> PGSHIFT) & (NPTEPG - 1);
            pa = PG_FRAME(pte->pt_entry);
        }
    }
    if (pa)
        pa |= va & PGOFSET;

    return (pa);
}

/*
 *      Copy the range specified by src_addr/len
 *      from the source map to the range dst_addr/len
 *      in the destination map.
 *
 *      This routine is only advisory and need not do anything.
 */
void
pmap_copy(dst_pmap, src_pmap, dst_addr, len, src_addr)
    pmap_t dst_pmap;
    pmap_t src_pmap;
    vm_offset_t dst_addr;
    vm_size_t len;
    vm_offset_t src_addr;
{
}

/*
 *      Require that all active physical maps contain no
 *      incorrect entries NOW.  [This update includes
 *      forcing updates of any address map caching.]
 *
 *      Generally used to insure that a thread about
 *      to run will see a semantically correct world.
 */
void
pmap_update()
{
}

/*
 *      Routine:        pmap_collect
 *      Function:
 *              Garbage collects the physical map system for
 *              pages which are no longer used.
 *              Success need not be guaranteed -- that is, there
 *              may well be pages which are not referenced, but
 *              others may be collected.
 *      Usage:
 *              Called by the pageout daemon when pages are scarce.
 */
void
pmap_collect(pmap)
    pmap_t pmap;
{
}

/*
 *      pmap_zero_page zeros the specified (machine independent)
 *      page.
 */
void
pmap_zero_page(phys)
    vm_offset_t phys;
{
    register int *p, *end;

    p = (int *)MACH_PHYS_TO_UNCACHED(phys);
    end = p + PAGE_SIZE / sizeof(int);
    do {
        p[0] = 0;
        p[1] = 0;
        p[2] = 0;
        p[3] = 0;
        p += 4;
    } while (p != end);
}

/*
 *      pmap_copy_page copies the specified (machine independent)
 *      page.
 */
void
pmap_copy_page(src, dst)
    vm_offset_t src, dst;
{
    register int *s, *d, *end;
    register int tmp0, tmp1, tmp2, tmp3;

    s = (int *)MACH_PHYS_TO_UNCACHED(src);
    d = (int *)MACH_PHYS_TO_UNCACHED(dst);
    end = s + PAGE_SIZE / sizeof(int);
    do {
        tmp0 = s[0];
        tmp1 = s[1];
        tmp2 = s[2];
        tmp3 = s[3];
        d[0] = tmp0;
        d[1] = tmp1;
        d[2] = tmp2;
        d[3] = tmp3;
        s += 4;
        d += 4;
    } while (s != end);
}

/*
 *      Routine:        pmap_pageable
 *      Function:
 *              Make the specified pages (by pmap, offset)
 *              pageable (or not) as requested.
 *
 *              A page which is not pageable may not take
 *              a fault; therefore, its page table entry
 *              must remain valid for the duration.
 *
 *              This routine is merely advisory; pmap_enter
 *              will specify that these pages are to be wired
 *              down (or not) as appropriate.
 */
void
pmap_pageable(pmap, sva, eva, pageable)
    pmap_t          pmap;
    vm_offset_t     sva, eva;
    boolean_t       pageable;
{
}

/*
 *      Clear the modify bits on the specified physical page.
 */
void
pmap_clear_modify(pa)
    vm_offset_t pa;
{
#ifdef ATTR
    pmap_attributes[atop(pa)] &= ~PMAP_ATTR_MOD;
#endif
}

/*
 *      pmap_clear_reference:
 *
 *      Clear the reference bit on the specified physical page.
 */
void
pmap_clear_reference(pa)
    vm_offset_t pa;
{
#ifdef ATTR
    pmap_attributes[atop(pa)] &= ~PMAP_ATTR_REF;
#endif
}

/*
 *      pmap_is_referenced:
 *
 *      Return whether or not the specified physical page is referenced
 *      by any physical maps.
 */
boolean_t
pmap_is_referenced(pa)
    vm_offset_t pa;
{
#ifdef ATTR
    return (pmap_attributes[atop(pa)] & PMAP_ATTR_REF);
#else
    return (FALSE);
#endif
}

/*
 *      pmap_is_modified:
 *
 *      Return whether or not the specified physical page is modified
 *      by any physical maps.
 */
boolean_t
pmap_is_modified(pa)
    vm_offset_t pa;
{
#ifdef ATTR
    return (pmap_attributes[atop(pa)] & PMAP_ATTR_MOD);
#else
    return (FALSE);
#endif
}

vm_offset_t
pmap_phys_address(ppn)
    int ppn;
{
    return (mips_ptob(ppn));
}

/*
 * Miscellaneous support routines
 */

/*
 * Allocate a hardware PID and return it.
 * It takes almost as much or more time to search the TLB for a
 * specific PID and flush those entries as it does to flush the entire TLB.
 * Therefore, when we allocate a new PID, we just take the next number. When
 * we run out of numbers, we flush the TLB, increment the generation count
 * and start over. PID zero is reserved for kernel use.
 * This is called only by switch().
 */
int
pmap_alloc_tlbpid(p)
    register struct proc *p;
{
    register pmap_t pmap;
    register int id;

    pmap = &p->p_vmspace->vm_pmap;
    if (pmap->pm_tlbgen != tlbpid_gen) {
        id = tlbpid_cnt;
        if (id == VMMACH_NUM_PIDS) {
            tlb_flush();
            /* reserve tlbpid_gen == 0 to alway mean invalid */
            if (++tlbpid_gen == 0)
                tlbpid_gen = 1;
            id = 1;
        }
        tlbpid_cnt = id + 1;
        pmap->pm_tlbpid = id;
        pmap->pm_tlbgen = tlbpid_gen;
    } else
        id = pmap->pm_tlbpid;

    return (id);
}

/*
 * Remove a physical to virtual address translation.
 */
void
pmap_remove_pv(pmap, va, pa)
    pmap_t pmap;
    vm_offset_t va, pa;
{
    register pv_entry_t pv, npv;
    int s;

    /*
     * Remove page from the PV table (raise IPL since we
     * may be called at interrupt time).
     */
    if (!IS_VM_PHYSADDR(pa))
        return;
    pv = pa_to_pvh(pa);
    s = splimp();
    /*
     * If it is the first entry on the list, it is actually
     * in the header and we must copy the following entry up
     * to the header.  Otherwise we must search the list for
     * the entry.  In either case we free the now unused entry.
     */
    if (pmap == pv->pv_pmap && va == pv->pv_va) {
        npv = pv->pv_next;
        if (npv) {
            *pv = *npv;
            free((caddr_t)npv, M_VMPVENT);
        } else
            pv->pv_pmap = NULL;
    } else {
        for (npv = pv->pv_next; npv; pv = npv, npv = npv->pv_next) {
            if (pmap == npv->pv_pmap && va == npv->pv_va)
                goto fnd;
        }
#ifdef DIAGNOSTIC
        printf("pmap_remove_pv(%x, %x, %x) not found\n", pmap, va, pa);
        panic("pmap_remove_pv");
#endif
    fnd:
        pv->pv_next = npv->pv_next;
        free((caddr_t)npv, M_VMPVENT);
    }
    splx(s);
}

/*
 *      vm_page_alloc1:
 *
 *      Allocate and return a memory cell with no associated object.
 */
vm_page_t
vm_page_alloc1()
{
    register vm_page_t      mem;
    int             spl;

    spl = splimp();                         /* XXX */
    simple_lock(&vm_page_queue_free_lock);
    if (vm_page_queue_free.tqh_first == NULL) {
        simple_unlock(&vm_page_queue_free_lock);
        splx(spl);
        return (NULL);
    }

    mem = vm_page_queue_free.tqh_first;
    TAILQ_REMOVE(&vm_page_queue_free, mem, pageq);

    cnt.v_free_count--;
    simple_unlock(&vm_page_queue_free_lock);
    splx(spl);

    mem->flags = PG_BUSY | PG_CLEAN | PG_FAKE;
    mem->wire_count = 0;

    /*
     *      Decide if we should poke the pageout daemon.
     *      We do this if the free count is less than the low
     *      water mark, or if the free count is less than the high
     *      water mark (but above the low water mark) and the inactive
     *      count is less than its target.
     *
     *      We don't have the counts locked ... if they change a little,
     *      it doesn't really matter.
     */

    if (cnt.v_free_count < cnt.v_free_min ||
        (cnt.v_free_count < cnt.v_free_target &&
         cnt.v_inactive_count < cnt.v_inactive_target))
        thread_wakeup(&vm_pages_needed);
    return (mem);
}

/*
 *      vm_page_free1:
 *
 *      Returns the given page to the free list,
 *      disassociating it with any VM object.
 *
 *      Object and page must be locked prior to entry.
 */
void
vm_page_free1(mem)
    register vm_page_t      mem;
{

    if (mem->flags & PG_ACTIVE) {
        TAILQ_REMOVE(&vm_page_queue_active, mem, pageq);
        mem->flags &= ~PG_ACTIVE;
        cnt.v_active_count--;
    }

    if (mem->flags & PG_INACTIVE) {
        TAILQ_REMOVE(&vm_page_queue_inactive, mem, pageq);
        mem->flags &= ~PG_INACTIVE;
        cnt.v_inactive_count--;
    }

    if (!(mem->flags & PG_FICTITIOUS)) {
        int     spl;

        spl = splimp();
        simple_lock(&vm_page_queue_free_lock);
        TAILQ_INSERT_TAIL(&vm_page_queue_free, mem, pageq);

        cnt.v_free_count++;
        simple_unlock(&vm_page_queue_free_lock);
        splx(spl);
    }
}
