/*
 * Copyright (c) 1982, 1986, 1989, 1991, 1993
 *  The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
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
 *  This product includes software developed by the University of
 *  California, Berkeley and its contributors.
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
 *  @(#)kern_exit.c 8.10 (Berkeley) 2/23/95
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/map.h>
#include <sys/ioctl.h>
#include <sys/proc.h>
#include <sys/tty.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/kernel.h>
#include <sys/buf.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <sys/vnode.h>
#include <sys/syslog.h>
#include <sys/malloc.h>
#include <sys/resourcevar.h>
#include <sys/ptrace.h>
#include <sys/filedesc.h>
#include <sys/signalvar.h>
#include <sys/acct.h>

#include <machine/cpu.h>

#include <vm/vm.h>
#include <vm/vm_kern.h>

__dead void cpu_exit __P((struct proc *));
__dead void exit1 __P((struct proc *, int));

/*
 * exit --
 *  Death of process.
 */
struct rexit_args {
    int rval;
};
__dead void
exit(p, uap, retval)
    struct proc *p;
    struct rexit_args *uap;
    int *retval;
{
    exit1(p, W_EXITCODE(uap->rval, 0));
    /* NOTREACHED */
}

/*
 * Exit: deallocate address space and other resources, change proc state
 * to zombie, and unlink proc from allproc and parent's lists.  Save exit
 * status and rusage for wait().  Check for child processes and orphan them.
 * 进程退出
 */
__dead void
exit1(p, rv)
    register struct proc *p;
    int rv;
{
    register struct proc *q, *nq;
    register struct vmspace *vm;

    if (p->p_pid == 1)//init进程不能退出
        panic("init died (signal %d, exit %d)",
            WTERMSIG(rv), WEXITSTATUS(rv));
#ifdef PGINPROF
    vmsizmon();
#endif
    if (p->p_flag & P_PROFIL)//关闭用户进程的资源统计定时器
        stopprofclock(p);
    MALLOC(p->p_ru, struct rusage *, sizeof(struct rusage),
        M_ZOMBIE, M_WAITOK);
    /*
     * If parent is waiting for us to exit or exec,
     * P_PPWAIT is set; we will wakeup the parent below.
     */
    p->p_flag &= ~(P_TRACED | P_PPWAIT);
    p->p_flag |= P_WEXIT;//进程标记为正在退出中
    p->p_sigignore = ~0;//忽略所有信号
    p->p_siglist = 0;//清除未决信号
    untimeout(realitexpire, (caddr_t)p);//清除用户模式下的资源定时器

    /*
     * Close open files and release open-file table.
     * This may block!
     */
    fdfree(p);//关闭打开的文件句柄，释放文件资源

    /* The next two chunks should probably be moved to vmspace_exit. */
    vm = p->p_vmspace;
#ifdef SYSVSHM
    if (vm->vm_shm)
        shmexit(p);
#endif
    /*
     * Release user portion of address space.
     * This releases references to vnodes,
     * which could cause I/O if the file has been unlinked.
     * Need to do this early enough that we can still sleep.
     * Can't free the entire vmspace as the kernel stack
     * may be mapped within that space also.
     * 释放用户地址空间
     */
    if (vm->vm_refcnt == 1)//清除用户地址空间
        (void) vm_map_remove(&vm->vm_map, VM_MIN_ADDRESS,
            VM_MAXUSER_ADDRESS);

    if (SESS_LEADER(p)) {
        register struct session *sp = p->p_session;

        if (sp->s_ttyvp) {
            /*
             * Controlling process.
             * Signal foreground pgrp,
             * drain controlling terminal
             * and revoke access to controlling terminal.
             * 如果是一个终端控制进程。给该会话下的所有进程发送一个终端退出信号
             */
            if (sp->s_ttyp->t_session == sp) {
                if (sp->s_ttyp->t_pgrp)
                    pgsignal(sp->s_ttyp->t_pgrp, SIGHUP, 1);
                (void) ttywait(sp->s_ttyp);
                /*
                 * The tty could have been revoked
                 * if we blocked.
                 */
                if (sp->s_ttyvp)//撤销终端
                    VOP_REVOKE(sp->s_ttyvp, REVOKEALL);
            }
            if (sp->s_ttyvp)
                vrele(sp->s_ttyvp);
            sp->s_ttyvp = NULL;
            /*
             * s_ttyp is not zero'd; we use this to indicate
             * that the session once had a controlling terminal.
             * (for logging and informational purposes)
             */
        }
        sp->s_leader = NULL;
    }
    fixjobc(p, p->p_pgrp, 0);
    p->p_rlimit[RLIMIT_FSIZE].rlim_cur = RLIM_INFINITY;
    (void)acct_process(p);//打印进程信息
#ifdef KTRACE
    /*
     * release trace file
     */
    p->p_traceflag = 0; /* don't trace the vrele() */
    if (p->p_tracep)
        vrele(p->p_tracep);
#endif
    /*
     * Remove proc from allproc queue and pidhash chain.
     * Place onto zombproc.  Unlink from parent's child list.
     */
    LIST_REMOVE(p, p_list);//将进程从allproc队列移到zombproc队列中
    LIST_INSERT_HEAD(&zombproc, p, p_list);
    p->p_stat = SZOMB;

    LIST_REMOVE(p, p_hash);

    q = p->p_children.lh_first;
    if (q)      /* only need this if any child is S_ZOMB */
        wakeup((caddr_t) initproc);//唤醒init进程去接收p的子进程信息，防止子进程一直处于zomb状态
    for (; q != 0; q = nq) {
        nq = q->p_sibling.le_next;
        LIST_REMOVE(q, p_sibling);
        LIST_INSERT_HEAD(&initproc->p_children, q, p_sibling);
        q->p_pptr = initproc;
        /*
         * Traced processes are killed
         * since their existence means someone is screwing up.
         */
        if (q->p_flag & P_TRACED) {
            q->p_flag &= ~P_TRACED;
            psignal(q, SIGKILL);
        }
    }

    /*
     * Save exit status and final rusage info, adding in child rusage
     * info and self times.
     */
    p->p_xstat = rv;//退出状态
    *p->p_ru = p->p_stats->p_ru;
    calcru(p, &p->p_ru->ru_utime, &p->p_ru->ru_stime, NULL);
    ruadd(p->p_ru, &p->p_stats->p_cru);

    /*
     * Notify parent that we're gone.
     */
    psignal(p->p_pptr, SIGCHLD);//给父进程发送SIGCHLD信号
    wakeup((caddr_t)p->p_pptr);//唤醒父进程去接收该进程退出信息
#if defined(tahoe)
    /* move this to cpu_exit */
    p->p_addr->u_pcb.pcb_savacc.faddr = (float *)NULL;
#endif
    /*
     * Clear curproc after we've done all operations
     * that could block, and before tearing down the rest
     * of the process state that might be used from clock, etc.
     * Also, can't clear curproc while we're still runnable,
     * as we're not on a run queue (we are current, just not
     * a proper proc any longer!).
     *
     * Other substructures are freed from wait().
     */
    curproc = NULL;//清除p_limit
    if (--p->p_limit->p_refcnt == 0)
        FREE(p->p_limit, M_SUBPROC);

    /*
     * Finally, call machine-dependent code to release the remaining
     * resources including address space, the kernel stack and pcb.
     * The address space is released by "vmspace_free(p->p_vmspace)";
     * This is machine-dependent, as we may have to change stacks
     * or ensure that the current one isn't reallocated before we
     * finish.  cpu_exit will end with a call to cpu_swtch(), finishing
     * our execution (pun intended).
     * 这部分是机器依赖相关代码的执行。包括释放地址空间，内核栈，以及进程控制块
     */
    cpu_exit(p);
}

struct wait_args {
    int pid;//退出的进程id
    int *status;//退出进程的状态对应p->p_xstat
    int options;//
    struct  rusage *rusage;//资源使用情况对应p->p_ru
};

#define wait1   wait4

int
wait1(q, uap, retval)
    register struct proc *q;
    register struct wait_args *uap;
    int retval[];
{
    register int nfound;
    register struct proc *p, *t;
    int status, error;

    if (uap->pid == 0)
        uap->pid = -q->p_pgid;
#ifdef notyet
    if (uap->options &~ (WUNTRACED|WNOHANG))
        return (EINVAL);
#endif
loop:
    nfound = 0;
    for (p = q->p_children.lh_first; p != 0; p = p->p_sibling.le_next) {
        if (uap->pid != WAIT_ANY &&
            p->p_pid != uap->pid && p->p_pgid != -uap->pid)
            continue;
        nfound++;
        if (p->p_stat == SZOMB) {
            retval[0] = p->p_pid;
            if (uap->status) {
                status = p->p_xstat;    /* convert to int */
                error = copyout((caddr_t)&status,
                    (caddr_t)uap->status, sizeof(status));
                if (error)
                    return (error);
            }
            if (uap->rusage && (error = copyout((caddr_t)p->p_ru,
                (caddr_t)uap->rusage, sizeof (struct rusage))))
                return (error);
            /*
             * If we got the child via a ptrace 'attach',
             * we need to give it back to the old parent.
             */
            if (p->p_oppid && (t = pfind(p->p_oppid))) {
                p->p_oppid = 0;
                proc_reparent(p, t);
                psignal(t, SIGCHLD);
                wakeup((caddr_t)t);
                return (0);
            }
            p->p_xstat = 0;
            ruadd(&q->p_stats->p_cru, p->p_ru);
            FREE(p->p_ru, M_ZOMBIE);

            /*
             * Decrement the count of procs running with this uid.
             */
            (void)chgproccnt(p->p_cred->p_ruid, -1);//减少用户拥有的进程数

            /*
             * Free up credentials.
             */
            if (--p->p_cred->p_refcnt == 0) {//减少用户的引用计数器
                crfree(p->p_cred->pc_ucred);
                FREE(p->p_cred, M_SUBPROC);
            }

            /*
             * Release reference to text vnode
             */
            if (p->p_textvp)//减少代码段的引用计数器
                vrele(p->p_textvp);

            /*
             * Finally finished with old proc entry.
             * Unlink it from its process group and free it.
             */
            leavepgrp(p);//将进程从进程组中移除
            LIST_REMOVE(p, p_list); /* off zombproc */
            LIST_REMOVE(p, p_sibling);

            /*
             * Give machine-dependent layer a chance
             * to free anything that cpu_exit couldn't
             * release while still running in process context.
             */
            cpu_wait(p);//释放一些在cpu_exit函数中处理不了的资源，例如进程上下文信息
            FREE(p, M_PROC);
            nprocs--;//当前系统的进程数量减1；
            return (0);
        }
        if (p->p_stat == SSTOP && (p->p_flag & P_WAITED) == 0 &&
            (p->p_flag & P_TRACED || uap->options & WUNTRACED)) {
            p->p_flag |= P_WAITED;
            retval[0] = p->p_pid;
            if (uap->status) {
                status = W_STOPCODE(p->p_xstat);
                error = copyout((caddr_t)&status,
                    (caddr_t)uap->status, sizeof(status));
            } else
                error = 0;
            return (error);
        }
    }
    if (nfound == 0)
        return (ECHILD);
    if (uap->options & WNOHANG) {
        retval[0] = 0;
        return (0);
    }
    error = tsleep((caddr_t)q, PWAIT | PCATCH, "wait", 0);
    if (error)
        return (error);
    goto loop;
}

/*
 * make process 'parent' the new parent of process 'child'.
 * 重定向进程的父进程。一般会将退出进程的子进程重定向到init进程
 */
void
proc_reparent(child, parent)
    register struct proc *child;
    register struct proc *parent;
{

    if (child->p_pptr == parent)
        return;

    LIST_REMOVE(child, p_sibling);
    LIST_INSERT_HEAD(&parent->p_children, child, p_sibling);
    child->p_pptr = parent;
}
