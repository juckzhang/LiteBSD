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
 *  @(#)kern_fork.c 8.8 (Berkeley) 2/14/95
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/map.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/resourcevar.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/acct.h>
#include <sys/ktrace.h>
#include <vm/vm.h>

int nprocs = 1;     /* process 0 */

static int
fork1(p1, isvfork, retval)
    register struct proc *p1;
    int isvfork;
    register_t *retval;
{
    register struct proc *p2;
    register uid_t uid;
    struct proc *newproc;
    int count;
    static int nextpid, pidchecked = 0;

    /*
     * Although process entries are dynamically created, we still keep
     * a global limit on the maximum number we will create.  Don't allow
     * a nonprivileged user to use the last process; don't let root
     * exceed the limit. The variable nprocs is the current number of
     * processes, maxproc is the limit.
     * nprocs:当前进程数量。maxproc:允许存在的最大进程数量
     * 保证最后一个进程只能又超级用户创建
     */
    uid = p1->p_cred->p_ruid;
    if ((nprocs >= maxproc - 1 && uid != 0) || nprocs >= maxproc) {
        tablefull("proc");
        return (EAGAIN);
    }

    /*
     * Increment the count of procs running with this uid. Don't allow
     * a nonprivileged user to exceed their current limit.
     * 将用户拥有的进程数量加1，表示该用户马上要创建一个新进程了。
     * 判断该用户拥有的进程数量是不是超过限制，超过限制不让创建了（超级用户除外）
     */
    count = chgproccnt(uid, 1);
    if (uid != 0 && count > p1->p_rlimit[RLIMIT_NPROC].rlim_cur) {
        (void)chgproccnt(uid, -1);
        return (EAGAIN);
    }

    /* Allocate new proc. 给新进程分配内存个*/
    MALLOC(newproc, struct proc *, sizeof(struct proc), M_PROC, M_WAITOK);

    /*
     * Find an unused process ID.  We remember a range of unused IDs
     * ready to use (from nextpid+1 through pidchecked-1).
     * 以下这段是为了找到一个最小未使用的进程id分配给新进程。
     * 查找规则：nextpid：可能可使用的进程号。保证nextpid未出现在allproc与zombproc两个队列中。
     * 并且，也不能是一个存在的进程组id。否则nextpid++再次查找。
     */
    nextpid++;
retry:
    /*
     * If the process ID prototype has wrapped around,
     * restart somewhat above 0, as the low-numbered procs
     * tend to include daemons that don't exit.
     */
    if (nextpid >= PID_MAX) {
        nextpid = 100;
        pidchecked = 0;
    }
    if (nextpid >= pidchecked) {
        int doingzomb = 0;

        pidchecked = PID_MAX;
        /*
         * Scan the active and zombie procs to check whether this pid
         * is in use.  Remember the lowest pid that's greater
         * than nextpid, so we can avoid checking for a while.
         */
        p2 = allproc.lh_first;
again:
        for (; p2 != 0; p2 = p2->p_list.le_next) {
            while (p2->p_pid == nextpid ||
                p2->p_pgrp->pg_id == nextpid) {
                nextpid++;
                if (nextpid >= pidchecked)
                    goto retry;
            }
            if (p2->p_pid > nextpid && pidchecked > p2->p_pid)
                pidchecked = p2->p_pid;
            if (p2->p_pgrp->pg_id > nextpid &&
                pidchecked > p2->p_pgrp->pg_id)
                pidchecked = p2->p_pgrp->pg_id;
        }
        if (!doingzomb) {
            doingzomb = 1;
            p2 = zombproc.lh_first;
            goto again;
        }
    }//已经找到一个最小未使用的进程号
	
    nprocs++;//已创建进程数加1.
    p2 = newproc;
    p2->p_stat = SIDL;          /* 设置进程状态为SIDL */
    p2->p_pid = nextpid;
    LIST_INSERT_HEAD(&allproc, p2, p_list);//将新进程插入allproc队列
    p2->p_forw = p2->p_back = NULL;     /* shouldn't be necessary */
    LIST_INSERT_HEAD(PIDHASH(p2->p_pid), p2, p_hash);

    /*
     * Make a proc table entry for the new process.
     * Start by zeroing the section of proc that is zero-initialized,
     * then copy the section that is copied directly from the parent.
     */
    bzero(&p2->p_startzero,
        (unsigned) ((caddr_t)&p2->p_endzero - (caddr_t)&p2->p_startzero));
    bcopy(&p1->p_startcopy, &p2->p_startcopy,
        (unsigned) ((caddr_t)&p2->p_endcopy - (caddr_t)&p2->p_startcopy));

    /*
     * Duplicate sub-structures as needed.
     * Increase reference counts on shared objects.
     * The p_stats and p_sigacts substructs are set in vm_fork.
     */
    p2->p_flag = P_INMEM;
    if (p1->p_flag & P_PROFIL)//继承父进程的P_PROFIL标志。所有的用户进程都会设置这个标志
        startprofclock(p2);
    MALLOC(p2->p_cred, struct pcred *, sizeof(struct pcred),
        M_SUBPROC, M_WAITOK);
    bcopy(p1->p_cred, p2->p_cred, sizeof(*p2->p_cred));
    p2->p_cred->p_refcnt = 1;
    crhold(p1->p_ucred);

    /* bump references to the text vnode (for procfs) */
    p2->p_textvp = p1->p_textvp;//子进程与父进程共享代码段副本
    if (p2->p_textvp)
        VREF(p2->p_textvp);//增加代码段的引用计数器

    p2->p_fd = fdcopy(p1);//拷贝文件描述符信息
    /*
     * If p_limit is still copy-on-write, bump refcnt,
     * otherwise get a copy that won't be modified.
     * (If PL_SHAREMOD is clear, the structure is shared
     * copy-on-write.)
     * 设置子进程的资源限制信息
     */
    if (p1->p_limit->p_lflags & PL_SHAREMOD)
        p2->p_limit = limcopy(p1->p_limit);
    else {
        p2->p_limit = p1->p_limit;
        p2->p_limit->p_refcnt++;
    }

    if (p1->p_session->s_ttyvp != NULL && p1->p_flag & P_CONTROLT)
        p2->p_flag |= P_CONTROLT;//标记子进程是否有控制终端（deamon进程没有控制终端）
    if (isvfork)//如果是vfork调用，标记子进程为父进程在等待子进程执行。
        p2->p_flag |= P_PPWAIT;
    LIST_INSERT_AFTER(p1, p2, p_pglist);
    p2->p_pptr = p1;
    LIST_INSERT_HEAD(&p1->p_children, p2, p_sibling);
    LIST_INIT(&p2->p_children);//初始化新进程的子进程结构

#ifdef KTRACE
    /*
     * Copy traceflag and tracefile if enabled.
     * If not inherited, these were zeroed above.
     */
    if (p1->p_traceflag&KTRFAC_INHERIT) {
        p2->p_traceflag = p1->p_traceflag;
        if ((p2->p_tracep = p1->p_tracep) != NULL)
            VREF(p2->p_tracep);
    }
#endif

    /*
     * This begins the section where we must prevent the parent
     * from being swapped.
     */
    p1->p_flag |= P_NOSWAP;//标记父进程不能被换出.
    /*
     * Set return values for child before vm_fork,
     * so they can be copied to child stack.
     * We return parent pid, and mark as child in retval[1].
     * NOTE: the kernel stack may be at a different location in the child
     * process, and thus addresses of automatic variables (including retval)
     * may be invalid after vm_fork returns in the child process.
     */
    retval[0] = p1->p_pid;
    retval[1] = 1;
    if (vm_fork(p1, p2, isvfork)) {//拷贝进程的上下文信息（延迟拷贝）
        /*
         * Child process.  Set start time and get to work.
         */
        (void) splclock();
        p2->p_stats->p_start = time;//资源统计的开始时间
        (void) spl0();
        p2->p_acflag = AFORK;
        return (0);
    }

    /*
     * Make child runnable and add to run queue.
     */
    (void) splhigh();
    p2->p_stat = SRUN;
    setrunqueue(p2);//将子进程加入可运行队列
    (void) spl0();

    /*
     * Now can be swapped.
     */
    p1->p_flag &= ~P_NOSWAP;

    /*
     * Preserve synchronization semantics of vfork.  If waiting for
     * child to exec or exit, set P_PPWAIT on child, and sleep on our
     * proc (in case of exit).
     * 如果是vfork 标记子进程为父进程在等待它先执行。并且让父进程sleep
     */
    if (isvfork)
        while (p2->p_flag & P_PPWAIT)
            tsleep(p1, PWAIT, "ppwait", 0);

    /*
     * Return child pid to parent process,
     * marking us as parent via retval[1].
     * 貌似并没有看到有返回-1的情况。
     */
    retval[0] = p2->p_pid;//父进程返回子进程id
    retval[1] = 0;//子进程返回0
    return (0);
}

/* ARGSUSED */
int
fork(p, uap, retval)
    struct proc *p;
    void *uap;
    register_t *retval;
{
    return (fork1(p, 0, retval));
}

/* ARGSUSED */
int
vfork(p, uap, retval)
    struct proc *p;
    void *uap;
    register_t *retval;
{
    return (fork1(p, 1, retval));
}
