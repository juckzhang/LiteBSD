/*-
 * Copyright (c) 1986, 1989, 1991, 1993
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
 *  @(#)proc.h  8.15 (Berkeley) 5/19/95
 */

#ifndef _SYS_PROC_H_
#define _SYS_PROC_H_

#include <machine/proc.h>       /* Machine-dependent proc substruct. */
#include <sys/select.h>         /* For struct selinfo. */
#include <sys/queue.h>

/*
 * One structure allocated per session.
 */
struct  session {
    int     s_count;                /* Ref cnt; pgrps in session. 会话中的进程组数量*/
    struct  proc *s_leader;         /* Session leader. 领导进程*/
    struct  vnode *s_ttyvp;         /* Vnode of controlling terminal. 控制终端的vnode节点*/
    struct  tty *s_ttyp;            /* Controlling terminal. 控制终端*/
    char    s_login[MAXLOGNAME];    /* Setlogin() name. 登录名*/
};

/*
 * One structure allocated per process group.
 */
struct  pgrp {
    LIST_ENTRY(pgrp) pg_hash;       /* Hash chain. */
    LIST_HEAD(, proc) pg_members;   /* Pointer to pgrp members. */
    struct  session *pg_session;    /* Pointer to session. */
    pid_t   pg_id;                  /* Pgrp id. */
    int     pg_jobc;                /* # procs qualifying pgrp for job control */
};

/*
 * Description of a process.
 *
 * This structure contains the information needed to manage a thread of
 * control, known in UN*X as a process; it has references to substructures
 * containing descriptions of things that the process uses, but may share
 * with related processes.  The process structure and the substructures
 * are always addressible except for those marked "(PROC ONLY)" below,
 * which might be addressible only on a processor on which the process
 * is running.
 */
struct  proc {
    struct  proc *p_forw;       //这个指针没搞懂/* Doubly-linked run/sleep queue. */
    struct  proc *p_back; //下一个可运行进程（或者sleep进程）
    LIST_ENTRY(proc) p_list;    /* List of all processes. */

    /* substructures: */
    struct  pcred *p_cred;      /* Process owner's identity. 用户身份信息*/
    struct  filedesc *p_fd;     /* Ptr to open files structure. 当前进程打开的文件信息*/
    struct  pstats *p_stats;    /* Accounting/statistics (PROC ONLY). 统计信息*/
    struct  plimit *p_limit;    /* Process limits. 资源限制信息*/
    struct  vmspace *p_vmspace; /* Address space. 虚拟地址空间分配管理结构*/
    struct  sigacts *p_sigacts; /* Signal actions, state (PROC ONLY). 信号*/

#define p_ucred     p_cred->pc_ucred
#define p_rlimit    p_limit->pl_rlimit

    int     p_flag;             /* P_* flags. 进程标志 往往需要结合p_stat一起使用*/
    char    p_stat;             /* S* process status. */
    char    p_pad1[3];

    pid_t   p_pid;              /* Process identifier. 进程id*/
    LIST_ENTRY(proc) p_pglist;  /* List of processes in pgrp. 维护进程组中上一个与下一个进程的指针*/
    struct  proc *p_pptr;       /* Pointer to parent process. 父进程指针*/
    LIST_ENTRY(proc) p_sibling; /* 维护同属一个服务进程的兄弟进程指针 */
    LIST_HEAD(, proc) p_children; /* 子进程指针 */

/* The following fields are all zeroed upon creation in fork. */
#define p_startzero p_oppid //从此地方开始 当fork一个进程时，子进程会清零的值

    pid_t   p_oppid;            /* Save parent pid during ptrace. 保存在跟踪调试时的父进程idXXX */
    int     p_dupfd;            /* Sideways return value from fdopen. XXX */

    /* scheduling */
    u_int   p_estcpu;           /* 平均cpu使用时间 */
    int     p_cpticks;          /* cpu的时钟频率 */
    fixpt_t p_pctcpu;           /* %cpu for this process during p_swtime 在换入换出时，cpu使用率*/
    void    *p_wchan;           /* Sleep address. 进程休眠地址*/
    char    *p_wmesg;           /* Reason for sleep. 休眠原因*/
    u_int   p_swtime;           /* Time swapped in or out. 换入换出使用时间*/
    u_int   p_slptime;          /* Time since last blocked. 最近被阻塞的时间*/

    struct  itimerval p_realtimer;  /* Alarm timer. */
    struct  timeval p_rtime;    /* Real time. */
    u_quad_t p_uticks;          /* Statclock hits in user mode. */
    u_quad_t p_sticks;          /* Statclock hits in system mode. */
    u_quad_t p_iticks;          /* Statclock hits processing intr. */

    int     p_traceflag;        /* Kernel trace points. */
    struct  vnode *p_tracep;    /* Trace to vnode. */

    int     p_siglist;          /* Signals arrived but not delivered. 进程的未决信号集*/

    struct  vnode *p_textvp;    /* Vnode of executable. 指向进程代码段的指针*/

    short   p_locks;            /* DEBUG: lockmgr count of held locks 进程当前持有的锁数量*/
    short   p_simple_locks;     /* DEBUG: count of held simple locks 进程当前持有的简单锁数量*/
    long    p_spare[2];         /* pad to 256, avoid shifting eproc. 避免栈溢出的备用空间？？*/

/* End area that is zeroed on creation. */
#define p_endzero   p_hash.le_next //清零结束

    /*
     * Not copied, not zero'ed.
     * Belongs after p_pid, but here to avoid shifting proc elements.
     */
    LIST_ENTRY(proc) p_hash;    /* Hash chain. */

/* The following fields are all copied upon creation in fork. */
#define p_startcopy p_sigmask //此地方开始，fork一个进程时候，子进程会复制父进程的值

    sigset_t p_sigmask;         /* Current signal mask. */
    sigset_t p_sigignore;       /* Signals being ignored. */
    sigset_t p_sigcatch;        /* Signals being caught by user. */

    u_char  p_priority;         /* Process priority. */
    u_char  p_usrpri;           /* User-priority based on p_cpu and p_nice. */
    char    p_nice;             /* Process "nice" value. */
    char    p_comm[MAXCOMLEN+1];

    struct  pgrp *p_pgrp;       /* Pointer to process group. */

/* End area that is copied on creation. */
#define p_endcopy   p_thread

    void    *p_thread;          /* Id for this "thread"; Mach glue. XXX */
    struct  user *p_addr;       /* Kernel virtual addr of u-area (PROC ONLY). */
    struct  mdproc p_md;        /* Any machine-dependent fields. */

    u_short p_xstat;            /* Exit status for wait; also stop signal. 进程退出时的状态*/
    u_short p_acflag;           /* Accounting flags. 标记退出的原因*/
    struct  rusage *p_ru;       /* Exit information. XXX 退出时候的进程统计信息（进程退出时候在分配内存）*/
};

#define p_session   p_pgrp->pg_session
#define p_pgid      p_pgrp->pg_id

/* Status values. */
#define SIDL    1       /* Process being created by fork. 进程被fork创建*/
#define SRUN    2       /* Currently runnable. 可运行*/
#define SSLEEP  3       /* Sleeping on an address. 等待某个事件的完成而休眠*/
#define SSTOP   4       /* Process debugging or suspension. 被信号或父进程设置为暂停*/
#define SZOMB   5       /* Awaiting collection by parent. 进程退出，等待父进程接收退出信息*/

/* These flags are kept in p_flags. */
#define P_ADVLOCK   0x00001 /* Process may hold a POSIX advisory lock. */
#define P_CONTROLT  0x00002 /* 标记进程有控制终端*/
#define P_INMEM     0x00004 /* 进程已经被加载到内存中*/
#define P_NOCLDSTOP 0x00008 /* 子进程退出时，不发送SIGCHLD信号*/
#define P_PPWAIT    0x00010 /* 在子进程中标记父进程在等待子进程执行或者退出*/
#define P_PROFIL    0x00020 /* Has started profiling. */
#define P_SELECT    0x00040 /* Selecting; wakeup/waiting danger. */
#define P_SINTR     0x00080 /* 标记进程休眠被中断*/
#define P_SUGID     0x00100 /* Had set id privileges since last exec. */
#define P_SYSTEM    0x00200 /* 标记为系统进程（系统进程不接收信号，不统计资源信息，也不会被换出） */
#define P_TIMEOUT   0x00400 /* 休眠超时 */
#define P_TRACED    0x00800 /* 标记进程被跟踪调试 */
#define P_WAITED    0x01000 /* 标记一个debug进程在等待子进程*/
#define P_WEXIT     0x02000 /* 正在退出 */
#define P_EXEC      0x04000 /* Process called exec. 已执行*/

/* Should probably be changed into a hold count. */
#define P_NOSWAP    0x08000 /* 标记进程不能被换出 */
#define P_PHYSIO    0x10000 /* 标记进程正在处理物理I/O操作 */

/* Should be moved to machine-dependent areas. */
#define P_OWEUPC    0x20000 /* Owe process an addupc() call at next ast. */

/*
 * MOVE TO ucred.h?
 *
 * Shareable process credentials (always resident).  This includes a reference
 * to the current user credentials as well as real and saved ids that may be
 * used to change ids.
 */
struct  pcred {
    struct  ucred *pc_ucred;    /* Current credentials. 当前用户身份*/
    uid_t   p_ruid;             /* 真实用户id*/
    uid_t   p_svuid;            /* 保存的有效用户id */
    gid_t   p_rgid;             /* 真实组id */
    gid_t   p_svgid;            /* 保存的有效组id */
    int     p_refcnt;           /* Number of references. 引用计数器*/
};

#ifdef KERNEL
/*
 * We use process IDs <= PID_MAX; PID_MAX + 1 must also fit in a pid_t,
 * as it is used to represent "no process group".
 */
#define PID_MAX     30000
#define NO_PID      30001

#define SESS_LEADER(p)  ((p)->p_session->s_leader == (p))
#define SESSHOLD(s) ((s)->s_count++)
#define SESSRELE(s) { \
    if (--(s)->s_count == 0) \
        FREE(s, M_SESSION); \
}

#define PIDHASH(pid)    (&pidhashtbl[(pid) & pidhash])
extern LIST_HEAD(pidhashhead, proc) *pidhashtbl;
extern u_long pidhash;

#define PGRPHASH(pgid)  (&pgrphashtbl[(pgid) & pgrphash])
extern LIST_HEAD(pgrphashhead, pgrp) *pgrphashtbl;
extern u_long pgrphash;

extern struct proc *curproc;        /* Current running proc. */
extern struct proc proc0;           /* Process slot for swapper. */
extern int nprocs, maxproc;         /* Current and max number of procs. */

LIST_HEAD(proclist, proc);
extern struct proclist allproc;     /* List of all processes. */
extern struct proclist zombproc;    /* List of zombie processes. */
struct proc *initproc, *pageproc;   /* Process slots for init, pager. */

#define NQS 32              /* 32 run queues. 可运行对列有32个，根据进程优先级/4来进程分组*/
int whichqs;                /* Bit mask summary of non-empty Q's. */
struct  prochd {
    struct  proc *ph_link;          /* Linked list of running processes. */
    struct  proc *ph_rlink;
} qs[NQS];

struct proc *pfind __P((pid_t));    /* Find process by id. */
struct pgrp *pgfind __P((pid_t));   /* Find process group by id. */

int     chgproccnt __P((uid_t uid, int diff));
int     enterpgrp __P((struct proc *p, pid_t pgid, int mksess));
void    fixjobc __P((struct proc *p, struct pgrp *pgrp, int entering));
int     inferior __P((struct proc *p));
int     leavepgrp __P((struct proc *p));
void    mi_switch __P((void));
void    pgdelete __P((struct pgrp *pgrp));
void    procinit __P((void));
void    resetpriority __P((struct proc *));
void    setrunnable __P((struct proc *));
void    setrunqueue __P((struct proc *));
void    sleep __P((void *chan, int pri));
int     tsleep __P((void *chan, int pri, char *wmesg, int timo));
void    unsleep __P((struct proc *));
void    wakeup __P((void *chan));
#endif  /* KERNEL */
#endif  /* !_SYS_PROC_H_ */
