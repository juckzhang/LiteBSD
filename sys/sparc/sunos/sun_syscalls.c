/*
 * System call names.
 *
 * DO NOT EDIT-- this file is automatically generated.
 * created from @(#)syscalls.master 8.2 (Berkeley) 4/3/95
 */

char *syscallnames[] = {
    "#0",                       /* 0 = nosys syscall */
    "exit",                     /* 1 = exit */
    "fork",                     /* 2 = fork */
    "read",                     /* 3 = read */
    "write",                    /* 4 = write */
    "open",                     /* 5 = open */
    "close",                    /* 6 = close */
    "sun_wait4",                /* 7 = sun_wait4 */
    "sun_creat",                /* 8 = sun_creat */
    "link",                     /* 9 = link */
    "unlink",                   /* 10 = unlink */
    "sun_execv",                /* 11 = sun_execv */
    "chdir",                    /* 12 = chdir */
    "old.sun_time",             /* 13 = old sun_time */
    "mknod",                    /* 14 = mknod */
    "chmod",                    /* 15 = chmod */
    "chown",                    /* 16 = chown */
    "break",                    /* 17 = break */
    "old.sun_stat",             /* 18 = old sun_stat */
    "compat_43_lseek",          /* 19 = compat_43_lseek */
    "getpid",                   /* 20 = getpid */
    "obs_sun_old_mount",        /* 21 = obsolete sun_old_mount */
    "#22",                      /* 22 = System V umount */
    "old.setuid",               /* 23 = old setuid */
    "getuid",                   /* 24 = getuid */
    "old.sun_stime",            /* 25 = old sun_stime */
    "#26",                      /* 26 = sun_ptrace */
    "old.sun_alarm",            /* 27 = old sun_alarm */
    "old.sun_fstat",            /* 28 = old sun_fstat */
    "old.sun_pause",            /* 29 = old sun_pause */
    "old.sun_utime",            /* 30 = old sun_utime */
    "#31",                      /* 31 = was stty */
    "#32",                      /* 32 = was gtty */
    "access",                   /* 33 = access */
    "old.sun_nice",             /* 34 = old sun_nice */
    "old.sun_ftime",            /* 35 = old sun_ftime */
    "sync",                     /* 36 = sync */
    "kill",                     /* 37 = kill */
    "compat_43_stat",           /* 38 = compat_43_stat */
    "old.sun_setpgrp",          /* 39 = old sun_setpgrp */
    "compat_43_lstat",          /* 40 = compat_43_lstat */
    "dup",                      /* 41 = dup */
    "pipe",                     /* 42 = pipe */
    "old.sun_times",            /* 43 = old sun_times */
    "profil",                   /* 44 = profil */
    "#45",                      /* 45 = nosys */
    "old.sun_setgid",           /* 46 = old sun_setgid */
    "getgid",                   /* 47 = getgid */
    "old.sun_ssig",             /* 48 = old sun_ssig */
    "#49",                      /* 49 = reserved for USG */
    "#50",                      /* 50 = reserved for USG */
    "acct",                     /* 51 = acct */
    "#52",                      /* 52 = nosys */
    "sun_mctl",                 /* 53 = sun_mctl */
    "sun_ioctl",                /* 54 = sun_ioctl */
    "reboot",                   /* 55 = reboot */
    "obs_sun_owait3",           /* 56 = obsolete sun_owait3 */
    "symlink",                  /* 57 = symlink */
    "readlink",                 /* 58 = readlink */
    "execve",                   /* 59 = execve */
    "umask",                    /* 60 = umask */
    "chroot",                   /* 61 = chroot */
    "compat_43_fstat",          /* 62 = compat_43_fstat */
    "#63",                      /* 63 = nosys */
    "compat_43_getpagesize",    /* 64 = compat_43_getpagesize */
    "sun_omsync",               /* 65 = sun_omsync */
    "vfork",                    /* 66 = vfork */
    "obs_vread",                /* 67 = obsolete vread */
    "obs_vwrite",               /* 68 = obsolete vwrite */
    "sbrk",                     /* 69 = sbrk */
    "sstk",                     /* 70 = sstk */
    "mmap",                     /* 71 = mmap */
    "vadvise",                  /* 72 = vadvise */
    "munmap",                   /* 73 = munmap */
    "mprotect",                 /* 74 = mprotect */
    "madvise",                  /* 75 = madvise */
    "old.vhangup",              /* 76 = old vhangup */
    "old.vlimit",               /* 77 = old vlimit */
    "mincore",                  /* 78 = mincore */
    "getgroups",                /* 79 = getgroups */
    "setgroups",                /* 80 = setgroups */
    "getpgrp",                  /* 81 = getpgrp */
    "setpgid",                  /* 82 = setpgid */
    "setitimer",                /* 83 = setitimer */
    "old.wait",                 /* 84 = old wait */
    "swapon",                   /* 85 = swapon */
    "getitimer",                /* 86 = getitimer */
    "compat_43_gethostname",    /* 87 = compat_43_gethostname */
    "compat_43_sethostname",    /* 88 = compat_43_sethostname */
    "getdtablesize",            /* 89 = getdtablesize */
    "dup2",                     /* 90 = dup2 */
    "#91",                      /* 91 = getdopt */
    "fcntl",                    /* 92 = fcntl */
    "select",                   /* 93 = select */
    "#94",                      /* 94 = setdopt */
    "fsync",                    /* 95 = fsync */
    "setpriority",              /* 96 = setpriority */
    "socket",                   /* 97 = socket */
    "connect",                  /* 98 = connect */
    "compat_43_accept",         /* 99 = compat_43_accept */
    "getpriority",              /* 100 = getpriority */
    "compat_43_send",           /* 101 = compat_43_send */
    "compat_43_recv",           /* 102 = compat_43_recv */
    "#103",                     /* 103 = old socketaddr */
    "bind",                     /* 104 = bind */
    "sun_setsockopt",           /* 105 = sun_setsockopt */
    "listen",                   /* 106 = listen */
    "old.vtimes",               /* 107 = old vtimes */
    "compat_43_sigvec",         /* 108 = compat_43_sigvec */
    "compat_43_sigblock",       /* 109 = compat_43_sigblock */
    "compat_43_sigsetmask",     /* 110 = compat_43_sigsetmask */
    "sigsuspend",               /* 111 = sigsuspend */
    "compat_43_sigstack",       /* 112 = compat_43_sigstack */
    "compat_43_recvmsg",        /* 113 = compat_43_recvmsg */
    "compat_43_sendmsg",        /* 114 = compat_43_sendmsg */
    "obs_vtrace",               /* 115 = obsolete vtrace */
    "gettimeofday",             /* 116 = gettimeofday */
    "getrusage",                /* 117 = getrusage */
    "getsockopt",               /* 118 = getsockopt */
    "#119",                     /* 119 = nosys */
    "readv",                    /* 120 = readv */
    "writev",                   /* 121 = writev */
    "settimeofday",             /* 122 = settimeofday */
    "fchown",                   /* 123 = fchown */
    "fchmod",                   /* 124 = fchmod */
    "compat_43_recvfrom",       /* 125 = compat_43_recvfrom */
    "compat_43_setreuid",       /* 126 = compat_43_setreuid */
    "compat_43_setregid",       /* 127 = compat_43_setregid */
    "rename",                   /* 128 = rename */
    "compat_43_truncate",       /* 129 = compat_43_truncate */
    "compat_43_ftruncate",      /* 130 = compat_43_ftruncate */
    "flock",                    /* 131 = flock */
    "#132",                     /* 132 = nosys */
    "sendto",                   /* 133 = sendto */
    "shutdown",                 /* 134 = shutdown */
    "socketpair",               /* 135 = socketpair */
    "mkdir",                    /* 136 = mkdir */
    "rmdir",                    /* 137 = rmdir */
    "utimes",                   /* 138 = utimes */
    "sigreturn",                /* 139 = sigreturn */
    "adjtime",                  /* 140 = adjtime */
    "compat_43_getpeername",    /* 141 = compat_43_getpeername */
    "compat_43_gethostid",      /* 142 = compat_43_gethostid */
    "#143",                     /* 143 = old sethostid */
    "compat_43_getrlimit",      /* 144 = compat_43_getrlimit */
    "compat_43_setrlimit",      /* 145 = compat_43_setrlimit */
    "compat_43_killpg",         /* 146 = compat_43_killpg */
    "#147",                     /* 147 = nosys */
    "#148",                     /* 148 = nosys */
    "#149",                     /* 149 = nosys */
    "compat_43_getsockname",    /* 150 = compat_43_getsockname */
    "#151",                     /* 151 = getmsg */
    "#152",                     /* 152 = putmsg */
    "#153",                     /* 153 = poll */
    "#154",                     /* 154 = nosys */
    "#155",                     /* 155 = nosys */
    "getdirentries",            /* 156 = getdirentries */
    "statfs",                   /* 157 = statfs */
    "fstatfs",                  /* 158 = fstatfs */
    "sun_unmount",              /* 159 = sun_unmount */
    "#160",                     /* 160 = nosys */
    "#161",                     /* 161 = nosys */
    "sun_getdomainname",        /* 162 = sun_getdomainname */
    "sun_setdomainname",        /* 163 = sun_setdomainname */
    "#164",                     /* 164 = rtschedule */
    "#165",                     /* 165 = quotactl */
    "#166",                     /* 166 = exportfs */
    "sun_mount",                /* 167 = sun_mount */
    "#168",                     /* 168 = ustat */
    "#169",                     /* 169 = semsys */
    "#170",                     /* 170 = msgsys */
#ifdef SYSVSHM
    "shmsys",                   /* 171 = shmsys */
#else
    "#171",                     /* 171 = nosys */
#endif
    "#172",                     /* 172 = auditsys */
    "#173",                     /* 173 = rfssys */
    "sun_getdents",             /* 174 = sun_getdents */
    "setsid",                   /* 175 = setsid */
    "fchdir",                   /* 176 = fchdir */
    "sun_fchroot",              /* 177 = sun_fchroot */
    "#178",                     /* 178 = nosys */
    "#179",                     /* 179 = nosys */
    "#180",                     /* 180 = nosys */
    "#181",                     /* 181 = nosys */
    "#182",                     /* 182 = nosys */
    "sun_sigpending",           /* 183 = sun_sigpending */
    "#184",                     /* 184 = nosys */
    "setpgid",                  /* 185 = setpgid */
    "#186",                     /* 186 = pathconf */
    "#187",                     /* 187 = fpathconf */
    "#188",                     /* 188 = sysconf */
    "#189",                     /* 189 = uname */
};
