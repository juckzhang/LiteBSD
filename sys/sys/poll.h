/*	$OpenBSD: poll.h,v 1.11 2003/12/10 23:10:08 millert Exp $ */

/*
 * Copyright (c) 1996 Theo de Raadt
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef	_SYS_POLL_H_
#define	_SYS_POLL_H_

typedef struct pollfd {
	int 	fd;//文件描述符id
	short	events;//监听的事件(read、write、error)
	short	revents;//已发生的事件
} pollfd_t;

typedef unsigned int	nfds_t;

#define	POLLIN		0x0001 //读事件
#define	POLLPRI		0x0002 //OOB/urgent 读事件
#define	POLLOUT		0x0004 //写事件
#define	POLLERR		0x0008 //some poll error occurred
#define	POLLHUP		0x0010 //file descriptor was "hung up"
#define	POLLNVAL	0x0020 //requested events "invalid"
#define	POLLRDNORM	0x0040 //non-oob/urg data available
#define POLLNORM	POLLRDNORM //no write type differentiation
#define POLLWRNORM      POLLOUT 
#define	POLLRDBAND	0x0080 //oob/urg readable data
#define	POLLWRBAND	0x0100 //oob/urg data can be written

#define INFTIM		(-1)

#ifndef _KERNEL
#include <ctype.h>

__BEGIN_DECLS
int   poll(struct pollfd[], nfds_t, int);
__END_DECLS
#endif /* _KERNEL */

#endif /* !_SYS_POLL_H_ */
