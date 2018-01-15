/*	$NetBSD: at.h,v 1.5 2008/04/05 16:26:57 christos Exp $	*/

/*
 *  at.h -  header for at(1)
 *  Copyright (C) 1993  Thomas Koenig
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. The name of the author(s) may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * From: $OpenBSD: at.h,v 1.3 1997/03/01 23:40:09 millert Exp $
 */

#ifndef _AT_H_
#define _AT_H_

extern bool fcreated;
extern char atfile[];
extern char atverify;

#define AT_MAXJOBS	255	/* max jobs outstanding per user */
#define AT_VERSION	2.9	/* our version number */

#define DEFAULT_BATCH_QUEUE	'E'
#define DEFAULT_AT_QUEUE	'c'

#define LOGIN_NAME_MAX	31

#define __arraycount(a) (sizeof(a) / sizeof(*(a)))

#endif /* _AT_H_ */
