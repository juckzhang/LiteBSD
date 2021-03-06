/*-
 * Copyright (c) 1992, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
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
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
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
 */

#ifndef lint
static char sccsid[] = "@(#)exf.c	9.14 (Berkeley) 12/2/94";
#endif /* not lint */

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/time.h>

/*
 * We include <sys/file.h>, because the flock(2) and open(2) #defines
 * were found there on historical systems.  We also include <fcntl.h>
 * because the open(2) #defines are found there on newer systems.
 */
#include <sys/file.h>

#include <bitstring.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "compat.h"
#include <db.h>
#include <regex.h>
#include <pathnames.h>

#include "vi.h"
#include "excmd.h"

static int file_backup __P((SCR *, char *, char *));

/*
 * file_add --
 *	Insert a file name into the FREF list, if it doesn't already
 *	appear in it.
 *
 * !!!
 * The "if it doesn't already appear" changes vi's semantics slightly.  If
 * you do a "vi foo bar", and then execute "next bar baz", the edit of bar
 * will reflect the line/column of the previous edit session.  Historic nvi
 * did not do this.  The change is a logical extension of the change where
 * vi now remembers the last location in any file that it has ever edited,
 * not just the previously edited file.
 */
FREF *
file_add(sp, name)
	SCR *sp;
	CHAR_T *name;
{
	FREF *frp;

	/*
	 * Return it if it already exists.  Note that we test against the
	 * user's name, whatever that happens to be, including if it's a
	 * temporary file.
	 */
	if (name != NULL)
		for (frp = sp->frefq.cqh_first;
		    frp != (FREF *)&sp->frefq; frp = frp->q.cqe_next)
			if (!strcmp(frp->name, name))
				return (frp);

	/* Allocate and initialize the FREF structure. */
	CALLOC(sp, frp, FREF *, 1, sizeof(FREF));
	if (frp == NULL)
		return (NULL);

	/*
	 * If no file name specified, or if the file name is a request
	 * for something temporary, file_init() will allocate the file
	 * name.  Temporary files are always ignored.
	 */
	if (name != NULL && strcmp(name, TEMPORARY_FILE_STRING) &&
	    (frp->name = strdup(name)) == NULL) {
		FREE(frp, sizeof(FREF));
		msgq(sp, M_SYSERR, NULL);
		return (NULL);
	}

	/* Append into the chain of file names. */
	CIRCLEQ_INSERT_TAIL(&sp->frefq, frp, q);

	return (frp);
}

/*
 * file_init --
 *	Start editing a file, based on the FREF structure.  If successsful,
 *	let go of any previous file.  Don't release the previous file until
 *	absolutely sure we have the new one.
 */
int
file_init(sp, frp, rcv_name, flags)
	SCR *sp;
	FREF *frp;
	char *rcv_name;
	int flags;
{
	EXF *ep;
	RECNOINFO oinfo;
	struct stat sb;
	size_t psize;
	int fd, nf, open_err;
	char *p, *oname, tname[MAXPATHLEN];

	open_err = 0;

	/*
	 * If the file is a recovery file, let the recovery code handle it.
	 * Clear the FR_RECOVER flag first -- the recovery code does set up,
	 * and then calls us!  If the recovery call fails, it's probably
	 * because the named file doesn't exist.  So, move boldly forward,
	 * presuming that there's an error message the user will get to see.
	 */
	if (F_ISSET(frp, FR_RECOVER)) {
		F_CLR(frp, FR_RECOVER);
		return (rcv_read(sp, frp));
	}

	/*
	 * Required FRP initialization; the only flag we keep is the
	 * cursor information.
	 */
	F_CLR(frp, ~(FR_CURSORSET | FR_FNONBLANK));

	/*
	 * Required EXF initialization:
	 *	Flush the line caches.
	 *	Default recover mail file fd to -1.
	 *	Set initial EXF flag bits.
	 */
	CALLOC_RET(sp, ep, EXF *, 1, sizeof(EXF));
	ep->c_lno = ep->c_nlines = OOBLNO;
	ep->rcv_fd = ep->fcntl_fd = -1;
	F_SET(ep, F_FIRSTMODIFY);

	/*
	 * If no name or backing file, for whatever reason, create a backing
	 * temporary file, saving the temp file name so we can later unlink
	 * it.  If the user never named this file, copy the temporary file name
	 * to the real name (we display that until the user renames it).
	 */
	oname = frp->name;
	if (LF_ISSET(FS_OPENERR) || oname == NULL || stat(oname, &sb)) {
		(void)snprintf(tname, sizeof(tname),
		    "%s/vi.XXXXXX", O_STR(sp, O_DIRECTORY));
		if ((fd = mkstemp(tname)) == -1) {
			msgq(sp, M_SYSERR,
			    "002|Unable to create temporary file");
			goto err;
		}
		(void)close(fd);

		if (frp->name == NULL)
			F_SET(frp, FR_TMPFILE);
		if ((frp->tname = strdup(tname)) == NULL ||
		    frp->name == NULL && (frp->name = strdup(tname)) == NULL) {
			if (frp->tname != NULL)
				free(frp->tname);
			msgq(sp, M_SYSERR, NULL);
			(void)unlink(tname);
			goto err;
		}
		oname = frp->tname;
		psize = 4 * 1024;
		if (!LF_ISSET(FS_OPENERR))
			F_SET(frp, FR_NEWFILE);
	} else {
		/*
		 * Try to keep it at 10 pages or less per file.  This
		 * isn't friendly on a loaded machine, btw.
		 */
		if (sb.st_size < 40 * 1024)
			psize = 4 * 1024;
		else if (sb.st_size < 320 * 1024)
			psize = 32 * 1024;
		else
			psize = 64 * 1024;

		ep->mdev = sb.st_dev;
		ep->minode = sb.st_ino;
		ep->mtime = sb.st_mtime;

		if (!S_ISREG(sb.st_mode)) {
			p = msg_print(sp, oname, &nf);
			msgq(sp, M_ERR,
			    "003|Warning: %s is not a regular file", p);
			if (nf)
				FREE_SPACE(sp, p, 0);
		}
	}

	/* Set up recovery. */
	memset(&oinfo, 0, sizeof(RECNOINFO));
	oinfo.bval = '\n';			/* Always set. */
	oinfo.psize = psize;
	oinfo.flags = F_ISSET(sp->gp, G_SNAPSHOT) ? R_SNAPSHOT : 0;
	if (rcv_name == NULL) {
		if (!rcv_tmp(sp, ep, frp->name))
			oinfo.bfname = ep->rcv_path;
	} else {
		if ((ep->rcv_path = strdup(rcv_name)) == NULL) {
			msgq(sp, M_SYSERR, NULL);
			goto err;
		}
		oinfo.bfname = ep->rcv_path;
		F_SET(ep, F_MODIFIED);
	}

	/* Open a db structure. */
	if ((ep->db = dbopen(rcv_name == NULL ? oname : NULL,
	    O_NONBLOCK | O_RDONLY, DEFFILEMODE, DB_RECNO, &oinfo)) == NULL) {
		p = msg_print(sp, rcv_name == NULL ? oname : rcv_name, &nf);
		msgq(sp, M_SYSERR, "%s", p);
		if (nf)
			FREE_SPACE(sp, p, 0);
		/*
		 * !!!
		 * Historically, vi permitted users to edit files that couldn't
		 * be read.  This isn't useful for single files from a command
		 * line, but it's quite useful for "vi *.c", since you can skip
		 * past files that you can't read.
		 */ 
		open_err = 1;
		goto oerr;
	}

	/*
	 * Do the remaining things that can cause failure of the new file,
	 * mark and logging initialization.
	 */
	if (mark_init(sp, ep) || log_init(sp, ep))
		goto err;

	/*
	 * Set the alternate file name to be the file we're discarding.
	 *
	 * !!!
	 * Temporary files can't become alternate files, so there's no file
	 * name.  This matches historical practice, although it could only
	 * happen in historical vi as the result of the initial command, i.e.
	 * if vi was executed without a file name.
	 */
	if (LF_ISSET(FS_SETALT))
		set_alt_name(sp, sp->frp == NULL ||
		    F_ISSET(sp->frp, FR_TMPFILE) ? NULL : sp->frp->name);

	/*
	 * Close the previous file; if that fails, close the new one and run
	 * for the border.
	 *
	 * !!!
	 * There's a nasty special case.  If the user edits a temporary file,
	 * and then does an ":e! %", we need to re-initialize the backing
	 * file, but we can't change the name.  (It's worse -- we're dealing
	 * with *names* here, we can't even detect that it happened.)  Set a
	 * flag so that the file_end routine ignores the backing information
	 * of the old file if it happens to be the same as the new one.
	 *
	 * !!!
	 * Side-effect: after the call to file_end(), sp->frp may be NULL.
	 */
	F_SET(frp, FR_DONTDELETE);
	if (sp->ep != NULL && file_end(sp, NULL, LF_ISSET(FS_FORCE))) {
		(void)file_end(sp, ep, 1);
		goto err;
	}
	F_CLR(frp, FR_DONTDELETE);

	/*
	 * Lock the file; if it's a recovery file, it should already be
	 * locked.  Note, we acquire the lock after the previous file
	 * has been ended, so that we don't get an "already locked" error
	 * for ":edit!".
	 *
	 * XXX
	 * While the user can't interrupt us between the open and here,
	 * there's a race between the dbopen() and the lock.  Not much
	 * we can do about it.
	 *
	 * XXX
	 * We don't make a big deal of not being able to lock the file.  As
	 * locking rarely works over NFS, and often fails if the file was
	 * mmap(2)'d, it's far too common to do anything like print an error
	 * message, let alone make the file readonly.  At some future time,
	 * when locking is a little more reliable, this should change to be
	 * an error.
	 */
	if (rcv_name == NULL)
		switch (file_lock(sp, oname,
		    &ep->fcntl_fd, ep->db->fd(ep->db), 0)) {
		case LOCK_FAILED:
			F_SET(frp, FR_UNLOCKED);
			break;
		case LOCK_UNAVAIL:
			p = msg_print(sp, oname, &nf);
			msgq(sp, M_INFO,
			    "004|%s already locked, session is read-only", p);
			if (nf)
				FREE_SPACE(sp, p, 0);
			F_SET(frp, FR_RDONLY);
			break;
		case LOCK_SUCCESS:
			break;
		}

	/*
	 * The -R flag, or doing a "set readonly" during a session causes
	 * all files edited during the session (using an edit command, or
	 * even using tags) to be marked read-only.  Changing the file name
	 * (see ex/ex_file.c), clears this flag.
	 *
	 * Otherwise, try and figure out if a file is readonly.  This is a
	 * dangerous thing to do.  The kernel is the only arbiter of whether
	 * or not a file is writeable, and the best that a user program can
	 * do is guess.  Obvious loopholes are files that are on a file system
	 * mounted readonly (access catches this one on a few systems), or
	 * alternate protection mechanisms, ACL's for example, that we can't
	 * portably check.  Lots of fun, and only here because users whined.
	 *
	 * !!!
	 * Historic vi displayed the readonly message if none of the file
	 * write bits were set, or if an an access(2) call on the path
	 * failed.  This seems reasonable.  If the file is mode 444, root
	 * users may want to know that the owner of the file did not expect
	 * it to be written.
	 *
	 * Historic vi set the readonly bit if no write bits were set for
	 * a file, even if the access call would have succeeded.  This makes
	 * the superuser force the write even when vi expects that it will
	 * succeed.  I'm less supportive of this semantic, but it's historic
	 * practice and the conservative approach to vi'ing files as root.
	 *
	 * It would be nice if there was some way to update this when the user
	 * does a "^Z; chmod ...".  The problem is that we'd first have to
	 * distinguish between readonly bits set because of file permissions
	 * and those set for other reasons.  That's not too hard, but deciding
	 * when to reevaluate the permissions is trickier.  An alternative
	 * might be to turn off the readonly bit if the user forces a write
	 * and it succeeds.
	 *
	 * XXX
	 * Access(2) doesn't consider the effective uid/gid values.  This
	 * probably isn't a problem for vi when it's running standalone.
	 */
	if (O_ISSET(sp, O_READONLY) || !F_ISSET(frp, FR_NEWFILE) &&
	    (!(sb.st_mode & (S_IWUSR | S_IWGRP | S_IWOTH)) ||
	    access(frp->name, W_OK)))
		F_SET(frp, FR_RDONLY);

	/*
	 * Switch...
	 *
	 * !!!
	 * Note, because the EXF structure is examined at interrupt time,
	 * the underlying DB structures have to be consistent as soon as
	 * it's assigned to an SCR structure.
	 */
	++ep->refcnt;
	sp->ep = ep;
	sp->frp = frp;

	/* Set the initial cursor position. */
	file_cinit(sp);

	/* Redraw the screen from scratch. */
	F_SET(sp, S_SCR_REFORMAT);

	/* Display file statistics. */
	return (msg_status(sp, sp->lno, 0));

err:	if (frp->name != NULL) {
		free(frp->name);
		frp->name = NULL;
	}
	if (frp->tname != NULL) {
		(void)unlink(frp->tname);
		free(frp->tname);
		frp->tname = NULL;
	}

oerr:	if (F_ISSET(ep, F_RCV_ON))
		(void)unlink(ep->rcv_path);
	if (ep->rcv_path != NULL) {
		free(ep->rcv_path);
		ep->rcv_path = NULL;
	}
	if (ep->db != NULL)
		(void)ep->db->close(ep->db);
	FREE(ep, sizeof(EXF));

	return (open_err ?
	    file_init(sp, frp, rcv_name, flags | FS_OPENERR) : 1);
}

/*
 * file_cinit --
 *	Set up the initial cursor position.
 */
void
file_cinit(sp)
	SCR *sp;
{
	MARK m;
	size_t len;
	int nb;

	/*
	 * If in ex mode, move to the last line, first nonblank character.
	 * Otherwise, if the file has previously been edited, move to the
	 * last position, and check it for validity.  Otherwise, move to
	 * the first line, first nonblank.  This gets called by some the
	 * file init code, because we may be in a file of ex commands and
	 * we want to execute them from the right location in the file.  A
	 * few other places that want special case behavior also call here.
	 */
	nb = 0;
	if (IN_EX_MODE(sp)) {
		/* XXX:  If this fails, we're toast. */
		(void)file_lline(sp, &sp->lno);
		if (sp->lno == 0) {
			sp->lno = 1;
			sp->cno = 0;
			return;
		}
		nb = 1;
	} else {
		if (F_ISSET(sp->frp, FR_CURSORSET)) {
			sp->lno = sp->frp->lno;
			if (F_ISSET(sp->frp, FR_FNONBLANK))
				nb = 1;
			else
				sp->cno = sp->frp->cno;

			/* If returning to a file in vi, center the line. */
			 F_SET(sp, S_SCR_CENTER);
		} else {
			sp->lno = 1;
			nb = 1;
		}
		if (file_gline(sp, sp->lno, &len) == NULL) {
			sp->lno = 1;
			sp->cno = 0;
			return;
		}
		if (!nb && sp->cno > len)
			nb = 1;
	}
	if (nb) {
		sp->cno = 0;
		(void)nonblank(sp, sp->lno, &sp->cno);
	}

	/*
	 * !!!
	 * Historically, vi initialized the absolute mark, but ex did not.
	 * Which meant, that if the first command in ex mode was "visual",
	 * or if an ex command was executed first (e.g. vi +10 file) vi was
	 * entered without the mark being initialized.  For consistency, if
	 * the file isn't empty, we initialize it for everyone, believing
	 * that it can't hurt, and is generally useful.  Not initializing it
	 * if the file is empty is historic practice, although it has always
	 * been possible to set (and use) marks in empty vi files.
	 */
	m.lno = sp->lno;
	m.cno = sp->cno;
	(void)mark_set(sp, ABSMARK1, &m, 0);
}

/*
 * file_end --
 *	Stop editing a file.
 */
int
file_end(sp, ep, force)
	SCR *sp;
	EXF *ep;
	int force;
{
	FREF *frp;
	int nf;
	char *p;

	/*
	 * !!!
	 * ep MAY NOT BE THE SAME AS sp->ep, DON'T USE THE LATTER.
	 * (If argument ep is NULL, use sp->ep.)
	 */
	if (ep == NULL)
		ep = sp->ep;

	/*
	 *
	 * Clean up the FREF structure.
	 *
	 * Save the cursor location.
	 *
	 * XXX
	 * It would be cleaner to do this somewhere else, but by the time
	 * ex or vi knows that we're changing files it's already happened.
	 */
	frp = sp->frp;
	frp->lno = sp->lno;
	frp->cno = sp->cno;
	F_SET(frp, FR_CURSORSET);

	/*
	 * We may no longer need the temporary backing file, so clean it
	 * up.  We don't need the FREF structure either, if the file was
	 * never named, so lose it.
	 *
	 * !!!
	 * Re: FR_DONTDELETE, see the comment above in file_init().
	 */
	if (!F_ISSET(frp, FR_DONTDELETE) && frp->tname != NULL) {
		if (unlink(frp->tname)) {
			p = msg_print(sp, frp->tname, &nf);
			msgq(sp, M_SYSERR, "005|%s: remove", p);
			if (nf)
				FREE_SPACE(sp, p, 0);
		}
		free(frp->tname);
		frp->tname = NULL;
		if (F_ISSET(frp, FR_TMPFILE)) {
			CIRCLEQ_REMOVE(&sp->frefq, frp, q);
			free(frp->name);
			free(frp);
		}
		sp->frp = NULL;
	}

	/*
	 * Clean up the EXF structure.
	 *
	 * If multiply referenced, just decrement the count and return.
	 */
	if (--ep->refcnt != 0)
		return (0);

	/* Close the db structure. */
	if (ep->db->close != NULL && ep->db->close(ep->db) && !force) {
		p = msg_print(sp, frp->name, &nf);
		msgq(sp, M_SYSERR, "006|%s: close", p);
		if (nf)
			FREE_SPACE(sp, p, 0);
		++ep->refcnt;
		return (1);
	}

	/* COMMITTED TO THE CLOSE.  THERE'S NO GOING BACK... */

	/* Stop logging. */
	(void)log_end(sp, ep);

	/* Free up any marks. */
	(void)mark_end(sp, ep);

	/*
	 * Delete recovery files, close the open descriptor, free recovery
	 * memory.  See recover.c for a description of the protocol.
	 *
	 * XXX
	 * Unlink backup file first, we can detect that the recovery file
	 * doesn't reference anything when the user tries to recover it.
	 * There's a race, here, obviously, but it's fairly small.
	 */
	if (!F_ISSET(ep, F_RCV_NORM)) {
		if (ep->rcv_path != NULL && unlink(ep->rcv_path)) {
			p = msg_print(sp, ep->rcv_path, &nf);
			msgq(sp, M_SYSERR, "007|%s: remove", p);
			if (nf)
				FREE_SPACE(sp, p, 0);
		}
		if (ep->rcv_mpath != NULL && unlink(ep->rcv_mpath)) {
			p = msg_print(sp, ep->rcv_mpath, &nf);
			msgq(sp, M_SYSERR, "008|%s: remove", p);
			if (nf)
				FREE_SPACE(sp, p, 0);
		}
	}
	if (ep->fcntl_fd != -1)
		(void)close(ep->fcntl_fd);
	if (ep->rcv_fd != -1)
		(void)close(ep->rcv_fd);
	if (ep->rcv_path != NULL)
		free(ep->rcv_path);
	if (ep->rcv_mpath != NULL)
		free(ep->rcv_mpath);

	FREE(ep, sizeof(EXF));
	return (0);
}

/*
 * file_write --
 *	Write the file to disk.  Historic vi had fairly convoluted
 *	semantics for whether or not writes would happen.  That's
 *	why all the flags.
 */
int
file_write(sp, fm, tm, name, flags)
	SCR *sp;
	MARK *fm, *tm;
	char *name;
	int flags;
{
	enum { NEWFILE, NONE, EXISTING } mtype;
	struct stat sb;
	EXF *ep;
	FILE *fp;
	FREF *frp;
	MARK from, to;
	u_long nlno, nch;
	int btear, fd, nf, noname, oflags, rval;
	char *p;

	/*
	 * Writing '%', or naming the current file explicitly, has the
	 * same semantics as writing without a name.
	 */
	frp = sp->frp;
	if (name == NULL || !strcmp(name, frp->name)) {
		noname = 1;
		name = frp->name;
	} else
		noname = 0;

	/* Can't write files marked read-only, unless forced. */
	if (!LF_ISSET(FS_FORCE) && noname && F_ISSET(frp, FR_RDONLY)) {
		if (LF_ISSET(FS_POSSIBLE))
			msgq(sp, M_ERR,
		    "009|Read-only file, not written; use ! to override");
		else
			msgq(sp, M_ERR, "010|Read-only file, not written");
		return (1);
	}

	/* If not forced, not appending, and "writeany" not set ... */
	if (!LF_ISSET(FS_FORCE | FS_APPEND) && !O_ISSET(sp, O_WRITEANY)) {
		/* Don't overwrite anything but the original file. */
		if ((!noname || F_ISSET(frp, FR_NAMECHANGE)) &&
		    !stat(name, &sb)) {
			p = msg_print(sp, name, &nf);
			if (LF_ISSET(FS_POSSIBLE)) {
				msgq(sp, M_ERR,
		"011|%s exists, not written; use ! to override", p);
			} else
				msgq(sp, M_ERR,
				    "012|%s exists, not written", p);
			if (nf)
				FREE_SPACE(sp, p, 0);
			return (1);
		}

		/*
		 * Don't write part of any existing file.  Only test for the
		 * original file, the previous test catches anything else.
		 */
		if (!LF_ISSET(FS_ALL) && noname && !stat(name, &sb)) {
			if (LF_ISSET(FS_POSSIBLE))
				msgq(sp, M_ERR,
				    "013|Use ! to write a partial file");
			else
				msgq(sp, M_ERR,
				    "014|Partial file, not written");
			return (1);
		}
	}

	/*
	 * Figure out if the file already exists -- if it doesn't, we display
	 * the "new file" message.  The stat might not be necessary, but we
	 * just repeat it because it's easier than hacking the previous tests.
	 * The information is only used for the user message and modification
	 * time test, so we can ignore the obvious race condition.
	 *
	 * If the user is overwriting a file other than the original file, and
	 * O_WRITEANY was what got us here (neither force nor append was set),
	 * display the "existing file" messsage.  Since the FR_NAMECHANGE flag
	 * is cleared on a successful write, the message only appears once when
	 * the user changes a file name.  This is historic practice.
	 *
	 * One final test.  If we're not forcing or appending, and we have a
	 * saved modification time, object if the file was changed since we
	 * last edited or wrote it, and make them force it.
	 */
	if (stat(name, &sb))
		mtype = NEWFILE;
	else {
		mtype = NONE;
		if (!LF_ISSET(FS_FORCE | FS_APPEND)) {
			ep = sp->ep;
			if (ep->mtime != 0 &&
			    (sb.st_dev != sp->ep->mdev ||
			    sb.st_ino != ep->minode ||
			    sb.st_mtime != ep->mtime)) {
				p = msg_print(sp, name, &nf);
				msgq(sp, M_ERR,
				    LF_ISSET(FS_POSSIBLE) ?
"016|%s: file modified more recently than this copy; use ! to override" :
"017|%s: file modified more recently than this copy",
				    p);
				if (nf)
					FREE_SPACE(sp, p, 0);
				return (1);
			}
			if (!noname || F_ISSET(frp, FR_NAMECHANGE))
				mtype = EXISTING;
		}
	}

	/* Set flags to either append or truncate. */
	oflags = O_CREAT | O_WRONLY;
	if (LF_ISSET(FS_APPEND))
		oflags |= O_APPEND;
	else
		oflags |= O_TRUNC;

	/* Backup the file if requested. */
	p = O_STR(sp, O_BACKUP);
	if (p[0] != '\0' && file_backup(sp, name, p) && !LF_ISSET(FS_FORCE))
		return (1);

	/* Open the file. */
	SIGBLOCK(sp->gp);
	if ((fd = open(name, oflags, DEFFILEMODE)) < 0) {
		p = msg_print(sp, name, &nf);
		msgq(sp, M_SYSERR, "%s", p);
		if (nf)
			FREE_SPACE(sp, p, 0);
		return (1);
	}
	SIGUNBLOCK(sp->gp);

	/* Try and get a lock. */
	if (!noname && file_lock(sp, NULL, NULL, fd, 0) == LOCK_UNAVAIL)
		msgq(sp, M_ERR, "265|%s: write lock was unavailable", name);

	/* Use stdio for buffering. */
	if ((fp = fdopen(fd, "w")) == NULL) {
		(void)close(fd);
		p = msg_print(sp, name, &nf);
		msgq(sp, M_SYSERR, "%s", p);
		if (nf)
			FREE_SPACE(sp, p, 0);
		return (1);
	}

	/* Build fake addresses, if necessary. */
	if (fm == NULL) {
		from.lno = 1;
		from.cno = 0;
		fm = &from;
		if (file_lline(sp, &to.lno))
			return (1);
		to.cno = 0;
		tm = &to;
	}

	/* Turn on the busy message. */
	btear = F_ISSET(sp, S_EXSILENT) ? 0 : !busy_on(sp, "Writing...");
	rval = ex_writefp(sp, name, fp, fm, tm, &nlno, &nch);
	if (btear)
		busy_off(sp);

	/*
	 * Save the new last modification time -- even if the write fails
	 * we re-init the time.  That way the user can clean up the disk
	 * and rewrite without having to force it.
	 */
	if (noname) {
		ep = sp->ep;
		if (stat(name, &sb))
			ep->mtime = 0;
		else {
			ep->mdev = sb.st_dev;
			ep->minode = sb.st_ino;
			ep->mtime = sb.st_mtime;
		}
	}

	/* If the write failed, complain loudly. */
	if (rval) {
		if (!LF_ISSET(FS_APPEND)) {
			p = msg_print(sp, name, &nf);
			msgq(sp, M_ERR,
			    "019|%s: WARNING: FILE TRUNCATED", p);
			if (nf)
				FREE_SPACE(sp, p, 0);
		}
		return (1);
	}

	/*
	 * Once we've actually written the file, it doesn't matter that the
	 * file name was changed -- if it was, we've already whacked it.
	 */
	F_CLR(frp, FR_NAMECHANGE);

	/*
	 * If wrote the entire file clear the modified bit.  If the file was
	 * written back to the original file name and the file is a temporary,
	 * set the "no exit" bit.  This permits the user to write the file and
	 * use it in the context of the file system, but still keeps them from
	 * losing their changes by exiting.
	 */
	if (LF_ISSET(FS_ALL)) {
		F_CLR(sp->ep, F_MODIFIED);
		if (F_ISSET(frp, FR_TMPFILE))
			if (noname)
				F_SET(frp, FR_TMPEXIT);
			else
				F_CLR(frp, FR_TMPEXIT);
	}

	p = msg_print(sp, name, &nf);
	if (INTERRUPTED(sp))
		switch (mtype) {
		case EXISTING:
			msgq(sp, M_INFO,
    "015|Interrupted write: %s: existing file: %lu lines, %lu characters",
			    p, nlno, nch);
			break;
		case NEWFILE:
			msgq(sp, M_INFO,
    "018|Interrupted write: %s: new file: %lu lines, %lu characters",
			    p, nlno, nch);
			break;
		case NONE:
			msgq(sp, M_INFO,
    "020|Interrupted write: %s: %lu lines, %lu characters",
			    p, nlno, nch);
			break;
		}
	else
		switch (mtype) {
		case EXISTING:
			msgq(sp, M_INFO,
			    "025|%s: existing file: %lu lines, %lu characters",
			    p, nlno, nch);
			break;
		case NEWFILE:
			msgq(sp, M_INFO,
			    "092|%s: new file: %lu lines, %lu characters",
			    p, nlno, nch);
			break;
		case NONE:
			msgq(sp, M_INFO,
			    "093|%s: %lu lines, %lu characters", p, nlno, nch);
			break;
		}

	if (nf)
		FREE_SPACE(sp, p, 0);
	return (0);
}

/*
 * file_backup --
 *	Backup the about-to-be-written file.
 *
 * XXX
 * We do the backup by copying the entire file.  It would be nice to do
 * a rename instead, but: (1) both files may not fit and we want to fail
 * before doing the rename; (2) the backup file may not be on the same
 * disk partition as the file being written; (3) there may be optional
 * file information (MACs, DACs, whatever) that we won't get right if we
 * recreate the file.  So, let's not risk it.
 */
static int
file_backup(sp, name, bname)
	SCR *sp;
	char *name, *bname;
{
	struct dirent *dp;
	struct stat sb;
	ARGS *ap[2], a;
	DIR *dirp;
	EXCMDARG cmd;
	off_t off;
	size_t blen;
	int flags, maxnum, nf, nr, num, nw, rfd, wfd, version;
	char *bp, *estr, *p, *pct, *slash, *t, *wfname, buf[8192];

	rfd = wfd = -1;
	bp = estr = wfname = NULL;

	/*
	 * Open the current file for reading.  Do this first, so that
	 * we don't exec a shell before the most likely failure point.
	 * If it doesn't exist, it's okay, there's just nothing to back
	 * up.
	 */
	errno = 0;
	if ((rfd = open(name, O_RDONLY, 0)) < 0) {
		if (errno == ENOENT)
			return (0);
		estr = name;
		goto err;
	}

	/*
	 * If the name starts with an 'N' character, add a version number
	 * to the name.  Strip the leading N from the string passed to the
	 * expansion routines, for no particular reason.  It would be nice
	 * to permit users to put the version number anywhere in the backup
	 * name, but there isn't a special character that we can use in the
	 * name, and giving a new character a special meaning leads to ugly
	 * hacks both here and in the supporting ex routines.
	 *
	 * Shell and file name expand the option's value.
	 */
	argv_init(sp, &cmd);
	ex_cbuild(&cmd, 0, 0, 0, 0, 0, ap, &a, NULL);
	if (bname[0] == 'N') {
		version = 1;
		++bname;
	} else
		version = 0;
	if (argv_exp2(sp, &cmd, bname, strlen(bname)))
		return (1);

	/*
	 *  0 args: impossible.
	 *  1 args: use it.
	 * >1 args: object, too many args.
	 */
	if (cmd.argc != 1) {
		(void)close(rfd);
		p = msg_print(sp, bname, &nf);
		msgq(sp, M_ERR,
		    "256|%s expanded into too many file names", p);
		if (nf)
			FREE_SPACE(sp, p, 0);
		return (1);
	}

	/*
	 * If appending a version number, read through the directory, looking
	 * for file names that match the name followed by a number.  Make all
	 * of the other % characters in name literal, so the user doesn't get
	 * surprised and sscanf doesn't drop core indirecting through pointers
	 * that don't exist.  If any such files are found, increment its number
	 * by one.
	 */
	if (version) {
		GET_SPACE_GOTO(sp, bp, blen, cmd.argv[0]->len * 2 + 50);
		for (t = bp, slash = NULL,
		    p = cmd.argv[0]->bp; p[0] != '\0'; *t++ = *p++)
			if (p[0] == '%') {
				if (p[1] != '%')
					*t++ = '%';
			} else if (p[0] == '/')
				slash = t;
		pct = t;
		*t++ = '%';
		*t++ = 'd';
		*t = '\0';

		if (slash == NULL) {
			dirp = opendir(".");
			p = bp;
		} else {
			*slash = '\0';
			dirp = opendir(bp);
			*slash = '/';
			p = slash + 1;
		}
		if (dirp == NULL) {
			estr = cmd.argv[0]->bp;
			goto err;
		}

		for (maxnum = 0; (dp = readdir(dirp)) != NULL;)
			if (sscanf(dp->d_name, p, &num) == 1 && num > maxnum)
				maxnum = num;
		(void)closedir(dirp);

		/* Format the backup file name. */
		(void)snprintf(pct, blen - (pct - bp), "%d", maxnum + 1);
		wfname = bp;
	} else {
		bp = NULL;
		wfname = cmd.argv[0]->bp;
	}
	
	/* Open the backup file, avoiding lurkers. */
	if (stat(wfname, &sb) == 0) {
		if (!S_ISREG(sb.st_mode)) {
			t = "257|%s: not a regular file";
			goto perm;
		}
		if (sb.st_uid != getuid()) {
			t = "258|%s: not owned by you";
			goto perm;
		}
		if (sb.st_mode & (S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)) {
			t = "259|%s: accessible by a user other than the owner";
perm:			p = msg_print(sp, bname, &nf);
			msgq(sp, M_ERR, t, p);
			if (nf)
				FREE_SPACE(sp, p, 0);
			goto err;
		}
		flags = O_TRUNC;
	} else
		flags = O_CREAT | O_EXCL;
	if ((wfd = open(wfname, flags | O_WRONLY, S_IRUSR | S_IWUSR)) < 0) {
		estr = bname;
		goto err;
	}

	/* Copy the file's current contents to its backup value. */
	while ((nr = read(rfd, buf, sizeof(buf))) > 0)
		for (off = 0; nr != 0; nr -= nw, off += nw)
			if ((nw = write(wfd, buf + off, nr)) < 0) {
				estr = wfname;
				goto err;
			}
	if (nr < 0) {
		estr = name;
		goto err;
	}

	if (close(rfd)) {
		estr = name;
		goto err;
	}
	if (close(wfd)) {
		estr = wfname;
		goto err;
	}
	if (bp != NULL)
		FREE_SPACE(sp, bp, blen);
	return (0);

binc_err:
err:	if (rfd != -1)
		(void)close(rfd);
	if (wfd != -1) {
		(void)unlink(wfname);
		(void)close(wfd);
	}
	if (estr) {
		p = msg_print(sp, estr, &nf);
		msgq(sp, M_SYSERR, "%s", p);
		if (nf)
			FREE_SPACE(sp, p, 0);
	}
	if (bp != NULL)
		FREE_SPACE(sp, bp, blen);
	return (1);
}

/*
 * file_m1 --
 * 	First modification check routine.  The :next, :prev, :rewind, :tag,
 *	:tagpush, :tagpop, ^^ modifications check.
 */
int
file_m1(sp, force, flags)
	SCR *sp;
	int force, flags;
{
	/* If no file loaded, return no modifications. */
	if (sp->ep == NULL)
		return (0);

	/*
	 * If the file has been modified, we'll want to write it back or
	 * fail.  If autowrite is set, we'll write it back automatically,
	 * unless force is also set.  Otherwise, we fail unless forced or
	 * there's another open screen on this file.
	 */
	if (F_ISSET(sp->ep, F_MODIFIED))
		if (O_ISSET(sp, O_AUTOWRITE)) {
			if (!force && file_aw(sp, flags))
				return (1);
		} else if (sp->ep->refcnt <= 1 && !force) {
			msgq(sp, M_ERR, LF_ISSET(FS_POSSIBLE) ?
"021|File modified since last complete write; write or use ! to override" :
"022|File modified since last complete write; write or use :edit! to override");
			return (1);
		}

	return (file_m3(sp, force));
}

/*
 * file_m2 --
 * 	Second modification check routine.  The :edit, :quit, :recover
 *	modifications check.
 */
int
file_m2(sp, force)
	SCR *sp;
	int force;
{
	/* If no file loaded, return no modifications. */
	if (sp->ep == NULL)
		return (0);

	/*
	 * If the file has been modified, we'll want to fail, unless forced
	 * or there's another open screen on this file.
	 */
	if (F_ISSET(sp->ep, F_MODIFIED) && sp->ep->refcnt <= 1 && !force) {
		msgq(sp, M_ERR,
"023|File modified since last complete write; write or use ! to override");
		return (1);
	}

	return (file_m3(sp, force));
}

/*
 * file_m3 --
 * 	Third modification check routine.
 */
int
file_m3(sp, force)
	SCR *sp;
	int force;
{
	/* If no file loaded, return no modifications. */
	if (sp->ep == NULL)
		return (0);

	/*
	 * Don't exit while in a temporary files if the file was ever modified.
	 * The problem is that if the user does a ":wq", we write and quit,
	 * unlinking the temporary file.  Not what the user had in mind at all.
	 * We permit writing to temporary files, so that user maps using file
	 * system names work with temporary files.
	 */
	if (F_ISSET(sp->frp, FR_TMPEXIT) && sp->ep->refcnt <= 1 && !force) {
		msgq(sp, M_ERR,
		    "024|File is a temporary; exit will discard modifications");
		return (1);
	}
	return (0);
}

/*
 * file_aw --
 *	Autowrite routine.  If modified, autowrite is set and the readonly bit
 *	is not set, write the file.  A routine so there's a place to put the
 *	comment.
 */
int
file_aw(sp, flags)
	SCR *sp;
	int flags;
{
	if (!F_ISSET(sp->ep, F_MODIFIED))
		return (0);
	if (!O_ISSET(sp, O_AUTOWRITE))
		return (0);

	/*
	 * !!!
	 * Historic 4BSD vi attempted to write the file if autowrite was set,
	 * regardless of the writeability of the file (as defined by the file
	 * readonly flag).  System V changed this as some point, not attempting
	 * autowrite if the file was readonly.  This feels like a bug fix to
	 * me (e.g. the principle of least surprise is violated if readonly is
	 * set and vi writes the file), so I'm compatible with System V.
	 */
	if (F_ISSET(sp->frp, FR_RDONLY)) {
		msgq(sp, M_INFO,
		    "268|File readonly, modifications not auto-written");
		return (0);
	}
	return (file_write(sp, NULL, NULL, NULL, flags));
}

/*
 * file_lock --
 *	Get an exclusive lock on a file.
 *
 * XXX
 * The default locking is flock(2) style, not fcntl(2).  The latter is
 * known to fail badly on some systems, and its only advantage is that
 * it occasionally works over NFS.
 *
 * Furthermore, the semantics of fcntl(2) are wrong.  The problems are
 * two-fold: you can't close any file descriptor associated with the file
 * without losing all of the locks, and you can't get an exclusive lock
 * unless you have the file open for writing.  Someone ought to be shot,
 * but it's probably too late, they may already have reproduced.  To get
 * around these problems, nvi opens the files for writing when it can and
 * acquires a second file descriptor when it can't.  The recovery files
 * are examples of the former, they're always opened for writing.  The DB
 * files can't be opened for writing because the semantics of DB are that
 * files opened for writing are flushed back to disk when the DB session
 * is ended. So, in that case we have to acquire an extra file descriptor.
 */
enum lockt
file_lock(sp, name, fdp, fd, iswrite)
	SCR *sp;
	char *name;
	int fd, *fdp, iswrite;
{
	if (!O_ISSET(sp, O_LOCK))
		return (LOCK_SUCCESS);
	
#if !defined(USE_FCNTL) && defined(LOCK_EX)
					/* Hurrah!  We've got flock(2). */
	/*
	 * !!!
	 * We need to distinguish a lock not being available for the file
	 * from the file system not supporting locking.  Flock is documented
	 * as returning EWOULDBLOCK; add EAGAIN for good measure, and assume
	 * they are the former.  There's no portable way to do this.
	 */
	errno = 0;
	return (flock(fd, LOCK_EX | LOCK_NB) ?
	    errno == EAGAIN || errno == EWOULDBLOCK ?
	        LOCK_UNAVAIL : LOCK_FAILED : LOCK_SUCCESS);

#else					/* Gag me.  We've got fcntl(2). */
{
	struct flock arg;
	int didopen, sverrno;

	arg.l_type = F_WRLCK;
	arg.l_whence = 0;		/* SEEK_SET */
	arg.l_start = arg.l_len = 0;
	arg.l_pid = 0;

	/*
	 * If the file descriptor isn't opened for writing, it must fail.
	 * If we fail because we can't get a read/write file descriptor,
	 * we return LOCK_SUCCESS, believing that the file is readonly
	 * and that will be sufficient to warn the user.
	 */
	if (!iswrite) {
		if (name == NULL || fdp == NULL)
			return (LOCK_FAILED);
		if ((fd = open(name, O_RDWR, 0)) == -1)
			return (LOCK_SUCCESS);
		*fdp = fd;
		didopen = 1;
	}

	errno = 0;
	if (!fcntl(fd, F_SETLK, &arg))
		return (LOCK_SUCCESS);
	if (didopen) {
		sverrno = errno;
		(void)close(fd);
		errno = sverrno;
	}

	/*
	 * !!!
	 * We need to distinguish a lock not being available for the file
	 * from the file system not supporting locking.  Fcntl is documented
	 * as returning EACCESS and EAGAIN; add EWOULDBLOCK for good measure,
	 * and assume they are the former.  There's no portable way to do this.
	 */
	return (errno == EACCES || errno == EAGAIN || errno == EWOULDBLOCK ?
	    LOCK_UNAVAIL : LOCK_FAILED);
}
#endif
}
