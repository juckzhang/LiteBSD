#	@(#)bsd.man.mk	8.1 (Berkeley) 6/8/93

.if exists(${.CURDIR}/../Makefile.inc)
.include "${.CURDIR}/../Makefile.inc"
.endif

MANGRP?=	bin
MANOWN?=	bin
MANMODE?=	444

MANDIR?=	/usr/share/man/cat

#MINSTALL=	install -c -m ${MANMODE}
MINSTALL=	install -c

maninstall:
.if defined(MAN1) && !empty(MAN1)
	install -d ${DESTDIR}${MANDIR}1${MANSUBDIR}
	${MINSTALL} ${MAN1} ${DESTDIR}${MANDIR}1${MANSUBDIR}
.endif
.if defined(MAN2) && !empty(MAN2)
	install -d ${DESTDIR}${MANDIR}2${MANSUBDIR}
	${MINSTALL} ${MAN2} ${DESTDIR}${MANDIR}2${MANSUBDIR}
.endif
.if defined(MAN3) && !empty(MAN3)
	install -d ${DESTDIR}${MANDIR}3${MANSUBDIR}
	${MINSTALL} ${MAN3} ${DESTDIR}${MANDIR}3${MANSUBDIR}
.endif
.if defined(MAN3F) && !empty(MAN3F)
	install -d ${DESTDIR}${MANDIR}3f${MANSUBDIR}
	${MINSTALL} ${MAN3F} ${DESTDIR}${MANDIR}3f${MANSUBDIR}
.endif
.if defined(MAN4) && !empty(MAN4)
	install -d ${DESTDIR}${MANDIR}4${MANSUBDIR}
	${MINSTALL} ${MAN4} ${DESTDIR}${MANDIR}4${MANSUBDIR}
.endif
.if defined(MAN5) && !empty(MAN5)
	install -d ${DESTDIR}${MANDIR}5${MANSUBDIR}
	${MINSTALL} ${MAN5} ${DESTDIR}${MANDIR}5${MANSUBDIR}
.endif
.if defined(MAN6) && !empty(MAN6)
	install -d ${DESTDIR}${MANDIR}6${MANSUBDIR}
	${MINSTALL} ${MAN6} ${DESTDIR}${MANDIR}6${MANSUBDIR}
.endif
.if defined(MAN7) && !empty(MAN7)
	install -d ${DESTDIR}${MANDIR}7${MANSUBDIR}
	${MINSTALL} ${MAN7} ${DESTDIR}${MANDIR}7${MANSUBDIR}
.endif
.if defined(MAN8) && !empty(MAN8)
	install -d ${DESTDIR}${MANDIR}8${MANSUBDIR}
	${MINSTALL} ${MAN8} ${DESTDIR}${MANDIR}8${MANSUBDIR}
.endif
.if defined(MLINKS) && !empty(MLINKS)
	@set ${MLINKS}; \
	while test $$# -ge 2; do \
		name=$$1; shift; \
		l=`expr $$name : '\([^\.]*\)'`.0; \
		name=$$1; shift; \
		dir=${DESTDIR}${MANDIR}`expr $$name : '[^\.]*\.\(.*\)'`; \
		t=$${dir}${MANSUBDIR}/`expr $$name : '\([^\.]*\)'`.0; \
		echo $$t -\> $$l; \
		rm -f $$t; \
		ln $$l $$t; \
	done; true
.endif
