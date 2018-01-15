#!/bin/sh
#	$OpenBSD: cpp.sh,v 1.7 2004/02/10 02:02:22 espie Exp $

#
# Copyright (c) 1990 The Regents of the University of California.
# All rights reserved.
#
# This code is derived from software contributed to Berkeley by
# the Systems Programming Group of the University of Utah Computer
# Science Department.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of the University nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
#	@(#)usr.bin.cpp.sh	6.5 (Berkeley) 4/1/91
#
# Transitional front end to CCCP to make it behave like (Reiser) CCP:
#	specifies -traditional
#	doesn't search gcc-include
#
PATH=/usr/bin:/bin
DGNUC="-D__GNUC__"
STDINC="-I/usr/include"
OPTS=""
FOUNDFILES=false

CPP=/usr/libexec/cpp

while [ $# -gt 0 ]
do
	A="$1"
	shift

	case $A in
	-I*)
		INCS="$INCS $A"
		;;
	-U__GNUC__)
		DGNUC=
		;;
	-*)
		OPTS="$OPTS '$A'"
		;;
	*)
		FOUNDFILES=true
		eval $CPP $DGNUC $INCS $STDINC $OPTS $A || exit $?
		;;
	esac
done

if ! $FOUNDFILES
then
	# read standard input
	eval exec $CPP $DGNUC $INCS $STDINC $OPTS
fi

exit 0
