# $NetBSD: Makefile,v 1.6 2023/07/10 18:00:13 stephanwib Exp $

.include <bsd.own.mk>

LIB=		root
# MAN=		root.3

SRCS=		time.c port.c thread.c area.c sem.c

LIBDPLIBS+=	pthread ${NETBSDSRCDIR}/lib/libpthread

INCS=		OS.h Errors.h
INCSDIR=	/usr/include

WARNS=		5

.include <bsd.lib.mk>
