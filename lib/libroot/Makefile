# $NetBSD: Makefile,v 1.6 2023/07/10 18:00:13 stephanwib Exp $

.include <bsd.own.mk>

LIB=		root
# MAN=		root.3

SRCS=		time.c port.c thread.c area.c sem.c team.c info.c fs.c image.c debug.c libroot.c parsedate.cpp launch.cpp

LIBDPLIBS+=	pthread ${NETBSDSRCDIR}/lib/libpthread
LIBDPLIBS+=	kvm ${NETBSDSRCDIR}/lib/libkvm

INCS=		OS.h Errors.h fs_attr.h fs_info.h TypeConstants.h image.h SupportDefs.h StorageDefs.h
INCSDIR=	/usr/include

CFLAGS= -Wno-multichar -Wno-implicit-fallthrough -Wno-missing-field-initializers

WARNS=		5

.include <bsd.lib.mk>
