# $NetBSD: Makefile,v 1.1 2022/10/15 12:58:43 stephanwib Exp $

NOOBJ=		# defined

.include <bsd.own.mk>

.if ${MKSHARE} != "no"
FILES=		port_close_test_1.cpp port_close_test_2.cpp port_delete_test.cpp port_multi_read_test.cpp  \
			port_wakeup_test_1.cpp port_wakeup_test_2.cpp port_wakeup_test_3.cpp port_wakeup_test_4.cpp \
			port_wakeup_test_5.cpp port_wakeup_test_6.cpp port_wakeup_test_7.cpp port_wakeup_test_8.cpp \
			port_wakeup_test_9.cpp README
FILESDIR=	/usr/share/examples/haiku
.endif

.include <bsd.prog.mk>
