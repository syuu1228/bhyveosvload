# $FreeBSD$

DESTDIR=/usr/local/sbin
PROG=	bhyveosvload
SRCS=	bhyveosvload.c osv.c
MAN=

DPADD+=	${LIBVMMAPI} ${LIBUTIL}
LDADD+=	-lvmmapi -lutil -lelf

WARNS?=	3

CFLAGS+=-I/usr/src/sys/boot/userboot

.include <bsd.prog.mk>
