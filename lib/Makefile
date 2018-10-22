#
# Makefile for the NSS and PAM modules used in Local EGA
#

NSS_LD_SONAME=-Wl,-soname,libnss_ega.so.2
NSS_LIBRARY=libnss_ega.so.2.0
PAM_LIBRARY = pam_ega.so

CC=gcc
LD=ld
AS=gcc -c
CFLAGS=-Wall -Wstrict-prototypes -Werror -fPIC -I. -I/usr/local/include -O2
LIBS=-lpam -L/usr/local/lib -lsqlite3 -luuid -lqrencode

ifdef SYSLOG
CFLAGS += -DHAS_SYSLOG
endif

EGA_LIBDIR=/usr/local/lib/ega
EGA_BINDIR=/usr/local/bin

HEADERS = utils.h config.h backend.h homedir.h qr.h

NSS_SOURCES = nss.c config.c backend.c
NSS_OBJECTS = $(NSS_SOURCES:%.c=%.o)

PAM_SOURCES = pam.c config.c backend.c homedir.c qr.c
PAM_OBJECTS = $(PAM_SOURCES:%.c=%.o)

.PHONY: all debug clean install install-nss install-pam qrencode
.SUFFIXES: .c .o .so .so.2 .so.2.0

all: install

debug1: CFLAGS += -DDEBUG=1 -g -DREPORT
debug1: install

debug2: CFLAGS += -DDEBUG=2 -g -DREPORT
debug2: install

debug3: CFLAGS += -DDEBUG=3 -g -DREPORT
debug3: install

$(NSS_LIBRARY): $(HEADERS) $(NSS_OBJECTS)
	@echo "Linking objects into $@"
	@$(CC) -shared $(NSS_LD_SONAME) -o $@ $(LIBS) $(NSS_OBJECTS)

$(PAM_LIBRARY): $(HEADERS) $(PAM_OBJECTS)
	@echo "Linking objects into $@"
	@$(LD) -x --shared -o $@ $(LIBS) $(PAM_OBJECTS)

%.o: %.c $(HEADERS)
	@echo "Compiling $<"
	@$(CC) $(CFLAGS) -c -o $@ $<

install-nss: $(NSS_LIBRARY)
	@[ -d $(EGA_LIBDIR) ] || { echo "Creating lib dir: $(EGA_LIBDIR)"; install -d $(EGA_LIBDIR); }
	@echo "Installing $< into $(EGA_LIBDIR)"
	@install $< $(EGA_LIBDIR)

install-pam: $(PAM_LIBRARY)
	@[ -d $(EGA_LIBDIR) ] || { echo "Creating lib dir: $(EGA_LIBDIR)"; install -d $(EGA_LIBDIR); }
	@echo "Installing $< into $(EGA_LIBDIR)"
	@install $< $(EGA_LIBDIR)

install: install-nss install-pam
	@echo "Do not forget to run ldconfig and create/configure the file /etc/ega/auth.conf"
	@echo "Look at the auth.conf.sample here, for example"

clean:
	-rm -f $(NSS_LIBRARY) $(NSS_OBJECTS)
	-rm -f $(PAM_LIBRARY) $(PAM_OBJECTS)

qrencode: CFLAGS += -DDEBUG=3 -g -DREPORT
qrencode: qrtest.o
	$(CC) -o $@ $< -lqrencode
