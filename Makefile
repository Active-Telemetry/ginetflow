ifneq ($(V),1)
	Q=@
endif

DESTDIR?=
PREFIX?=/usr/
CC:=$(CROSS_COMPILE)gcc
PKG_CONFIG ?= pkg-config
GREP = grep --line-buffered --color=always

CFLAGS = -fPIC -g -O2

EXTRA_CFLAGS = `$(PKG_CONFIG) --cflags glib-2.0 gio-2.0` -I.
EXTRA_LDFLAGS = `$(PKG_CONFIG) --libs glib-2.0 gio-2.0` 
EXTRA_LDFLAGS += -pthread

NDPIVERSION := $(shell $(PKG_CONFIG) --atleast-version=1.7 libndpi && echo NEW || ($(PKG_CONFIG) --exists libndpi && echo OLD || echo NONE))
ifneq ($(NDPIVERSION),NONE)
DEMO_CFLAGS = $(CFLAGS) $(EXTRA_CFLAGS)
DEMO_CFLAGS += $(shell $(PKG_CONFIG) --cflags libndpi)
DEMO_CFLAGS += -DLIBNDPI_$(NDPIVERSION)_API
DEMO_LDFLAGS = $(LDFLAGS) $(EXTRA_LDFLAGS) -L. -lginetflow
DEMO_LDFLAGS += $(shell $(PKG_CONFIG) --libs libndpi) -lpcap
endif

NOVAPROVA := $(shell $(PKG_CONFIG) --atleast-version=1.4 novaprova && echo yes || echo no)
ifeq ($(NOVAPROVA),yes)
NOVAPROVA_CFLAGS= $(CFLAGS) $(EXTRA_CFLAGS) `$(PKG_CONFIG) --cflags novaprova`
NOVAPROVA_LIBS := $(LDFLAGS) `$(PKG_CONFIG) --libs novaprova` $(EXTRA_LDFLAGS) -lz -liberty
FORMAT_RESULTS = $(GREP) -v "^np: running" $(COLOR_RESULTS)
COLOR_RESULTS = | $(GREP) -E 'FAIL|$$' | GREP_COLOR='01;32' $(GREP) -E 'PASS|$$'
ifndef NOVAPROVA_VALGRIND
ifeq ($(VALGRIND),no)
export NOVAPROVA_VALGRIND=no
endif
endif
endif

LIBRARY = libginetflow.so

all: $(LIBRARY)

$(LIBRARY): ginetflow.o
	@echo "Building "$@""
	$(Q)$(CC) -shared $(LDFLAGS) $(EXTRA_LDFLAGS) -o $@ $^

%.o: %.c
	@echo "Compiling "$<""
	$(Q)$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -c $< -o $@

demo: demo.c $(LIBRARY)
	@echo "Compiling $@"
	$(Q)$(CC) $(DEMO_CFLAGS) -o $@ $^ $(DEMO_LDFLAGS)

test: test.c
	@echo "Building $@"
	$(Q)$(CC) -g -fprofile-arcs -ftest-coverage $(NOVAPROVA_CFLAGS) -o $@ $< $(NOVAPROVA_LIBS)
	$(Q)G_SLICE=always-malloc ./test $(TESTSPEC) 2>&1 | $(FORMAT_RESULTS)

install: all
	@install -d $(DESTDIR)/$(PREFIX)/lib
	@install -D $(LIBRARY) $(DESTDIR)/$(PREFIX)/lib/
	@install -d $(DESTDIR)/$(PREFIX)/include
	@install -D ginetflow.h $(DESTDIR)/$(PREFIX)/include
	@install -d $(DESTDIR)/$(PREFIX)/lib/pkgconfig
	@install -D ginetflow.pc $(DESTDIR)/$(PREFIX)/lib/pkgconfig/

clean:
	@echo "Cleaning..."
	@rm -f $(LIBRARY) *.o demo

.PHONY: all clean test
