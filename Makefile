ifneq ($(V),1)
	Q=@
endif

DESTDIR?=
PREFIX?=/usr/
CC:=$(CROSS_COMPILE)gcc
PKG_CONFIG ?= pkg-config

CFLAGS = -fPIC -g -O2

EXTRA_CFLAGS = `$(PKG_CONFIG) --cflags glib-2.0 gio-2.0` -I.
EXTRA_LDFLAGS = `$(PKG_CONFIG) --libs glib-2.0 gio-2.0` 
EXTRA_LDFLAGS += -pthread

NDPIVERSION := $(shell \
	$(PKG_CONFIG) --atleast-version=2.2 libndpi && echo NEWEST || \
	($(PKG_CONFIG) --atleast-version=1.7 libndpi && echo NEW || \
	($(PKG_CONFIG) --exists libndpi && echo OLD || \
	echo NONE)))
ifneq ($(NDPIVERSION),NONE)
DEMO_CFLAGS = $(CFLAGS) $(EXTRA_CFLAGS)
DEMO_CFLAGS += $(shell $(PKG_CONFIG) --cflags libndpi)
DEMO_CFLAGS += -DLIBNDPI_$(NDPIVERSION)_API
DEMO_LDFLAGS = $(LDFLAGS) $(EXTRA_LDFLAGS) -L. -lginetflow
DEMO_LDFLAGS += $(shell $(PKG_CONFIG) --libs libndpi) -lpcap
endif

LIBRARY = libginetflow.so

all: $(LIBRARY)

$(LIBRARY): ginetflow.o ginettuple.o ginetfraglist.o
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
	$(Q)mkdir -p gcov
	$(Q)$(CC) -g -fprofile-arcs -fprofile-dir=gcov -ftest-coverage $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $< $(LDFLAGS) $(EXTRA_LDFLAGS)
	# $(Q)valgrind --tool=callgrind ./test -p /flow/create/many
	$(Q)G_SLICE=always-malloc VALGRIND_OPTS=--suppressions=valgrind.supp valgrind --leak-check=full ./test 2>&1
	$(Q)mv *.gcno gcov/
	$(Q)lcov -q --capture --directory . --output-file gcov/coverage.info
	$(Q)genhtml -q gcov/coverage.info --output-directory gcov

indent:
	indent -kr -nut -l92 *.c *.h
	rm *.c~ *.h~

install: all
	@install -d $(DESTDIR)/$(PREFIX)/lib
	@install -D $(LIBRARY) $(DESTDIR)/$(PREFIX)/lib/
	@install -d $(DESTDIR)/$(PREFIX)/include
	@install -D ginetflow.h $(DESTDIR)/$(PREFIX)/include
	@install -D ginettuple.h $(DESTDIR)/$(PREFIX)/include
	@install -D ginetfraglist.h $(DESTDIR)/$(PREFIX)/include
	@install -d $(DESTDIR)/$(PREFIX)/lib/pkgconfig
	@install -D ginetflow.pc $(DESTDIR)/$(PREFIX)/lib/pkgconfig/

clean:
	@echo "Cleaning..."
	@rm -fr $(LIBRARY) *.o demo test gcov

.PHONY: all clean test
