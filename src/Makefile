INSTALL ?= install
PREFIX ?= /usr/local
CC ?= gcc

# Compile and link flags
# Use ?= to allow users to add CFLAGS externally (e.g., make CFLAGS="-g -O2")
# -pthread for thread-safe compilation (v4)
# -ldl for dlsym
CFLAGS ?= -shared -fPIC -pthread
LDFLAGS ?= -ldl

LIB_DIR := $(PREFIX)/lib
DOC_DIR := $(PREFIX)/share/doc/libfakestat

SRC := libfakestat.c
TARGET := libfakestat.so
#DOC_FILE := README.md

RM := rm -f

.PHONY: all install uninstall clean distclean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

install: all
	$(INSTALL) -dm0755 "$(DESTDIR)$(LIB_DIR)"
	$(INSTALL) -dm0755 "$(DESTDIR)$(DOC_DIR)"
	
	$(INSTALL) -m0755 "$(TARGET)" "$(DESTDIR)$(LIB_DIR)/$(TARGET)"
	
	#$(INSTALL) -m0644 "$(DOC_FILE)" "$(DESTDIR)$(DOC_DIR)/$(DOC_FILE)"

uninstall:
	$(RM) "$(DESTDIR)$(LIB_DIR)/$(TARGET)"
	#$(RM) "$(DESTDIR)$(DOC_DIR)/$(DOC_FILE)"
	-rmdir "$(DESTDIR)$(DOC_DIR)" 2>/dev/null || true

clean:
	$(RM) $(TARGET)

distclean: clean
