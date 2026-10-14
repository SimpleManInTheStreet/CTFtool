CC      ?= cc
CFLAGS  ?= -O2 -g -Wall -Wextra -std=gnu11 -Isrc -pthread
LDFLAGS ?=

SRCDIR := src
COMMON := $(SRCDIR)/common/util.c
PROTO  := $(SRCDIR)/proto/proto.c

LOGIC_SRC := $(SRCDIR)/logic/main.c $(SRCDIR)/logic/logic.c $(SRCDIR)/logic/algos.c
WEB_SRC   := $(SRCDIR)/web/main.c $(SRCDIR)/web/web.c

BINDIR := bin
LOGIC_BIN := $(BINDIR)/ctf_logic
WEB_BIN   := $(BINDIR)/ctf_web

.PHONY: all clean run-logic run-web

all: $(LOGIC_BIN) $(WEB_BIN)

$(LOGIC_BIN): $(LOGIC_SRC) $(PROTO) $(COMMON) | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(WEB_BIN): $(WEB_SRC) $(PROTO) $(COMMON) | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BINDIR):
	mkdir -p $(BINDIR)

run-logic: $(LOGIC_BIN)
	$(LOGIC_BIN)

run-web: $(WEB_BIN)
	$(WEB_BIN)

clean:
	rm -rf $(BINDIR)
