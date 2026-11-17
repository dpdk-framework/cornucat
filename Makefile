CC ?= cc
PKG_CONFIG ?= pkg-config
CPPFLAGS += -Iinclude
CFLAGS ?= -O2 -g
WARNINGS = -std=c11 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wformat=2
CORE = src/packet.c src/options.c src/streams.c src/replay.c
# Treat dependency headers as system headers; keep strict warnings on project code.
DPDK_CFLAGS = $(patsubst -I%,-isystem %,$(shell $(PKG_CONFIG) --cflags libdpdk))

.PHONY: all dpdk receiver relay inspect-pcap tcp-session clean
all: build/packetgen

build:
	mkdir -p build

build/packetgen: src/main.c src/pcap.c $(CORE) include/packet.h include/options.h include/streams.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) src/main.c src/pcap.c $(CORE) $(LDFLAGS) -o $@

dpdk: build/packetgen-dpdk build/inspect-pcap
	chmod +x packet-gen-dpdk

receiver: build/packetgen-receiver

relay: build/packetgen-relay

inspect-pcap: build/inspect-pcap

build/packetgen-dpdk: src/main.c src/pcap.c src/dpdk_backend.c src/dpdk_streams.c src/dpdk_replay.c $(CORE) include/packet.h include/options.h include/streams.h include/replay.h | build
	$(PKG_CONFIG) --atleast-version=23.07 libdpdk
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) -DPG_HAVE_DPDK $(DPDK_CFLAGS) src/main.c src/pcap.c src/dpdk_backend.c src/dpdk_streams.c src/dpdk_replay.c $(CORE) $(LDFLAGS) $$( $(PKG_CONFIG) --libs libdpdk ) -o $@

tcp-session: build/tcp-session-fstack

build/tcp-session-fstack: src/tcp_session_fstack.c | build
	test -f "$(FSTACK_DIR)/lib/libfstack.a"
	grep -Fq -- 'Packet Generator: private single-process hugepages.' "$(FSTACK_DIR)/lib/ff_config.c"
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) $(DPDK_CFLAGS) -isystem "$(FSTACK_DIR)/lib" src/tcp_session_fstack.c $(LDFLAGS) -Wl,--whole-archive "$(FSTACK_DIR)/lib/libfstack.a" -Wl,--no-whole-archive $$( $(PKG_CONFIG) --libs libdpdk ) -lrte_net_bond -lrt -lm -ldl -lcrypto -pthread -lnuma -o $@

build/inspect-pcap: tools/inspect_pcap.c $(CORE) include/replay.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) tools/inspect_pcap.c $(CORE) $(LDFLAGS) -o $@

build/packetgen-receiver: src/dpdk_receiver.c | build
	$(PKG_CONFIG) --atleast-version=23.07 libdpdk
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) $(DPDK_CFLAGS) -pthread src/dpdk_receiver.c $(LDFLAGS) $$( $(PKG_CONFIG) --libs libdpdk ) -o $@

build/packetgen-relay: src/dpdk_relay.c | build
	$(PKG_CONFIG) --atleast-version=23.07 libdpdk
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) $(DPDK_CFLAGS) src/dpdk_relay.c $(LDFLAGS) $$( $(PKG_CONFIG) --libs libdpdk ) -o $@

clean:
	rm -rf build
