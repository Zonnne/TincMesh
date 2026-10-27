# Builds the TincCore C library natively (Linux or macOS) and runs the
# integration tests in this directory. This exercises exactly the C code
# the iOS app links, minus the Swift/NetworkExtension layer.
#
#   make -C tests          # build everything
#   make -C tests check    # build and run all tests

CC ?= cc
CORE := ../TincCore
BUILD := build

CFLAGS += -std=gnu11 -O2 -g -Wall -Wno-unused-parameter -Wno-address-of-packed-member -Wno-unknown-warning-option -Wno-unused-result -Wno-format-truncation -Wno-stringop-truncation \
          -I$(CORE) -I$(CORE)/tinc -I$(CORE)/ios
LDLIBS += -lz -lpthread -lm

TINC_SRCS := $(filter-out $(CORE)/tinc/tincd.c $(CORE)/tinc/control.c $(CORE)/tinc/script.c $(CORE)/tinc/process.c, \
               $(wildcard $(CORE)/tinc/*.c)) \
             $(wildcard $(CORE)/tinc/ed25519/*.c) \
             $(wildcard $(CORE)/tinc/chacha-poly1305/*.c) \
             $(wildcard $(CORE)/tinc/nolegacy/*.c)
IOS_SRCS := $(wildcard $(CORE)/ios/*.c)
OBJS := $(patsubst $(CORE)/%.c,$(BUILD)/%.o,$(TINC_SRCS) $(IOS_SRCS))

all: $(BUILD)/libtinccore.a $(BUILD)/node_harness $(BUILD)/join_harness

$(BUILD)/%.o: $(CORE)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/libtinccore.a: $(OBJS)
	ar rcs $@ $^

$(BUILD)/%: %.c $(BUILD)/libtinccore.a
	$(CC) $(CFLAGS) $< -o $@ $(BUILD)/libtinccore.a $(LDLIBS)

check: all
	./run_tests.sh

clean:
	rm -rf $(BUILD)

.PHONY: all check clean
