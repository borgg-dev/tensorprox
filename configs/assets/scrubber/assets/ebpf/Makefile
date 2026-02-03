CLANG ?= clang
ARCH  ?= $(shell uname -m | sed 's/x86_64/x86/')

SRC_DIR    := .
BUILD_DIR  := build

SOURCES := \
	$(SRC_DIR)/xdp_wan.c \
	$(SRC_DIR)/xdp_wg_audit.c \
	$(SRC_DIR)/tc_audit_redirect.c \
	$(SRC_DIR)/tc_ingress_wan.c \
	$(SRC_DIR)/tc_ingress_wg.c \
	$(SRC_DIR)/tc_wan_egress.c \
	$(SRC_DIR)/wg_egress_monitor.c

OBJECTS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SOURCES))

CFLAGS := -O2 -g -Wall -target bpf -D__TARGET_ARCH_$(ARCH)
ifeq ($(BPF_DEBUG),1)
CFLAGS += -DENABLE_BPF_DEBUG
endif
INCLUDES := -I$(SRC_DIR) -I/usr/include -I/usr/include/$(shell uname -m)-linux-gnu

.PHONY: all clean verify

all: $(BUILD_DIR) $(OBJECTS)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c $(SRC_DIR)/common.h | $(BUILD_DIR)
	$(CLANG) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)

verify: all
	@echo "=== Verifying eBPF objects ==="
	@for obj in $(OBJECTS); do \
		echo "Checking $$obj"; \
		llvm-objdump -h $$obj | grep -E "\\.text|\\.maps" || true; \
		echo ""; \
	done
