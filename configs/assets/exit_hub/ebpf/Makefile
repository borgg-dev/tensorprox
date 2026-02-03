CLANG ?= clang
ARCH  ?= $(shell uname -m | sed 's/x86_64/x86/')

SRC_DIR   := .
BUILD_DIR := build

SOURCES := \
	$(SRC_DIR)/tc_exit_snat.c \
	$(SRC_DIR)/xdp_metrics.c

OBJECTS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SOURCES))

CFLAGS   := -O2 -g -Wall -target bpf -D__TARGET_ARCH_$(ARCH)
INCLUDES := -I$(SRC_DIR) -I/usr/include -I/usr/include/$(shell uname -m)-linux-gnu

.PHONY: all clean verify

all: $(BUILD_DIR) $(OBJECTS)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CLANG) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)

verify: all
	@echo "=== Verifying exit hub eBPF objects ==="
	@for obj in $(OBJECTS); do \
		echo "Checking $$obj"; \
		llvm-objdump -h $$obj | grep -E "\.text|\.maps" || true; \
		echo ""; \
	done
