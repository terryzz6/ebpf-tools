# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT := $(abspath .output)

ARCH ?= arm64

CLANG ?= /home/zhou/android/android-ndk-r27b/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang
LLVM_STRIP ?= /home/zhou/android/android-ndk-r27b/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip
BPFTOOL ?= ./bin/bpftool
LIBBPF_OBJ := ./${ARCH}/lib/libbpf.a



INCLUDES := -I$(OUTPUT) -I${ARCH}/include

CFLAGS := -g -O2 -Wall -Wmissing-field-initializers -Werror -Werror=undef
BPFCFLAGS := -g -O2 -Wall -Werror=undef


USE_BLAZESYM ?= 1
$(shell [ -d $(OUTPUT) ] || mkdir -p $(OUTPUT))





ifeq ($(wildcard $(ARCH)/),)
$(error Architecture $(ARCH) is not supported yet. Please open an issue)
endif

BZ_APPS = \
	estrace \
	#

APPS = \
	hello_world \
	$(BZ_APPS) \
	#

# export variables that are used in Makefile.btfgen as well.
export OUTPUT BPFTOOL ARCH BTFHUB_ARCHIVE APPS

APP_ALIASES = $(FSDIST_ALIASES) $(FSSLOWER_ALIASES) ${SIGSNOOP_ALIAS}

COMMON_OBJ = \
	$(OUTPUT)/trace_helpers.o \
	$(OUTPUT)/syscall_helpers.o \
	$(OUTPUT)/errno_helpers.o \
	$(OUTPUT)/map_helpers.o \
	$(OUTPUT)/uprobe_helpers.o \
	$(OUTPUT)/btf_helpers.o \
	$(OUTPUT)/compat.o \
	$(OUTPUT)/path_helpers.o \
	#



define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
            $(findstring command line,$(origin $(1)))),,\
    $(eval $(1) = $(2)))
endef


.PHONY: all
all: $(APPS) $(APP_ALIASES)

ifeq ($(V),1)
Q =
msg =
else
Q = @
msg = @printf '  %-8s %s%s\n' "$(1)" "$(notdir $(2))" "$(if $(3), $(3))";
MAKEFLAGS += --no-print-directory
endif

ifneq ($(EXTRA_CFLAGS),)
CFLAGS += $(EXTRA_CFLAGS)
endif
ifneq ($(EXTRA_LDFLAGS),)
LDFLAGS += $(EXTRA_LDFLAGS)
endif
ifeq ($(USE_BLAZESYM),1)
CFLAGS += -DUSE_BLAZESYM=1
endif

ifeq ($(USE_BLAZESYM),1)
LDFLAGS += ${ARCH}/lib/libblazesym.a -lrt -lpthread -ldl
endif

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APPS) $(APP_ALIASES)


$(APPS): %: $(OUTPUT)/%.o $(COMMON_OBJ) $(LIBBPF_OBJ) | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CLANG) $(CFLAGS) $^ -L./$(ARCH)/lib -static -lblazesym -lbcc_bpf -lelf -lz -largp -o $@



$(patsubst %,$(OUTPUT)/%.o,$(APPS)): %.o: %.skel.h

$(OUTPUT)/%.o: %.c $(wildcard %.h) $(LIBBPF_OBJ) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CLANG) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@



$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@


$(OUTPUT)/%.bpf.o: %.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) $(ARCH)/vmlinux.h | $(OUTPUT)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) $(BPFCFLAGS) -target bpf -D__TARGET_ARCH_$(ARCH)	      \
		     -I$(ARCH)/ $(INCLUDES) $(BPF_INCLUDES)                   \
		     -c $(filter %.c,$^) -o $@ &&                             \
	$(LLVM_STRIP) -g $@


.PHONY: force
force:

# delete failed targets
.DELETE_ON_ERROR:
# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY: