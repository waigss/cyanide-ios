# Builds dfesp.dylib for iOS (arm64 + arm64e).
# Injected into Delta Force with TrollFools.

SDK   := $(shell xcrun --sdk iphoneos --show-sdk-path)
CLANG := xcrun --sdk iphoneos clang

OUT   := output
LIB   := $(OUT)/dfesp.dylib
SRC   := dfesp.m

CFLAGS := -arch arm64 -arch arm64e \
          -miphoneos-version-min=15.0 \
          -isysroot $(SDK) \
          -dynamiclib -O2 -fobjc-arc \
          -framework Foundation \
          -Wno-deprecated-declarations

all: $(LIB)

$(LIB): $(SRC)
	@mkdir -p $(OUT)
	$(CLANG) $(CFLAGS) -o $@ $(SRC)
	@if command -v ldid >/dev/null 2>&1; then ldid -S $@; echo "[ldid] signed"; fi
	@file $@
	@ls -l $@

clean:
	rm -rf $(OUT)

.PHONY: all clean
