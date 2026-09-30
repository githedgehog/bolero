#!/usr/bin/env bash

set -e

# Upstream has not tagged a release since 2.6 (2023), which predates the GCC 15 and
# binutils >= 2.39 build fixes, so track a pinned commit on master. Accepts a tag or commit.
version=${1:-940b958dfeb6f9131fd846cae31fcc0fe996ae98}
project_dir="$(pwd)"
tmp_dir="$(mktemp -d)"
honggfuzz_dir="$project_dir/honggfuzz/"

git clone --quiet https://github.com/google/honggfuzz.git "$tmp_dir"
git -C "$tmp_dir" checkout --quiet "$version"
revision="$(git -C "$tmp_dir" rev-parse HEAD)"
rm -rf "$honggfuzz_dir"
mkdir -p "$honggfuzz_dir"
mv "$tmp_dir/android/" "$honggfuzz_dir"
mv "$tmp_dir/includes/" "$honggfuzz_dir"
mv "$tmp_dir/libhfcommon/" "$honggfuzz_dir"
mv "$tmp_dir/libhfuzz/" "$honggfuzz_dir"
mv "$tmp_dir/libhfnetdriver/" "$honggfuzz_dir"
mv "$tmp_dir/linux/" "$honggfuzz_dir"
mv "$tmp_dir/mac/" "$honggfuzz_dir"
mv "$tmp_dir/netbsd/" "$honggfuzz_dir"
mv "$tmp_dir/posix/" "$honggfuzz_dir"
mv "$tmp_dir/third_party/" "$honggfuzz_dir"
mv "$tmp_dir/COPYING" "$honggfuzz_dir"
mv "$tmp_dir/Makefile" "$honggfuzz_dir"
mv "$tmp_dir"/*.c "$honggfuzz_dir"
mv "$tmp_dir"/*.h "$honggfuzz_dir"
echo "$revision" > "$honggfuzz_dir/REVISION"

function replace() {
    sed -i.bak -e "$1" "$2"
    rm "$2.bak"
}

SRC=$project_dir/honggfuzz/*.c
for f in $SRC
do
    name=$(basename "$f" .c | sed 's/-/_/g')
    replace "s/int main/int ${name}_main/" $f
done

replace "s/return EXIT_SUCCESS/return hfuzz->cnts.crashesCnt > 0 ? EXIT_FAILURE : EXIT_SUCCESS/" $project_dir/honggfuzz/honggfuzz.c

# build the fuzzer itself as a static library so cargo-bolero can link it and call honggfuzz_main
cat >> "$project_dir/honggfuzz/Makefile" <<'MAKEFILE'

$(_OBJDIR)/libhonggfuzz.a: $(OBJS) $(LCOMMON_ARCH) | $$(dir $$@)
	$(AR) rcs $@ $(OBJS)
MAKEFILE
