#!/usr/bin/env bash
set -x

# shellcheck source=/dev/null
source "$HOME"/.cargo/env
source "$(dirname "$0")"/test-util.sh

TEST_ARCH=$(uname -m)
export TEST_ARCH

# When invoked directly on the host (rather than through scripts/dev_cli.sh,
# which sets it in the container env), BUILD_TARGET is unset. Default it to the
# native GNU target so both `cargo build --target` and the artifact path resolve.
BUILD_TARGET="${BUILD_TARGET:-${TEST_ARCH}-unknown-linux-gnu}"

WORKLOADS_DIR="$HOME/workloads"
mkdir -p "$WORKLOADS_DIR"

process_common_args "$@"

build_features="mshv"
vm_type_arg=""
if [ "$VM_TYPE" = "confidential" ]; then
    build_features="mshv,igvm,sev_snp"
    vm_type_arg="--vm-type confidential"
fi

# Opt-in extra build features, e.g. EXTRA_FEATURES=net_backend_af_xdp to measure
# the in-process AF_XDP backend. That feature compiles an embedded eBPF program,
# which requires a nightly toolchain (with rust-src) and bpf-linker; the default
# (no extra features) path is unaffected.
if [ -n "$EXTRA_FEATURES" ]; then
    build_features="$build_features,$EXTRA_FEATURES"
    if [[ "$EXTRA_FEATURES" == *"net_backend_af_xdp"* ]]; then
        if ! rustup toolchain list 2>/dev/null | grep -q nightly; then
            echo "net_backend_af_xdp requires nightly: rustup toolchain install nightly --component rust-src"
            exit 1
        fi
        if ! command -v bpf-linker >/dev/null 2>&1; then
            echo "net_backend_af_xdp requires bpf-linker: cargo install bpf-linker"
            exit 1
        fi
    fi
fi

if [ "${TEST_ARCH}" == "aarch64" ]; then
    JAMMY_OS_IMAGE_NAME="jammy-server-cloudimg-arm64-custom-20220329-0.qcow2"
    JAMMY_OS_RAW_IMAGE_NAME="jammy-server-cloudimg-arm64-custom-20220329-0.raw"
else
    JAMMY_OS_IMAGE_NAME="jammy-server-cloudimg-amd64-custom-20241017-0.qcow2"
    JAMMY_OS_RAW_IMAGE_NAME="jammy-server-cloudimg-amd64-custom-20241017-0.raw"
fi

JAMMY_OS_IMAGE="$WORKLOADS_DIR/$JAMMY_OS_IMAGE_NAME"
if [ ! -f "$JAMMY_OS_IMAGE" ]; then
    echo "Missing: $JAMMY_OS_IMAGE — run: python3 scripts/fetch_workloads.py --test metrics"
    exit 1
fi

JAMMY_OS_RAW_IMAGE="$WORKLOADS_DIR/$JAMMY_OS_RAW_IMAGE_NAME"
if [ ! -f "$JAMMY_OS_RAW_IMAGE" ]; then
    pushd "$WORKLOADS_DIR" || exit
    time qemu-img convert -p -f qcow2 -O raw $JAMMY_OS_IMAGE_NAME $JAMMY_OS_RAW_IMAGE_NAME || exit 1
    popd || exit
fi

if [ "${TEST_ARCH}" == "aarch64" ]; then
    KERNEL_IMAGE="$WORKLOADS_DIR/Image-arm64"
else
    KERNEL_IMAGE="$WORKLOADS_DIR/vmlinux-x86_64"
fi
if [ ! -f "$KERNEL_IMAGE" ]; then
    echo "Missing: $KERNEL_IMAGE — run: python3 scripts/fetch_workloads.py --test metrics"
    exit 1
fi

CFLAGS=""
if [[ "${BUILD_TARGET}" == "${TEST_ARCH}-unknown-linux-musl" ]]; then
    # shellcheck disable=SC2034
    CFLAGS="-I /usr/include/${TEST_ARCH}-linux-musl/ -idirafter /usr/include/"
fi

cargo build --features "$build_features" --all --release --target "$BUILD_TARGET"

# setup hugepages
HUGEPAGESIZE=$(grep Hugepagesize /proc/meminfo | awk '{print $2}')
PAGE_NUM=$((12288 * 1024 / HUGEPAGESIZE))
echo "$PAGE_NUM" | sudo tee /proc/sys/vm/nr_hugepages
sudo chmod a+rwX /dev/hugepages

if [ -n "$test_filter" ]; then
    test_binary_args+=("--test-filter $test_filter")
fi

if [ -n "$test_exclude" ]; then
    test_binary_args+=("--test-exclude $test_exclude")
fi

# Ensure that git commands can be run in this directory (for metrics report)
git config --global --add safe.directory "$PWD"

RUST_BACKTRACE_VALUE=$RUST_BACKTRACE
if [ -z "$RUST_BACKTRACE_VALUE" ]; then
    export RUST_BACKTRACE=1
else
    echo "RUST_BACKTRACE is set to: $RUST_BACKTRACE_VALUE"
fi
# shellcheck disable=SC2048,SC2086
time target/"$BUILD_TARGET"/release/performance-metrics $vm_type_arg ${test_binary_args[*]}
RES=$?

exit $RES
