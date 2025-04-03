#!/bin/bash -

# --- Configuration ---
OPENSSL_BASE_URL="https://www.openssl.org/source/"
LOG_DIR="openssl-benchmarks"
NUM_CPU_CORES=$(nproc)
INSTALL_EXIT_FILE="install-exit-status"
TEST_EXIT_FILE="test-exit-status"
NUM_TEST_RUNS=3

# --- Helper Functions ---
log_info() {
  echo "[INFO] $1"
}

log_error() {
  echo "[ERROR] $1"
}

get_latest_openssl_version() {
  local download_page_content
  download_page_content=$(wget -qO- "${OPENSSL_BASE_URL}")

  # Extract the latest stable version from the download page
  local latest_version=$(echo "$download_page_content" | grep -oE 'openssl-[0-9]+\.[0-9]+\.[0-9]+\.tar\.gz' | head -n 1 | sed -E 's/openssl-(.+)\.tar\.gz/\1/')

  if [ -z "$latest_version" ]; then
    log_error "Failed to retrieve the latest OpenSSL version."
    return 1
  fi
  echo "$latest_version"
  return 0
}

get_evp_flag() {
  local algo="$1"
  if [[ "$algo" == "aes-128-gcm" || "$algo" == "aes-256-gcm" || "$algo" == "chacha20" || "$algo" == "chacha20-poly1305" ]]; then
    echo "-evp"
  else
    echo ""
  fi
}

# --- Get Latest OpenSSL Version ---
log_info "Fetching the latest stable OpenSSL version..."
latest_version=$(get_latest_openssl_version)
if [ $? -ne 0 ]; then
  exit 1
fi
OPENSSL_VERSION="${latest_version}"
OPENSSL_TAR_GZ="openssl-${OPENSSL_VERSION}.tar.gz"
OPENSSL_URL="${OPENSSL_BASE_URL}${OPENSSL_TAR_GZ}"

log_info "Latest stable OpenSSL version found: ${OPENSSL_VERSION}"

# --- Download OpenSSL ---
log_info "Downloading OpenSSL ${OPENSSL_VERSION} from ${OPENSSL_URL}..."
if [ ! -f "${OPENSSL_TAR_GZ}" ]; then
  wget "${OPENSSL_URL}" || { log_error "Failed to download OpenSSL."; exit 1; }
else
  log_info "OpenSSL archive already exists."
fi

# --- Extract OpenSSL ---
log_info "Extracting OpenSSL ${OPENSSL_VERSION}..."
if [ ! -d "openssl-${OPENSSL_VERSION}" ]; then
  tar -xf "${OPENSSL_TAR_GZ}" || { log_error "Failed to extract OpenSSL."; exit 1; }
else
  log_info "OpenSSL source directory already exists."
fi

# --- Configure and Build OpenSSL ---
log_info "Configuring OpenSSL..."
cd "openssl-${OPENSSL_VERSION}" || exit 1
./config no-zlib || { log_error "Failed to configure OpenSSL."; exit 1; }

log_info "Building OpenSSL using ${NUM_CPU_CORES} cores..."
make -j "${NUM_CPU_CORES}" || { log_error "Failed to build OpenSSL."; exit 1; }
install_exit_status=$?
echo "$install_exit_status" > "../${INSTALL_EXIT_FILE}"
cd ..

# --- Create Log Directory ---
mkdir -p "${LOG_DIR}"

# --- Benchmark Algorithms ---
log_info "Starting OpenSSL benchmarks..."

BENCHMARK_ALGORITHMS=(
  "rsa4096"
  "sha256"
  "sha512"
  "aes-128-gcm"
  "aes-256-gcm"
  "chacha20"
  "chacha20-poly1305"
  "rsa"
  "aes"
  "sha256"
)

BENCHMARK_MODES=(
  "single"
  "multi"
)

for algo in "${BENCHMARK_ALGORITHMS[@]}"; do
  for mode in "${BENCHMARK_MODES[@]}"; do
    for run in $(seq 1 "$NUM_TEST_RUNS"); do
      log_info "Benchmarking algorithm: ${algo}, mode: ${mode}, run: ${run}"
      if [ "$mode" == "single" ]; then
        NUM_THREADS=1
        LOG_FILE="../${LOG_DIR}/${algo// /_}_${mode}_run${run}.log"
      else
        NUM_THREADS="$NUM_CPU_CORES"
        LOG_FILE="../${LOG_DIR}/${algo// /_}_${mode}_run${run}.log"
      fi
      cd "openssl-${OPENSSL_VERSION}" || exit 1

      evp_flag=$(get_evp_flag "$algo")

      if [ "$mode" == "single" ]; then
        LD_LIBRARY_PATH=.:"$LD_LIBRARY_PATH" ./apps/openssl speed $evp_flag "$algo" > "$LOG_FILE" 2>&1
      else
        LD_LIBRARY_PATH=.:"$LD_LIBRARY_PATH" ./apps/openssl speed -multi "$NUM_THREADS" $evp_flag "$algo" > "$LOG_FILE" 2>&1
      fi
      test_exit_status=$?
      echo "$test_exit_status" > "../${TEST_EXIT_FILE}"
      cd ..
      if [ $test_exit_status -eq 0 ]; then
        log_info "Benchmark for ${algo} in ${mode} mode (run ${run}) completed. Results in ${LOG_FILE}"
      else
        log_error "Benchmark for ${algo} in ${mode} mode (run ${run}) failed. See logs in ${LOG_FILE}"
      fi
    done
  done
done

log_info "All OpenSSL benchmarks completed. Logs are in the '${LOG_DIR}' directory."

# --- Optional: Clean up OpenSSL source directory ---
log_info "Cleaning up OpenSSL source directory..."
rm -rf "openssl-${OPENSSL_VERSION}"
rm "${OPENSSL_TAR_GZ}"

exit 0
