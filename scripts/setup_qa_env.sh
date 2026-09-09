#!/bin/bash
# VigilNet QA Environment Setup Script
# Usage: ./scripts/setup_qa_env.sh

set -e

echo "🧪 Setting up VigilNet QA Environment..."

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check prerequisites
echo "📋 Checking prerequisites..."

if ! command -v rustc &> /dev/null; then
    echo -e "${RED}❌ Rust not found. Please install Rust first.${NC}"
    exit 1
fi

if ! command -v cargo &> /dev/null; then
    echo -e "${RED}❌ Cargo not found. Please install Rust first.${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Rust found: $(rustc --version)${NC}"
echo -e "${GREEN}✓ Cargo found: $(cargo --version)${NC}"

# Install Rust components
echo ""
echo "🔧 Installing Rust components..."
rustup component add rustfmt clippy llvm-tools-preview

# Install testing tools
echo ""
echo "📦 Installing testing tools..."

cargo_install() {
    if ! command -v $1 &> /dev/null; then
        echo "Installing $1..."
        cargo install $2
    else
        echo -e "${GREEN}✓ $1 already installed${NC}"
    fi
}

cargo_install "cargo-tarpaulin" "cargo-tarpaulin"
cargo_install "cargo-audit" "cargo-audit"
cargo_install "cargo-deny" "cargo-deny"
cargo_install "cargo-geiger" "cargo-geiger"
cargo_install "cargo-outdated" "cargo-outdated"
cargo_install "cargo-watch" "cargo-watch"

# Install nightly tools
if ! rustup toolchain list | grep -q "nightly"; then
    echo "Installing Rust nightly toolchain..."
    rustup toolchain install nightly
    rustup component add miri --toolchain nightly
fi

# Install fuzzing tools (optional)
read -p "Install fuzzing tools? (requires nightly) [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    cargo_install "cargo-fuzz" "cargo-fuzz"
fi

# Install system dependencies (Linux)
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo ""
    echo "🐧 Installing Linux system dependencies..."
    
    if command -v apt-get &> /dev/null; then
        sudo apt-get update
        sudo apt-get install -y \
            libssl-dev \
            pkg-config \
            protobuf-compiler \
            net-tools \
            iproute2
    elif command -v yum &> /dev/null; then
        sudo yum install -y \
            openssl-devel \
            pkgconfig \
            protobuf-compiler
    elif command -v pacman &> /dev/null; then
        sudo pacman -S --needed \
            openssl \
            pkgconf \
            protobuf
    fi
fi

# Install system dependencies (macOS)
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo ""
    echo "🍎 Installing macOS system dependencies..."
    
    if ! command -v brew &> /dev/null; then
        echo -e "${YELLOW}⚠️ Homebrew not found. Please install Homebrew first.${NC}"
    else
        brew install openssl protobuf
    fi
fi

# Setup test data
echo ""
echo "📁 Setting up test data..."
mkdir -p tests/data/crypto
mkdir -p tests/data/network
mkdir -p tests/data/compliance

# Generate test vectors
echo "Generating cryptographic test vectors..."
cargo run --bin generate_test_vectors 2>/dev/null || echo "No test vector generator found, skipping..."

# Setup Docker environment
echo ""
echo "🐳 Setting up Docker test environment..."
if command -v docker &> /dev/null; then
    if command -v docker-compose &> /dev/null; then
        echo "Building test images..."
        docker-compose -f tests/e2e/docker-compose.yml build --parallel 2>/dev/null || echo "Docker images will be built on first test run"
    else
        echo -e "${YELLOW}⚠️ docker-compose not found. E2E tests may not work properly.${NC}"
    fi
else
    echo -e "${YELLOW}⚠️ Docker not found. E2E tests will not work.${NC}"
fi

# Install semgrep (optional)
read -p "Install semgrep for security scanning? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    if command -v pip3 &> /dev/null; then
        pip3 install semgrep
    elif command -v brew &> /dev/null; then
        brew install semgrep
    else
        echo -e "${YELLOW}⚠️ Could not install semgrep automatically${NC}"
    fi
fi

# Create .env file for tests
echo ""
echo "📝 Creating test environment configuration..."
cat > .env.test << 'EOF'
# VigilNet Test Environment Configuration
RUST_LOG=debug
RUST_BACKTRACE=1

# Network Configuration
TOR_SOCKS_PROXY=socks5://localhost:9050
I2P_SAM_BRIDGE=localhost:7656
BOOTSTRAP_NODES=/dns4/localhost/tcp/10001

# Test Configuration
TEST_TIMEOUT=30
TEST_PARALLEL=false

# CI Configuration
CI=false
COVERAGE_THRESHOLD=85
EOF

echo -e "${GREEN}✓ Created .env.test${NC}"

# Run initial verification
echo ""
echo "🧪 Running initial verification..."
cargo fmt --all -- --check 2>/dev/null || echo "Formatting needed"
cargo clippy --workspace --all-targets 2>/dev/null || echo "Clippy warnings found"
cargo test --workspace --lib --quiet 2>/dev/null && echo -e "${GREEN}✓ Unit tests pass${NC}" || echo -e "${YELLOW}⚠️ Some tests failed${NC}"

# Summary
echo ""
echo "========================================"
echo -e "${GREEN}✅ QA Environment Setup Complete!${NC}"
echo "========================================"
echo ""
echo "Next steps:"
echo "  1. Review QA_PLAN.md for comprehensive testing strategy"
echo "  2. Run unit tests: cargo test --workspace --lib"
echo "  3. Run integration tests: cargo test --workspace --test '*'"
echo "  4. Run E2E tests: docker-compose -f tests/e2e/docker-compose.yml up -d && cargo test --workspace --test e2e"
echo ""
echo "Useful commands:"
echo "  cargo tarpaulin --workspace --out Html    # Generate coverage report"
echo "  cargo bench --workspace                   # Run benchmarks"
echo "  cargo audit                               # Security audit"
echo "  cargo watch -x 'test --workspace --lib'   # Watch mode"
echo ""
echo "For questions, see tests/README.md or contact the QA team."
