@echo off
REM VigilNet QA Environment Setup Script for Windows
REM Usage: .\scripts\setup_qa_env.ps1

echo ========================================
echo Setting up VigilNet QA Environment...
echo ========================================
echo.

REM Check prerequisites
echo [1/8] Checking prerequisites...

rustc --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Rust not found. Please install Rust first.
    exit /b 1
)

cargo --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Cargo not found. Please install Rust first.
    exit /b 1
)

echo [OK] Rust found
echo [OK] Cargo found

REM Install Rust components
echo.
echo [2/8] Installing Rust components...
rustup component add rustfmt clippy llvm-tools-preview

REM Install testing tools
echo.
echo [3/8] Installing testing tools...

cargo install cargo-tarpaulin 2>nul
cargo install cargo-audit 2>nul
cargo install cargo-deny 2>nul
cargo install cargo-geiger 2>nul
cargo install cargo-outdated 2>nul
cargo install cargo-watch 2>nul

REM Install nightly toolchain
echo.
echo [4/8] Installing nightly toolchain...
rustup toolchain install nightly
rustup component add miri --toolchain nightly

REM Setup directories
echo.
echo [5/8] Setting up test directories...
if not exist "tests\data\crypto" mkdir "tests\data\crypto"
if not exist "tests\data\network" mkdir "tests\data\network"
if not exist "tests\data\compliance" mkdir "tests\data\compliance"

REM Check for Docker
echo.
echo [6/8] Checking Docker installation...
docker --version >nul 2>&1
if errorlevel 1 (
    echo [WARNING] Docker not found. E2E tests will not work.
) else (
    echo [OK] Docker found
    docker-compose --version >nul 2>&1
    if errorlevel 1 (
        echo [WARNING] docker-compose not found.
    ) else (
        echo [OK] docker-compose found
    )
)

REM Create environment file
echo.
echo [7/8] Creating test environment configuration...
(
echo # VigilNet Test Environment Configuration
echo RUST_LOG=debug
echo RUST_BACKTRACE=1
echo.
echo # Network Configuration
echo TOR_SOCKS_PROXY=socks5://localhost:9050
echo I2P_SAM_BRIDGE=localhost:7656
echo BOOTSTRAP_NODES=/dns4/localhost/tcp/10001
echo.
echo # Test Configuration
echo TEST_TIMEOUT=30
echo TEST_PARALLEL=false
echo.
echo # CI Configuration
echo CI=false
echo COVERAGE_THRESHOLD=85
) > .env.test

echo [OK] Created .env.test

REM Run initial verification
echo.
echo [8/8] Running initial verification...
cargo fmt --all -- --check 2>nul
cargo clippy --workspace --all-targets 2>nul
cargo test --workspace --lib --quiet 2>nul && echo [OK] Unit tests pass || echo [WARNING] Some tests need attention

echo.
echo ========================================
echo QA Environment Setup Complete!
echo ========================================
echo.
echo Next steps:
echo   1. Review QA_PLAN.md for comprehensive testing strategy
echo   2. Run unit tests: cargo test --workspace --lib
echo   3. Run integration tests: cargo test --workspace --test '*'
echo   4. Run E2E tests: See QA_PLAN.md for setup
echo.
echo Useful commands:
echo   cargo tarpaulin --workspace --out Html
echo   cargo bench --workspace
echo   cargo audit
echo   cargo watch -x "test --workspace --lib"
echo.
pause
