#!/bin/bash

# CluelyGuard Installation Script
# Industrial-grade Linux Anti-LLM Proctoring System

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
CLUELYGUARD_VERSION="0.1.0"
INSTALL_DIR="/opt/cluelyguard"
CONFIG_DIR="/etc/cluelyguard"
DATA_DIR="/var/lib/cluelyguard"
LOG_DIR="/var/log/cluelyguard"


# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

# Function to detect OS
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
        OS_ID=$ID
        OS_ID_LIKE=$ID_LIKE
    else
        print_error "Unable to detect operating system"
        exit 1
    fi
}

# Function to detect package manager
detect_package_manager() {
    local pkg_managers=(
        "pacman:Arch-based"
        "apt-get:Debian-based"
        "apt:Debian-based"
        "dnf:Fedora-based"
        "yum:RHEL-based"
        "zypper:openSUSE-based"
        "emerge:Gentoo-based"
        "xbps-install:Void-based"
        "nix-env:NixOS"
        "apk:Alpine-based"
        "brew:Homebrew"
        "snap:Snap"
        "flatpak:Flatpak"
    )
    
    for pkg_manager in "${pkg_managers[@]}"; do
        local cmd="${pkg_manager%%:*}"
        local desc="${pkg_manager##*:}"
        
        if command -v "$cmd" &> /dev/null; then
            echo "$cmd:$desc"
            return 0
        fi
    done
    
    return 1
}

# Function to get package names for different distributions
get_package_names() {
    local pkg_manager=$1
    
    case $pkg_manager in
        "pacman")
            echo "python python-pip libpulse pkg-config curl base-devel python-joblib python-numpy python-scikit-learn"
            ;;
        "apt-get"|"apt")
            echo "python3 python3-pip libpulse-dev pkg-config curl build-essential python3-joblib python3-numpy python3-sklearn"
            ;;
        "dnf"|"yum")
            echo "python3 python3-pip pulseaudio-libs-devel pkgconfig curl gcc python3-joblib python3-numpy python3-scikit-learn"
            ;;
        "zypper")
            echo "python3 python3-pip libpulse-devel pkg-config curl gcc python3-joblib python3-numpy python3-scikit-learn"
            ;;
        "emerge")
            echo "dev-lang/python dev-python/pip media-sound/pulseaudio dev-util/pkgconf net-misc/curl sys-devel/gcc dev-python/joblib dev-python/numpy dev-python/scikit-learn"
            ;;
        "xbps-install")
            echo "python3 python3-pip pulseaudio-devel pkg-config curl base-devel python3-joblib python3-numpy python3-scikit-learn"
            ;;
        "apk")
            echo "python3 py3-pip pulseaudio-dev pkgconfig curl build-base py3-joblib py3-numpy py3-scikit-learn"
            ;;
        *)
            echo "python3 python3-pip libpulse-dev pkg-config curl build-essential"
            ;;
    esac
}

# Function to install packages using detected package manager
install_packages() {
    local pkg_manager=$1
    local packages=$2
    
    case $pkg_manager in
        "pacman")
            pacman -Syu --noconfirm $packages
            ;;
        "apt-get"|"apt")
            apt-get update
            apt-get install -y $packages
            ;;
        "dnf")
            dnf update -y
            dnf install -y $packages
            ;;
        "yum")
            yum update -y
            yum install -y $packages
            ;;
        "zypper")
            zypper refresh
            zypper install -y $packages
            ;;
        "emerge")
            emerge --sync
            emerge -q $packages
            ;;
        "xbps-install")
            xbps-install -Syu
            xbps-install -y $packages
            ;;
        "apk")
            apk update
            apk add $packages
            ;;
        *)
            print_error "Unsupported package manager: $pkg_manager"
            return 1
            ;;
    esac
}

# Function to test distribution compatibility
test_distribution_compatibility() {
    print_status "Testing distribution compatibility..."
    
    local compatible_distros=(
        "Arch Linux|Manjaro|Garuda|EndeavourOS|ArcoLinux|Artix|Parabola"
        "Ubuntu|Debian|Linux Mint|Pop!_OS|Elementary OS|Kali Linux|MX Linux"
        "Fedora|CentOS|RHEL|Rocky Linux|AlmaLinux|Oracle Linux|Amazon Linux"
        "openSUSE|SUSE Linux Enterprise|Tumbleweed|Leap"
        "Gentoo|Funtoo|Calculate Linux"
        "Void Linux"
        "Alpine Linux"
        "NixOS"
        "Clear Linux"
        "Solus"
        "PCLinuxOS"
        "Slackware"
        "FreeBSD|OpenBSD|NetBSD"
    )
    
    local detected=false
    
    for distro_group in "${compatible_distros[@]}"; do
        IFS='|' read -ra distros <<< "$distro_group"
        for distro in "${distros[@]}"; do
            if [[ "$OS" == *"$distro"* ]] || [[ "$OS_ID" == *"$distro"* ]] || [[ "$OS_ID_LIKE" == *"$distro"* ]]; then
                print_success "✅ Compatible distribution detected: $OS"
                detected=true
                break 2
            fi
        done
    done
    
    if [[ "$detected" == false ]]; then
        print_warning "⚠️  Unknown distribution: $OS"
        print_status "Will attempt universal installation using package manager detection"
    fi
}

# Function to check system requirements
check_system_requirements() {
    print_status "Checking system requirements..."
    
    local requirements_met=true
    
    # Check kernel version (Linux 3.0+)
    if [[ -f /proc/version ]]; then
        local kernel_version=$(uname -r | cut -d. -f1,2)
        local major=$(echo $kernel_version | cut -d. -f1)
        local minor=$(echo $kernel_version | cut -d. -f2)
        
        if [[ $major -lt 3 ]] || ([[ $major -eq 3 ]] && [[ $minor -lt 0 ]]); then
            print_warning "⚠️  Kernel version $kernel_version detected. Linux 3.0+ recommended."
            requirements_met=false
        else
            print_success "✅ Kernel version: $kernel_version"
        fi
    fi
    
    # Check available memory (512MB+ recommended)
    if command -v free &> /dev/null; then
        local mem_kb=$(free | grep Mem | awk '{print $2}')
        local mem_mb=$((mem_kb / 1024))
        
        if [[ $mem_mb -lt 512 ]]; then
            print_warning "⚠️  Low memory detected: ${mem_mb}MB. 512MB+ recommended."
            requirements_met=false
        else
            print_success "✅ Available memory: ${mem_mb}MB"
        fi
    fi
    
    # Check available disk space (1GB+ recommended)
    if command -v df &> /dev/null; then
        local disk_kb=$(df / | tail -1 | awk '{print $4}')
        local disk_mb=$((disk_kb / 1024))
        
        if [[ $disk_mb -lt 1024 ]]; then
            print_warning "⚠️  Low disk space: ${disk_mb}MB. 1GB+ recommended."
            requirements_met=false
        else
            print_success "✅ Available disk space: ${disk_mb}MB"
        fi
    fi
    
    # Check if running in container/virtual environment
    if [[ -f /.dockerenv ]] || [[ -f /run/.containerenv ]] || [[ -f /proc/1/cgroup ]] && grep -q docker /proc/1/cgroup; then
        print_warning "⚠️  Running in container environment. Some features may be limited."
    fi
    
    if [[ "$requirements_met" == true ]]; then
        print_success "✅ System requirements check passed"
    else
        print_warning "⚠️  Some system requirements not met, but installation will continue"
    fi
}

# Function to install system dependencies
install_dependencies() {
    print_status "Installing system dependencies..."
    print_status "Detected OS: $OS (ID: $OS_ID, ID_LIKE: $OS_ID_LIKE)"
    
    # Test distribution compatibility
    test_distribution_compatibility
    
    # Check system requirements
    check_system_requirements
    
    # Try to detect package manager
    local pkg_manager_info=$(detect_package_manager)
    
    if [[ $? -eq 0 ]]; then
        local pkg_manager="${pkg_manager_info%%:*}"
        local pkg_desc="${pkg_manager_info##*:}"
        
        print_status "Detected package manager: $pkg_manager ($pkg_desc)"
        
        # Get appropriate package names for this distribution
        local packages=$(get_package_names "$pkg_manager")
        print_status "Installing packages: $packages"
        
        # Install packages
        if install_packages "$pkg_manager" "$packages"; then
            print_success "System dependencies installed successfully using $pkg_manager"
        else
            print_warning "Failed to install packages using $pkg_manager, trying alternative methods..."
            install_dependencies_fallback
        fi
    else
        print_warning "Could not detect package manager, trying alternative methods..."
        install_dependencies_fallback
    fi
}

# Fallback installation methods
install_dependencies_fallback() {
    print_status "Attempting fallback installation methods..."
    
    # Method 1: Try to install Python from source if not available
    if ! command -v python3 &> /dev/null && ! command -v python &> /dev/null; then
        print_status "Python not found, attempting to install from source..."
        install_python_from_source
    fi
    
    # Method 2: Try to install pip if not available
    if ! command -v pip3 &> /dev/null && ! command -v pip &> /dev/null; then
        print_status "pip not found, attempting to install..."
        install_pip_from_source
    fi
    
    # Method 3: Try to install Rust if not available
    if ! command -v rustc &> /dev/null; then
        print_status "Rust not found, attempting to install..."
        install_rust_from_source
    fi
    
    # Method 4: Try to install build tools
    install_build_tools_fallback
    
    print_success "Fallback installation completed"
}

# Install Python from source
install_python_from_source() {
    print_status "Installing Python from source..."
    
    local python_version="3.11.7"
    local python_url="https://www.python.org/ftp/python/${python_version}/Python-${python_version}.tgz"
    local temp_dir=$(mktemp -d)
    
    cd "$temp_dir"
    
    # Download and extract Python
    curl -L "$python_url" -o "python-${python_version}.tgz"
    tar -xzf "python-${python_version}.tgz"
    cd "Python-${python_version}"
    
    # Configure and build
    ./configure --prefix=/usr/local --enable-optimizations
    make -j$(nproc)
    make altinstall
    
    # Create symlinks
    ln -sf /usr/local/bin/python3.11 /usr/local/bin/python3
    ln -sf /usr/local/bin/python3.11 /usr/local/bin/python
    
    cd /
    rm -rf "$temp_dir"
    
    print_success "Python installed from source"
}

# Install pip from source
install_pip_from_source() {
    print_status "Installing pip from source..."
    
    local temp_dir=$(mktemp -d)
    cd "$temp_dir"
    
    # Download get-pip.py
    curl -L https://bootstrap.pypa.io/get-pip.py -o get-pip.py
    
    # Install pip
    python3 get-pip.py --force-reinstall
    
    cd /
    rm -rf "$temp_dir"
    
    print_success "pip installed from source"
}

# Install Rust from source
install_rust_from_source() {
    print_status "Installing Rust from source..."
    
    # Download and run rustup installer
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    
    # Source the environment
    source ~/.cargo/env
    
    print_success "Rust installed from source"
}

# Install build tools fallback
install_build_tools_fallback() {
    print_status "Installing build tools..."
    
    # Try to install common build tools
    local build_tools=("gcc" "make" "pkg-config" "curl")
    
    for tool in "${build_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            print_warning "$tool not found, you may need to install it manually"
        fi
    done
    
    # Try to install pulseaudio development libraries
    if ! pkg-config --exists libpulse; then
        print_warning "PulseAudio development libraries not found"
        print_status "You may need to install them manually for audio monitoring features"
    fi
}

# Function to install Python dependencies
install_python_deps() {
    print_status "Installing Python dependencies..."
    
    # Check if we're in an externally managed environment
    local externally_managed=false
    
    # Method 1: Check for externally-managed module
    if python3 -c "import sys; print('externally-managed' in sys.modules)" 2>/dev/null | grep -q "True"; then
        externally_managed=true
    fi
    
    # Method 2: Check for PEP 668 marker
    if [[ -f "/usr/lib/python*/EXTERNALLY-MANAGED" ]] || [[ -f "/usr/local/lib/python*/EXTERNALLY-MANAGED" ]]; then
        externally_managed=true
    fi
    
    # Method 3: Try pip install and check for externally managed error
    if pip3 install --dry-run joblib 2>&1 | grep -q "externally-managed"; then
        externally_managed=true
    fi
    
    if [[ "$externally_managed" == true ]]; then
        print_status "Detected externally managed Python environment"
        install_python_deps_externally_managed
    else
        print_status "Using standard pip installation"
        install_python_deps_standard
    fi
}

# Install Python dependencies in externally managed environment
install_python_deps_externally_managed() {
    local pkg_manager_info=$(detect_package_manager)
    local pkg_manager="${pkg_manager_info%%:*}"
    
    case $pkg_manager in
        "pacman")
            print_status "Installing Python packages via pacman..."
            pacman -S --noconfirm python-joblib python-numpy python-scikit-learn
            ;;
        "apt-get"|"apt")
            print_status "Installing Python packages via apt..."
            apt-get install -y python3-joblib python3-numpy python3-sklearn
            ;;
        "dnf")
            print_status "Installing Python packages via dnf..."
            dnf install -y python3-joblib python3-numpy python3-scikit-learn
            ;;
        "yum")
            print_status "Installing Python packages via yum..."
            yum install -y python3-joblib python3-numpy python3-scikit-learn
            ;;
        "zypper")
            print_status "Installing Python packages via zypper..."
            zypper install -y python3-joblib python3-numpy python3-scikit-learn
            ;;
        *)
            print_warning "Unknown package manager, trying virtual environment..."
            install_python_deps_virtual_env
            ;;
    esac
    
    # Verify installation
    if python3 -c "import joblib, numpy, sklearn; print('✅ All ML dependencies available')" 2>/dev/null; then
        print_success "Python dependencies installed via system packages"
    else
        print_warning "System packages not available, trying virtual environment..."
        install_python_deps_virtual_env
    fi
}

# Install Python dependencies using standard pip
install_python_deps_standard() {
    pip3 install --upgrade pip
    pip3 install joblib numpy scikit-learn
    
    print_success "Python dependencies installed via pip"
}

# Install Python dependencies using virtual environment
install_python_deps_virtual_env() {
    print_status "Creating virtual environment for Python dependencies..."
    
    # Create virtual environment in install directory
    local venv_path="$INSTALL_DIR/venv"
    
    # Create virtual environment
    python3 -m venv "$venv_path"
    
    # Activate virtual environment and install packages
    source "$venv_path/bin/activate"
    pip install --upgrade pip
    pip install joblib numpy scikit-learn
    
    # Create activation script for the service
    cat > "$INSTALL_DIR/activate_venv.sh" << 'EOF'
#!/bin/bash
# Virtual environment activation script for CluelyGuard
source /opt/cluelyguard/venv/bin/activate
EOF
    
    chmod +x "$INSTALL_DIR/activate_venv.sh"
    
    # Update service file to use virtual environment
    if [[ -f "cluelyguard.service" ]]; then
        sed -i 's|ExecStart=/usr/local/bin/cluelyguard-daemon|ExecStart=/opt/cluelyguard/activate_venv.sh && /usr/local/bin/cluelyguard-daemon|' cluelyguard.service
    fi
    
    print_success "Python dependencies installed in virtual environment: $venv_path"
    print_status "Virtual environment will be used by the CluelyGuard service"
}

# Function to create user and directories


# Function to build and install CluelyGuard
build_and_install() {
    print_status "Building CluelyGuard..."
    
    # Build the project
    cargo build --release
    
    # Install binaries
    cp target/release/cluelyguard /usr/local/bin/
    cp target/release/cluelyguard-daemon /usr/local/bin/
    chmod +x /usr/local/bin/cluelyguard
    chmod +x /usr/local/bin/cluelyguard-daemon
    
    # Copy configuration
    cp config/default.yaml "$CONFIG_DIR/local.yaml"
    
    # Copy Python BAM module
    cp -r bam "$INSTALL_DIR/"
    
    print_success "CluelyGuard built and installed"
}

# Function to setup systemd service
setup_service() {
    print_status "Setting up systemd service..."
    
    cp cluelyguard.service /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable cluelyguard.service
    
    print_success "Systemd service configured"
}

# Function to initialize database


# Function to setup monitoring (optional)
setup_monitoring() {
    if [[ "$1" == "--with-monitoring" ]]; then
        print_status "Setting up monitoring stack..."
        
        # Create monitoring directory
        mkdir -p "$INSTALL_DIR/monitoring"
        
        # Copy monitoring configuration files
        if [[ -d "monitoring" ]]; then
            cp -r monitoring/* "$INSTALL_DIR/monitoring/"
        fi
        
        print_success "Monitoring stack configured"
    fi
}

# Function to display installation summary
show_summary() {
    echo
    print_success "CluelyGuard installation completed!"
    echo
    echo "Installation Summary:"
    echo "====================="
    echo "Version: $CLUELYGUARD_VERSION"
    echo "Install Directory: $INSTALL_DIR"
    echo "Configuration: $CONFIG_DIR"
    echo "Data Directory: $DATA_DIR"
    echo "Log Directory: $LOG_DIR"
    echo
    echo "Next Steps:"
    echo "==========="
    echo "1. Configure CluelyGuard:"
    echo "   sudo nano $CONFIG_DIR/local.yaml"
    echo
    echo "2. Start the service:"
    echo "   sudo systemctl start cluelyguard"
    echo
    echo "3. Check status:"
    echo "   sudo systemctl status cluelyguard"
    echo
    echo "4. View logs:"
    echo "   sudo journalctl -u cluelyguard -f"
    echo
    echo "5. Test the CLI:"
    echo "   cluelyguard status"
    echo
    echo "6. Access the API:"
    echo "   curl http://localhost:8080/health"
    echo
    echo "Documentation: https://github.com/yourusername/cluelyguard"
    echo
}

# Function to cleanup on error
cleanup() {
    print_error "Installation failed. Cleaning up..."
    
    # Remove created directories
    rm -rf "$INSTALL_DIR" "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"
    
    # Remove service file
    rm -f /etc/systemd/system/cluelyguard.service
    
    print_error "Cleanup completed"
}

# Main installation function
main() {
    echo "CluelyGuard Installation Script"
    echo "==============================="
    echo
    
    # Check if running as root
    check_root
    
    # Detect OS
    detect_os
    print_status "Detected OS: $OS $VER"
    
    # Set up error handling
    trap cleanup ERR
    
    # Install dependencies
    install_dependencies
    
    # Install Python dependencies
    install_python_deps
    
    # Build and install
    build_and_install
    
    # Setup service
    setup_service
    
    # Setup monitoring if requested
    setup_monitoring "$1"
    
    # Show summary
    show_summary
    
    # Remove error handler
    trap - ERR
}

# Check command line arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [OPTIONS]"
        echo
        echo "Options:"
        echo "  --with-monitoring    Install with monitoring stack (Prometheus/Grafana)"
        echo "  --help, -h          Show this help message"
        echo
        exit 0
        ;;
    --with-monitoring)
        main "$1"
        ;;
    "")
        main
        ;;
    *)
        print_error "Unknown option: $1"
        echo "Use --help for usage information"
        exit 1
        ;;
esac 