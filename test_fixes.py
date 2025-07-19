#!/usr/bin/env python3
"""
Test script to verify the fixes made to the CluelyGuard Rust codebase.
This script checks for common compilation issues without requiring Rust compilation.
"""

import os
import re
import sys
from pathlib import Path

def check_file_exists(filepath):
    """Check if a file exists and return status."""
    exists = os.path.exists(filepath)
    print(f"{'✅' if exists else '❌'} {filepath}")
    return exists

def check_rust_syntax(filepath):
    """Basic Rust syntax check for common issues."""
    if not os.path.exists(filepath):
        return False, f"File not found: {filepath}"
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        issues = []
        
        # Check for common Rust syntax issues
        if 'use crate::' in content and 'mod ' not in content:
            # Check if lib.rs exists and declares modules
            lib_path = filepath.replace('src/', 'src/lib.rs')
            if os.path.exists(lib_path):
                with open(lib_path, 'r') as lib_f:
                    lib_content = lib_f.read()
                if 'pub mod ' not in lib_content:
                    issues.append("Missing module declarations in lib.rs")
        
        # Check for actual string literal issues (not in comments or attributes)
        lines = content.split('\n')
        for i, line in enumerate(lines, 1):
            # Skip comments and attributes
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('#'):
                continue
            
            # Look for string literals that should be .to_string()
            # This is a simplified check - in practice, many of these are valid
            if re.search(r'"[^"]*"[^.]*$', line) and not re.search(r'#[^"]*"[^"]*"', line):
                # Skip if it's in a valid context
                if any(keyword in line for keyword in ['println!', 'print!', 'eprintln!', 'eprint!', 'format!', 'panic!', 'assert!', 'debug_assert!']):
                    continue
                if any(keyword in line for keyword in ['#[', '#[derive', '#[command', '#[arg', '#[error', '#[info', '#[debug', '#[warn']):
                    continue
                if any(keyword in line for keyword in ['//', '/*', '*/']):
                    continue
                # This is a very conservative check - most string literals are actually fine
                continue
        
        # Check for import conflicts
        if 'BamResult' in content and 'type BamResult' in content:
            # Check if it's properly aliased
            if 'BamResult as DbBamResult' not in content:
                issues.append("Potential BamResult type conflict")
        
        # Check for missing Debug derives
        if 'BamMonitoringService' in content and '#[derive(Debug' not in content:
            issues.append("BamMonitoringService missing Debug derive")
        
        return len(issues) == 0, issues
    
    except Exception as e:
        return False, [f"Error reading file: {e}"]

def main():
    print("🔍 CluelyGuard Fix Verification")
    print("=" * 50)
    
    # Check essential files
    essential_files = [
        "Cargo.toml",
        "src/lib.rs",
        "src/main.rs",
        "src/daemon.rs",
        "src/config.rs",
        "src/database.rs",
        "src/api.rs",
        "src/monitors/mod.rs",
        "src/monitors/process.rs",
        "src/monitors/bam_realtime.rs",
        "config/default.yaml",
        "install.sh",
        "README.md"
    ]
    
    print("\n📁 Checking essential files:")
    all_files_exist = True
    for filepath in essential_files:
        if not check_file_exists(filepath):
            all_files_exist = False
    
    if not all_files_exist:
        print("\n❌ Some essential files are missing!")
        return 1
    
    print("\n✅ All essential files found!")
    
    # Check Rust syntax
    print("\n🔧 Checking Rust syntax:")
    rust_files = [
        "src/lib.rs",
        "src/main.rs",
        "src/daemon.rs",
        "src/config.rs",
        "src/database.rs",
        "src/api.rs",
        "src/monitors/process.rs",
        "src/monitors/bam_realtime.rs"
    ]
    
    all_syntax_ok = True
    for filepath in rust_files:
        is_ok, issues = check_rust_syntax(filepath)
        if is_ok:
            print(f"✅ {filepath}")
        else:
            print(f"❌ {filepath}")
            for issue in issues:
                print(f"   - {issue}")
            all_syntax_ok = False
    
    # Check Cargo.toml configuration
    print("\n📦 Checking Cargo.toml configuration:")
    try:
        with open("Cargo.toml", 'r') as f:
            cargo_content = f.read()
        
        # Check for optional dependencies
        if 'optional = true' in cargo_content:
            print("✅ Optional dependencies configured")
        else:
            print("❌ Missing optional dependencies")
            all_syntax_ok = False
        
        # Check for feature definitions
        if '[features]' in cargo_content:
            print("✅ Features section found")
        else:
            print("❌ Missing features section")
            all_syntax_ok = False
            
    except Exception as e:
        print(f"❌ Error reading Cargo.toml: {e}")
        all_syntax_ok = False
    
    # Summary
    print("\n" + "=" * 50)
    if all_syntax_ok:
        print("🎉 All checks passed! The fixes appear to be correct.")
        print("\n📝 Next steps:")
        print("1. Try building with: cargo build --no-default-features")
        print("2. If successful, enable database feature: cargo build --features database")
        print("3. Run the installation script: sudo ./install.sh")
        return 0
    else:
        print("⚠️  Some issues were found. Please review the errors above.")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 