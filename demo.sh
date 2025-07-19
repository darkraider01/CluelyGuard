#!/bin/bash

# CluelyGuard Demo Script
# Shows how the system works in action

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored output
print_header() {
    echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${PURPLE}║                    CLUELYGUARD DEMO                          ║${NC}"
    echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo
}

print_step() {
    echo -e "${BLUE}🔹 Step $1:${NC} $2"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${CYAN}ℹ️  $1${NC}"
}

# Function to show monitoring in action
show_monitoring() {
    echo -e "${BLUE}🔍 CluelyGuard Monitoring Dashboard${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    
    for i in {1..5}; do
        echo -e "${YELLOW}[$(date '+%H:%M:%S')]${NC} Monitoring cycle $i..."
        
        # Simulate different detection scenarios
        case $i in
            1)
                echo -e "  ${GREEN}✅ Process Monitor: No suspicious processes detected${NC}"
                echo -e "  ${GREEN}✅ Network Monitor: No suspicious DNS queries${NC}"
                echo -e "  ${GREEN}✅ File System Monitor: No unusual activity${NC}"
                echo -e "  ${GREEN}✅ Syscall Monitor: No suspicious syscalls${NC}"
                echo -e "  ${GREEN}✅ User Activity Monitor: No unusual user behavior${NC}"
                echo -e "  ${GREEN}✅ Screensharing Monitor: No screensharing detected${NC}"
                echo -e "  ${GREEN}✅ Output Analysis: No LLM output detected${NC}"
                ;;
            2)
                echo -e "  ${YELLOW}⚠️  Process Monitor: Suspicious memory pattern detected!${NC}"
                echo -e "  ${GREEN}✅ Network Monitor: No suspicious DNS queries${NC}"
                echo -e "  ${GREEN}✅ File System Monitor: No unusual activity${NC}"
                echo -e "  ${GREEN}✅ Syscall Monitor: No suspicious syscalls${NC}"
                echo -e "  ${GREEN}✅ User Activity Monitor: No unusual user behavior${NC}"
                echo -e "  ${GREEN}✅ Screensharing Monitor: No screensharing detected${NC}"
                echo -e "  ${GREEN}✅ Output Analysis: No LLM output detected${NC}"
                ;;
            3)
                echo -e "  ${RED}🚨 Process Monitor: ChatGPT detected running!${NC}"
                echo -e "  ${RED}🚨 Network Monitor: DNS query to openai.com detected!${NC}"
                echo -e "  ${YELLOW}⚠️  File System Monitor: Unusual file access detected!${NC}"
                echo -e "  ${GREEN}✅ Syscall Monitor: No suspicious syscalls${NC}"
                echo -e "  ${GREEN}✅ User Activity Monitor: No unusual user behavior${NC}"
                echo -e "  ${GREEN}✅ Screensharing Monitor: No screensharing detected${NC}"
                echo -e "  ${RED}🚨 Output Analysis: LLM-generated text detected!${NC}"
                echo -e "  ${RED}🚨 ALERT: Multiple suspicious activities detected!${NC}"
                ;;
            4)
                echo -e "  ${GREEN}✅ Process Monitor: No suspicious processes detected${NC}"
                echo -e "  ${GREEN}✅ Network Monitor: No suspicious DNS queries${NC}"
                echo -e "  ${GREEN}✅ File System Monitor: No unusual activity${NC}"
                echo -e "  ${YELLOW}⚠️  Syscall Monitor: Unusual syscall pattern detected!${NC}"
                echo -e "  ${RED}🚨 User Activity Monitor: Suspicious command detected!${NC}"
                echo -e "  ${RED}🚨 Screensharing Monitor: Zoom detected!${NC}"
                echo -e "  ${GREEN}✅ Output Analysis: No LLM output detected${NC}"
                echo -e "  ${YELLOW}⚠️  ALERT: Suspicious user activity and screensharing!${NC}"
                ;;
            5)
                echo -e "  ${GREEN}✅ Process Monitor: No suspicious processes detected${NC}"
                echo -e "  ${GREEN}✅ Network Monitor: No suspicious DNS queries${NC}"
                echo -e "  ${GREEN}✅ File System Monitor: No unusual activity${NC}"
                echo -e "  ${GREEN}✅ Syscall Monitor: No suspicious syscalls${NC}"
                echo -e "  ${GREEN}✅ User Activity Monitor: No unusual user behavior${NC}"
                echo -e "  ${GREEN}✅ Screensharing Monitor: No screensharing detected${NC}"
                echo -e "  ${GREEN}✅ Output Analysis: No LLM output detected${NC}"
                ;;
        esac
        
        echo
        sleep 2
    done
}

# Function to show final report
show_report() {
    echo -e "${BLUE}📊 CluelyGuard Session Report${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo
    echo -e "${YELLOW}Session Details:${NC}"
    echo -e "  Session ID: demo-session-$(date +%s)"
    echo -e "  Description: Demo Exam Session"
    echo -e "  User ID: demo-student"
    echo -e "  Duration: 2 minutes 30 seconds"
    echo -e "  Started: $(date -d '2 minutes ago' '+%Y-%m-%d %H:%M:%S')"
    echo -e "  Ended: $(date '+%Y-%m-%d %H:%M:%S')"
    echo
    echo -e "${YELLOW}Detection Results:${NC}"
    echo -e "  Total Scans: 5 completed"
    echo -e "  Suspicious Activities Detected: 7"
    echo
    echo -e "${YELLOW}Suspicious Activities Timeline:${NC}"
    echo -e "  🚨 14:32:15 - ChatGPT process detected running"
    echo -e "  🚨 14:32:18 - DNS query to openai.com detected"
    echo -e "  ⚠️  14:33:05 - Unusual file access detected"
    echo -e "  🚨 14:33:10 - LLM-generated text detected"
    echo -e "  ⚠️  14:34:01 - Unusual syscall pattern detected"
    echo -e "  🚨 14:34:15 - Suspicious command detected"
    echo -e "  🚨 14:34:20 - Screensharing application detected"
    echo
    echo -e "${YELLOW}Recommendations:${NC}"
    echo -e "  🔍 Review this session carefully"
    echo -e "  📝 Multiple high-risk activities detected"
    echo -e "  ⚠️  Consider interviewing the student immediately"
    echo -e "  📊 Overall risk level: HIGH"
    echo
}

# Main demo function
run_demo() {
    print_header
    
    print_step "1" "Setting up CluelyGuard demo environment"
    print_info "This demo will show how CluelyGuard detects AI cheating in real-time"
    echo
    
    print_step "2" "Starting monitoring session"
    print_info "CluelyGuard is now monitoring for suspicious activities..."
    echo
    
    print_step "3" "Showing real-time monitoring dashboard"
    show_monitoring
    print_success "Monitoring demonstration completed"
    echo
    
    print_step "4" "Generating final report"
    show_report
    print_success "Demo completed successfully!"
    echo
    
    echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${PURPLE}║                    DEMO COMPLETED                            ║${NC}"
    echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "${CYAN}What you just saw:${NC}"
    echo -e "  • Real-time monitoring of processes, network, file system, syscalls, user activity, and screensharing"
    echo -e "  • Detection of LLM-generated output"
    echo -e "  • Comprehensive session reporting"
    echo
    echo -e "${CYAN}Next steps:${NC}"
    echo -e "  • Install CluelyGuard: sudo ./install.sh"
    echo -e "  • Read the user guide: cat USER_GUIDE.md"
    echo -e "  • Learn more: cat HOW_IT_WORKS.md"
    echo
}

# Run the demo
run_demo 