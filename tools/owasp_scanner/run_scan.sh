#!/bin/bash

# OWASP Scanner Wrapper Script with enhanced error handling and usability
# ----------------------------------------------------------------------

# Default values
URL_FILE="sample_domains.txt"
OUTPUT="owasp_scan_results.xlsx"
ZAP_PORT=8080
API_KEY="api-key-for-owasp"
MAX_WORKERS=3
SCAN_TIMEOUT=60
LOG_LEVEL="INFO"
SIMULATION_MODE=false
RESUME=false
BATCH_SIZE=3

# Text formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Display banner
echo -e "${BLUE}${BOLD}"
echo "====================================================="
echo "    OWASP Top 10 Vulnerability Scanner"
echo "====================================================="
echo -e "${NC}"

# Function to display usage instructions
function show_usage {
    echo -e "${YELLOW}Usage:${NC} $0 [options]"
    echo
    echo "Options:"
    echo "  -f, --url-file FILE    File containing URLs to scan (default: sample_domains.txt)"
    echo "  -u, --url URL          Single URL to scan (instead of URL file)"
    echo "  -o, --output FILE      Output file path (default: owasp_scan_results.xlsx)"
    echo "  -z, --zap-path PATH    Path to ZAP executable"
    echo "  -p, --port PORT        ZAP API port (default: 8080)"
    echo "  -k, --api-key KEY      ZAP API key (default: api-key-for-owasp)"
    echo "  -w, --workers NUM      Maximum concurrent workers (default: 3)"
    echo "  -t, --timeout MINS     Scan timeout in minutes per URL (default: 60)"
    echo "  -l, --log-level LEVEL  Log level: DEBUG, INFO, WARNING, ERROR (default: INFO)"
    echo "  -b, --batch-size SIZE  Number of URLs to scan in each batch (default: 3)"
    echo "  -s, --simulation       Run in simulation mode (no actual scanning)"
    echo "  -r, --resume           Resume from last saved state"
    echo "  -h, --help             Show this help message"
    echo
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        -f|--url-file)
            URL_FILE="$2"
            shift 2
            ;;
        -u|--url)
            SINGLE_URL="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT="$2"
            shift 2
            ;;
        -z|--zap-path)
            ZAP_PATH="$2"
            shift 2
            ;;
        -p|--port)
            ZAP_PORT="$2"
            shift 2
            ;;
        -k|--api-key)
            API_KEY="$2"
            shift 2
            ;;
        -w|--workers)
            MAX_WORKERS="$2"
            shift 2
            ;;
        -t|--timeout)
            SCAN_TIMEOUT="$2"
            shift 2
            ;;
        -l|--log-level)
            LOG_LEVEL="$2"
            shift 2
            ;;
        -b|--batch-size)
            BATCH_SIZE="$2"
            shift 2
            ;;
        -s|--simulation)
            SIMULATION_MODE=true
            shift
            ;;
        -r|--resume)
            RESUME=true
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            echo -e "${RED}Error: Unknown option '$1'${NC}"
            show_usage
            exit 1
            ;;
    esac
done

# Check if Python virtual environment exists and activate it
VENV_DIR="venv"
if [ -d "$VENV_DIR" ] && [ -f "$VENV_DIR/bin/activate" ]; then
    echo -e "${YELLOW}Activating Python virtual environment...${NC}"
    source "$VENV_DIR/bin/activate"
else
    echo -e "${YELLOW}Creating new Python virtual environment...${NC}"
    python3 -m venv "$VENV_DIR"
    source "$VENV_DIR/bin/activate"
    
    echo -e "${YELLOW}Installing required packages...${NC}"
    pip install -q --upgrade pip
    pip install -q -r requirements.txt
fi

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 not found. Please install Python 3.${NC}"
    exit 1
fi

# Check if OWASP scanner script exists
if [ ! -f "owasp_scanner.py" ]; then
    echo -e "${RED}Error: owasp_scanner.py not found in the current directory.${NC}"
    exit 1
fi

# Make the scanner script executable
chmod +x owasp_scanner.py

# Auto-detect ZAP location if not provided
if [ -z "$ZAP_PATH" ]; then
    echo -e "${YELLOW}ZAP path not provided, attempting to auto-detect...${NC}"
    
    # Check common locations for ZAP
    POSSIBLE_LOCATIONS=(
        "/Applications/ZAP.app/Contents/Java/zap.sh"  # macOS
        "/usr/share/zaproxy/zap.sh"                  # Linux package
        "/opt/zaproxy/zap.sh"                        # Linux custom install
        "/snap/zaproxy/current/zap.sh"               # Linux snap
    )
    
    for loc in "${POSSIBLE_LOCATIONS[@]}"; do
        if [ -f "$loc" ]; then
            ZAP_PATH="$loc"
            echo -e "${GREEN}Found ZAP at: $ZAP_PATH${NC}"
            break
        fi
    done
    
    # If not found in common locations, try using 'which'
    if [ -z "$ZAP_PATH" ]; then
        ZAP_PATH=$(which zap.sh 2>/dev/null)
        if [ -n "$ZAP_PATH" ]; then
            echo -e "${GREEN}Found ZAP in PATH: $ZAP_PATH${NC}"
        fi
    fi
    
    # If still not found and not in simulation mode, show error
    if [ -z "$ZAP_PATH" ] && [ "$SIMULATION_MODE" = false ]; then
        echo -e "${YELLOW}Warning: ZAP not found. Please install OWASP ZAP or provide path with --zap-path${NC}"
        echo -e "${YELLOW}Installing instructions for macOS:${NC}"
        echo "  1. Download from: https://www.zaproxy.org/download/"
        echo "  2. Move to Applications folder"
        echo "  3. Run this script with: --zap-path \"/Applications/ZAP.app/Contents/Java/zap.sh\""
        echo -e "${YELLOW}Or run with --simulation flag to use simulation mode${NC}"
        
        read -p "Continue in simulation mode? (y/n): " answer
        if [[ "$answer" =~ ^[Yy]$ ]]; then
            SIMULATION_MODE=true
            echo -e "${YELLOW}Continuing in simulation mode...${NC}"
        else
            exit 1
        fi
    fi
fi

# Check if ZAP is running
if [ "$SIMULATION_MODE" = false ]; then
    echo -e "${YELLOW}Checking if ZAP is running...${NC}"
    if curl -s -o /dev/null http://localhost:$ZAP_PORT; then
        echo -e "${GREEN}ZAP appears to be running on port $ZAP_PORT${NC}"
        ZAP_RUNNING=true
    else
        echo -e "${YELLOW}ZAP is not running on port $ZAP_PORT${NC}"
        ZAP_RUNNING=false
        
        if [ -n "$ZAP_PATH" ]; then
            echo -e "${YELLOW}Starting ZAP in daemon mode...${NC}"
            "$ZAP_PATH" -daemon -config api.key="$API_KEY" -port "$ZAP_PORT" &
            ZAP_PID=$!
            echo -e "${YELLOW}Waiting for ZAP to start (PID: $ZAP_PID)...${NC}"
            sleep 10  # Give ZAP time to start
        else
            echo -e "${YELLOW}Cannot start ZAP (path not found) - add --simulation flag to run without ZAP${NC}"
            if [ "$SIMULATION_MODE" = false ]; then
                exit 1
            fi
        fi
    fi
fi

# Build the command
CMD="./owasp_scanner.py"

# Add URL or URL file
if [ -n "$SINGLE_URL" ]; then
    CMD="$CMD --url '$SINGLE_URL'"
else
    if [ ! -f "$URL_FILE" ]; then
        echo -e "${RED}Error: URL file '$URL_FILE' not found${NC}"
        exit 1
    fi
    CMD="$CMD --url-file '$URL_FILE'"
fi

# Add other parameters
CMD="$CMD --output '$OUTPUT'"
CMD="$CMD --log-level $LOG_LEVEL"
CMD="$CMD --max-workers $MAX_WORKERS"
CMD="$CMD --scan-timeout $SCAN_TIMEOUT"
CMD="$CMD --batch-size $BATCH_SIZE"

if [ -n "$ZAP_PATH" ]; then
    CMD="$CMD --zap-path '$ZAP_PATH'"
fi

CMD="$CMD --zap-port $ZAP_PORT"
CMD="$CMD --api-key '$API_KEY'"

if [ "$SIMULATION_MODE" = true ]; then
    CMD="$CMD --simulation-mode"
fi

if [ "$RESUME" = true ]; then
    CMD="$CMD --resume"
fi

if [ "$ZAP_RUNNING" = true ]; then
    CMD="$CMD --start-zap"
fi

# Execute the scanner
echo -e "${GREEN}${BOLD}Starting OWASP Top 10 scan...${NC}"
echo -e "${BLUE}Command: $CMD${NC}"
echo -e "${YELLOW}----------------------------------------${NC}"

eval $CMD
EXIT_CODE=$?

# Check if script execution was successful
if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}${BOLD}Scan completed successfully!${NC}"
    echo -e "${GREEN}Results saved to: $OUTPUT${NC}"
else
    echo -e "${RED}${BOLD}Scan failed with exit code $EXIT_CODE${NC}"
fi

# Deactivate virtual environment
deactivate

exit $EXIT_CODE 