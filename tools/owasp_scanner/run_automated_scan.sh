#!/bin/bash

# Automated OWASP Scanning Script
# This script automates the process of fetching URLs and splitting them into batches for scanning

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
echo "    AUTOMATED OWASP Top 10 Vulnerability Scanner"
echo "====================================================="
echo -e "${NC}"

# Default settings
BATCH_SIZE=3
TIMEOUT=15
WORKERS=1
OUTPUT_DIR="reports/$(date +%Y%m%d_%H%M%S)"
API_KEY="api-key-for-owasp"
BY_DOMAIN=false
BEAUTIFY_REPORTS=true

# Function to display usage instructions
function show_usage {
    echo -e "${YELLOW}Usage:${NC} $0 [options]"
    echo
    echo "Options:"
    echo "  -f, --file FILE        Path to file containing URLs (txt, csv, json)"
    echo "  -w, --web URL          Web page URL to extract links from"
    echo "  -a, --api URL          API endpoint to fetch URLs from"
    echo "  -k, --api-key KEY      API key for authentication (for web APIs)"
    echo "  -z, --zap-key KEY      ZAP API key (default: api-key-for-owasp)"
    echo "  -b, --batch-size SIZE  Number of URLs per batch (default: 3)"
    echo "  -t, --timeout MINS     Scan timeout in minutes per URL (default: 15)"
    echo "  -p, --parallel NUM     Maximum concurrent workers (default: 1)"
    echo "  -o, --output DIR       Output directory for reports (default: reports/timestamp)"
    echo "  -d, --by-domain        Group URLs by domain in batches"
    echo "  -n, --no-beautify      Don't beautify generated reports"
    echo "  -h, --help             Show this help message"
    echo
    echo "Examples:"
    echo "  $0 --file domains.txt --batch-size 5 --timeout 20"
    echo "  $0 --web https://example.com --by-domain"
    echo "  $0 --api https://api.example.com/domains --api-key YOUR_KEY"
    echo
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        -f|--file)
            FILE="$2"
            shift 2
            ;;
        -w|--web)
            WEB_URL="$2"
            shift 2
            ;;
        -a|--api)
            API_URL="$2"
            shift 2
            ;;
        -k|--api-key)
            SOURCE_API_KEY="$2"
            shift 2
            ;;
        -z|--zap-key)
            API_KEY="$2"
            shift 2
            ;;
        -b|--batch-size)
            BATCH_SIZE="$2"
            shift 2
            ;;
        -t|--timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        -p|--parallel)
            WORKERS="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -d|--by-domain)
            BY_DOMAIN=true
            shift
            ;;
        -n|--no-beautify)
            BEAUTIFY_REPORTS=false
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

# Check if at least one source is provided
if [ -z "$FILE" ] && [ -z "$WEB_URL" ] && [ -z "$API_URL" ]; then
    echo -e "${RED}Error: You must specify a URL source using --file, --web, or --api${NC}"
    show_usage
    exit 1
fi

# Check for Python and required files
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 is required but not found${NC}"
    exit 1
fi

if [ ! -f "url_fetcher.py" ]; then
    echo -e "${RED}Error: url_fetcher.py not found in the current directory${NC}"
    exit 1
fi

if [ ! -f "run_scan.sh" ]; then
    echo -e "${RED}Error: run_scan.sh not found in the current directory${NC}"
    exit 1
fi

# Make scripts executable
chmod +x url_fetcher.py run_scan.sh

# Build fetcher command
CMD="python3 url_fetcher.py"

# Add source
if [ -n "$FILE" ]; then
    CMD="$CMD --file '$FILE'"
    
    # Detect file format based on extension
    if [[ "$FILE" == *.csv ]]; then
        CMD="$CMD --file-format csv"
    elif [[ "$FILE" == *.json ]]; then
        CMD="$CMD --file-format json"
    fi
elif [ -n "$WEB_URL" ]; then
    CMD="$CMD --web '$WEB_URL'"
elif [ -n "$API_URL" ]; then
    CMD="$CMD --api '$API_URL'"
    if [ -n "$SOURCE_API_KEY" ]; then
        CMD="$CMD --api-key '$SOURCE_API_KEY'"
    fi
fi

# Add other parameters
CMD="$CMD --batch-size $BATCH_SIZE"
CMD="$CMD --output-dir batches"
CMD="$CMD --scan-output-dir '$OUTPUT_DIR'"
CMD="$CMD --workers $WORKERS"
CMD="$CMD --timeout $TIMEOUT"
CMD="$CMD --scan-api-key '$API_KEY'"
CMD="$CMD --run-scans"

if [ "$BY_DOMAIN" = true ]; then
    CMD="$CMD --by-domain"
fi

# Create report directory
mkdir -p "$OUTPUT_DIR"

# Execute the fetcher
echo -e "${GREEN}${BOLD}Starting URL fetching and batched scanning...${NC}"
echo -e "${BLUE}Command: $CMD${NC}"
echo -e "${YELLOW}----------------------------------------${NC}"

eval $CMD
EXIT_CODE=$?

# Check if script execution was successful
if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}${BOLD}Automated scanning completed successfully!${NC}"
    echo -e "${GREEN}Results saved to: $OUTPUT_DIR${NC}"
    
    # Generate combined report if multiple batch files exist
    REPORT_COUNT=$(find "$OUTPUT_DIR" -name "*.xlsx" | wc -l)
    if [ $REPORT_COUNT -gt 1 ]; then
        echo -e "${YELLOW}Multiple reports generated. Merging them for a unified view.${NC}"
        
        # Merge reports
        MERGED_REPORT="$OUTPUT_DIR/merged_report.xlsx"
        python3 merge_reports.py "$OUTPUT_DIR" "$MERGED_REPORT"
        echo -e "${GREEN}Merged report generated at: $MERGED_REPORT${NC}"
        
        # Beautify the merged report if requested
        if [ "$BEAUTIFY_REPORTS" = true ]; then
            echo -e "${YELLOW}Beautifying the merged report...${NC}"
            python3 owasp_scanner_production/enhanced_report_generator.py "$MERGED_REPORT"
            echo -e "${GREEN}Enhanced report saved as: ${MERGED_REPORT%.*}_enhanced.xlsx${NC}"
        fi
    fi
else
    echo -e "${RED}${BOLD}Automated scanning failed with exit code $EXIT_CODE${NC}"
fi

exit $EXIT_CODE 