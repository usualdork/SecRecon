#!/bin/bash

# Modified OWASP Vulnerability Scanner
# This script skips problematic domains that cause ZAP to hang

set -e

# Default values
URL_FILE="filtered_domains.txt"
OUTPUT_DIR="indepth_scan_results_$(date +%Y%m%d_%H%M%S)"
TIMEOUT=15
API_KEY="api-key-for-owasp"
PROBLEMATIC_DOMAINS="info.coindcx.com"  # Add more domains here separated by |

# Function to display help
function show_help {
    echo "Modified OWASP Vulnerability Scanner with Skip Functionality"
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -f, --file FILE         Input file containing URLs to scan (default: filtered_domains.txt)"
    echo "  -o, --output DIR        Output directory for scan results (default: auto-generated)"
    echo "  -t, --timeout MINUTES   Timeout in minutes for each URL scan (default: 15)"
    echo "  -k, --api-key KEY       API key for ZAP (default: api-key-for-owasp)"
    echo "  -p, --problematic REGEX Regex pattern for problematic domains to skip"
    echo "  -h, --help              Show this help message"
    exit 0
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -f|--file)
            URL_FILE="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -t|--timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        -k|--api-key)
            API_KEY="$2"
            shift 2
            ;;
        -p|--problematic)
            PROBLEMATIC_DOMAINS="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            ;;
    esac
done

# Check if URL file exists
if [ ! -f "$URL_FILE" ]; then
    echo "Error: URL file $URL_FILE does not exist"
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"
echo "Created output directory: $OUTPUT_DIR"

# Create filtered list of domains (excluding problematic ones)
FILTERED_FILE="$OUTPUT_DIR/filtered_urls.txt"
grep -v -E "($PROBLEMATIC_DOMAINS)" "$URL_FILE" > "$FILTERED_FILE"

# Count domains
TOTAL_DOMAINS=$(wc -l < "$URL_FILE")
FILTERED_DOMAINS=$(wc -l < "$FILTERED_FILE")
SKIPPED_DOMAINS=$((TOTAL_DOMAINS - FILTERED_DOMAINS))

echo "Total domains: $TOTAL_DOMAINS"
echo "Domains to scan: $FILTERED_DOMAINS"
echo "Domains to skip: $SKIPPED_DOMAINS"

# Create a list of skipped domains for reference
SKIPPED_FILE="$OUTPUT_DIR/skipped_domains.txt"
grep -E "($PROBLEMATIC_DOMAINS)" "$URL_FILE" > "$SKIPPED_FILE"
echo "Skipped domains saved to: $SKIPPED_FILE"

# Activate virtual environment
if [ -d "venv" ]; then
    echo "Activating Python virtual environment..."
    source venv/bin/activate
else
    echo "Creating Python virtual environment..."
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
fi

# Function to clean up ZAP processes and state
function cleanup_zap {
    echo "Cleaning up ZAP processes and state..."
    pkill -f zap || true
    pkill -f owasp_scanner.py || true
    rm -f owasp_scan_state.json || true
    rm -rf "$HOME/Library/Application Support/ZAP/.ZAP_JVM_LOCK" || true
    sleep 5
}

# Initial cleanup
cleanup_zap

# Start ZAP
echo "Starting ZAP..."
/Applications/ZAP.app/Contents/Java/zap.sh -daemon -config api.key="$API_KEY" -port 8080 &
sleep 15
echo "ZAP started"

# Run the automated scan with the filtered list
echo "Starting automated scan..."
./run_automated_scan.sh --file "$FILTERED_FILE" --batch-size 2 --timeout "$TIMEOUT" --parallel 1 --output "$OUTPUT_DIR" --api-key "$API_KEY"

# Merge reports
echo "Merging reports..."
MERGED_REPORT="$OUTPUT_DIR/merged_report.xlsx"
./merge_reports.py "$OUTPUT_DIR" "$MERGED_REPORT"

# Final cleanup
cleanup_zap

echo "In-depth scan completed successfully!"
echo "Results saved to: $OUTPUT_DIR"
echo "Merged report: $MERGED_REPORT"
echo "NOTE: $SKIPPED_DOMAINS problematic domains were skipped. See $SKIPPED_FILE for details." 