#!/bin/bash

# Comprehensive OWASP Vulnerability Scanner
# This script combines URL fetching, batch scanning, and report merging into a single workflow

set -e

# Default values
URL_FILE=""
OUTPUT_DIR="scan_results_$(date +%Y%m%d_%H%M%S)"
BATCH_SIZE=2
TIMEOUT=10
PARALLEL=1
API_KEY="api-key-for-owasp"
FETCH_URLS=false
FETCH_SOURCE=""
FETCH_PATTERN=""
CLEAN_START=false
MERGE_REPORTS=true
BEAUTIFY_REPORT=true

# Display help
function show_help {
    echo "Comprehensive OWASP Vulnerability Scanner"
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -f, --file FILE         Input file containing URLs to scan"
    echo "  -o, --output DIR        Output directory for scan results (default: auto-generated)"
    echo "  -b, --batch-size SIZE   Number of URLs to process in each batch (default: 2)"
    echo "  -t, --timeout MINUTES   Timeout in minutes for each URL scan (default: 10)"
    echo "  -p, --parallel NUM      Number of parallel scans to run (default: 1)"
    echo "  -k, --api-key KEY       API key for ZAP (default: api-key-for-owasp)"
    echo "  -u, --fetch-urls        Fetch URLs before scanning"
    echo "  -s, --source URL        Source URL for fetching (required with -u)"
    echo "  -r, --pattern REGEX     Regex pattern for URL extraction (required with -u)"
    echo "  -c, --clean             Clean start (kill existing ZAP processes and remove state files)"
    echo "  -n, --no-merge          Don't merge reports after scanning"
    echo "  -m, --no-beautify       Don't beautify the merged report"
    echo "  -h, --help              Show this help message"
    echo ""
    echo "Example:"
    echo "  $0 -f domains.txt -o scan_results -b 3 -t 15 -p 1 -k my-api-key"
    echo "  $0 -u -s https://example.com -r 'https://.*\\.example\\.com' -o scan_results -b 2"
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
        -b|--batch-size)
            BATCH_SIZE="$2"
            shift 2
            ;;
        -t|--timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        -p|--parallel)
            PARALLEL="$2"
            shift 2
            ;;
        -k|--api-key)
            API_KEY="$2"
            shift 2
            ;;
        -u|--fetch-urls)
            FETCH_URLS=true
            shift
            ;;
        -s|--source)
            FETCH_SOURCE="$2"
            shift 2
            ;;
        -r|--pattern)
            FETCH_PATTERN="$2"
            shift 2
            ;;
        -c|--clean)
            CLEAN_START=true
            shift
            ;;
        -n|--no-merge)
            MERGE_REPORTS=false
            shift
            ;;
        -m|--no-beautify)
            BEAUTIFY_REPORT=false
            shift
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

# Validate inputs
if [ "$FETCH_URLS" = true ]; then
    if [ -z "$FETCH_SOURCE" ] || [ -z "$FETCH_PATTERN" ]; then
        echo "Error: When using --fetch-urls, both --source and --pattern are required"
        exit 1
    fi
elif [ -z "$URL_FILE" ]; then
    echo "Error: Input file (-f) is required unless using --fetch-urls"
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"
echo "Created output directory: $OUTPUT_DIR"

# Clean start if requested
if [ "$CLEAN_START" = true ]; then
    echo "Performing clean start..."
    pkill -f zap || true
    pkill -f owasp_scanner.py || true
    rm -f owasp_scan_state.json || true
    echo "Removed existing processes and state files"
    sleep 2
fi

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

# Fetch URLs if requested
if [ "$FETCH_URLS" = true ]; then
    echo "Fetching URLs from $FETCH_SOURCE with pattern '$FETCH_PATTERN'..."
    TEMP_URL_FILE="$OUTPUT_DIR/fetched_urls.txt"
    python url_fetcher.py --url "$FETCH_SOURCE" --pattern "$FETCH_PATTERN" --output "$TEMP_URL_FILE"
    URL_FILE="$TEMP_URL_FILE"
    echo "URLs saved to $URL_FILE"
fi

# Count total URLs
TOTAL_URLS=$(wc -l < "$URL_FILE")
echo "Total URLs to scan: $TOTAL_URLS"

# Start ZAP if not already running
if ! curl -s http://localhost:8080/JSON/core/view/version/ > /dev/null; then
    echo "Starting ZAP..."
    /Applications/ZAP.app/Contents/Java/zap.sh -daemon -config api.key="$API_KEY" -port 8080 &
    sleep 15
    echo "ZAP started"
fi

# Run the automated scan
echo "Starting automated scan with batch size $BATCH_SIZE..."
./run_automated_scan.sh --file "$URL_FILE" --batch-size "$BATCH_SIZE" --timeout "$TIMEOUT" --parallel "$PARALLEL" --output "$OUTPUT_DIR" --api-key "$API_KEY"

# Merge reports if requested
if [ "$MERGE_REPORTS" = true ]; then
    echo "Merging reports..."
    MERGED_REPORT="$OUTPUT_DIR/merged_report.xlsx"
    ./merge_reports.py "$OUTPUT_DIR" "$MERGED_REPORT"
    echo "Merged report saved to $MERGED_REPORT"
    
    # Beautify the merged report if requested
    if [ "$BEAUTIFY_REPORT" = true ]; then
        echo "Beautifying the merged report..."
        python owasp_scanner_production/enhanced_report_generator.py "$MERGED_REPORT"
        echo "Enhanced report saved as: ${MERGED_REPORT%.*}_enhanced.xlsx"
    fi
fi

echo "Comprehensive scan completed successfully!"
echo "Results saved to: $OUTPUT_DIR"
if [ "$MERGE_REPORTS" = true ]; then
    echo "Merged report: $MERGED_REPORT"
    if [ "$BEAUTIFY_REPORT" = true ]; then
        echo "Enhanced report: ${MERGED_REPORT%.*}_enhanced.xlsx"
    fi
fi 