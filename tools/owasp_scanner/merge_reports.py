#!/usr/bin/env python3
"""
Merge multiple OWASP ZAP scan reports into a single comprehensive report.
"""

import os
import sys
import glob
import pandas as pd
from datetime import datetime

def merge_reports(report_dir, output_file=None):
    """
    Merge all Excel reports in the specified directory into a single report.
    
    Args:
        report_dir (str): Directory containing Excel reports
        output_file (str, optional): Output file name. If not provided, a default name will be used.
    
    Returns:
        str: Path to the merged report
    """
    # Find all Excel files in the directory
    excel_files = glob.glob(os.path.join(report_dir, "*.xlsx"))
    
    if not excel_files:
        print(f"No Excel files found in {report_dir}")
        return None
    
    print(f"Found {len(excel_files)} Excel files to merge")
    
    # Create a list to store all dataframes
    all_dfs = []
    total_vulnerabilities = 0
    scanned_urls = set()
    
    # Read each Excel file and append to the list
    for file in excel_files:
        try:
            print(f"Processing {file}...")
            df = pd.read_excel(file)
            
            # Extract URLs from the report
            if 'URL' in df.columns:
                scanned_urls.update(df['URL'].unique())
            
            # Count vulnerabilities
            total_vulnerabilities += len(df)
            
            # Add source file information
            df['Source Report'] = os.path.basename(file)
            
            all_dfs.append(df)
        except Exception as e:
            print(f"Error processing {file}: {e}")
    
    if not all_dfs:
        print("No valid data found in the Excel files")
        return None
    
    # Concatenate all dataframes
    merged_df = pd.concat(all_dfs, ignore_index=True)
    
    # Create output file name if not provided
    if not output_file:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(report_dir, f"merged_report_{timestamp}.xlsx")
    
    # Create a summary dataframe
    summary_data = {
        'Metric': ['Total URLs Scanned', 'Total Vulnerabilities Found', 'Number of Reports Merged'],
        'Value': [len(scanned_urls), total_vulnerabilities, len(excel_files)]
    }
    summary_df = pd.DataFrame(summary_data)
    
    # Write to Excel with multiple sheets
    with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
        summary_df.to_excel(writer, sheet_name='Summary', index=False)
        merged_df.to_excel(writer, sheet_name='All Vulnerabilities', index=False)
        
        # Create a sheet with vulnerability counts by type
        if 'Alert' in merged_df.columns:
            vuln_counts = merged_df['Alert'].value_counts().reset_index()
            vuln_counts.columns = ['Vulnerability Type', 'Count']
            vuln_counts.to_excel(writer, sheet_name='Vulnerability Summary', index=False)
        
        # Create a sheet with vulnerability counts by URL
        if 'URL' in merged_df.columns:
            url_counts = merged_df.groupby('URL').size().reset_index()
            url_counts.columns = ['URL', 'Vulnerability Count']
            url_counts = url_counts.sort_values('Vulnerability Count', ascending=False)
            url_counts.to_excel(writer, sheet_name='URL Summary', index=False)
        
        # Create a sheet with risk level summary if available
        if 'Risk' in merged_df.columns:
            risk_counts = merged_df['Risk'].value_counts().reset_index()
            risk_counts.columns = ['Risk Level', 'Count']
            # Sort by risk level (High, Medium, Low, Informational)
            risk_order = {'High': 0, 'Medium': 1, 'Low': 2, 'Informational': 3}
            risk_counts['Order'] = risk_counts['Risk Level'].map(risk_order)
            risk_counts = risk_counts.sort_values('Order').drop('Order', axis=1)
            risk_counts.to_excel(writer, sheet_name='Risk Summary', index=False)
    
    print(f"Merged report saved to {output_file}")
    print(f"Total URLs scanned: {len(scanned_urls)}")
    print(f"Total vulnerabilities found: {total_vulnerabilities}")
    
    return output_file

def main():
    if len(sys.argv) < 2:
        print("Usage: python merge_reports.py <reports_directory> [output_file]")
        sys.exit(1)
    
    report_dir = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    if not os.path.isdir(report_dir):
        print(f"Error: {report_dir} is not a valid directory")
        sys.exit(1)
    
    merged_file = merge_reports(report_dir, output_file)
    
    if merged_file:
        print(f"Successfully merged reports into {merged_file}")
    else:
        print("Failed to merge reports")
        sys.exit(1)

if __name__ == "__main__":
    main() 