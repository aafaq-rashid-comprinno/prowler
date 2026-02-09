#!/bin/bash
set -e

# Parse arguments to find output directory BEFORE running prowler
OUTPUT_DIR="/tmp/prowler-output"
for arg in "$@"; do
    if [[ "$prev_arg" == "--output-directory" ]]; then
        OUTPUT_DIR="$arg"
        break
    fi
    prev_arg="$arg"
done

# Export for Python script
export OUTPUT_DIR

echo "Prowler will output to: $OUTPUT_DIR"

# Run Prowler with all passed arguments using poetry
cd /home/prowler
poetry run prowler "$@"

echo "Starting CSV cleaning in: $OUTPUT_DIR"

# Clean CSV files (remove newlines within fields)
python3 << 'EOF'
import csv
import glob
import os
import sys

output_dir = os.environ.get('OUTPUT_DIR', '/tmp/prowler-output')
csv_files = glob.glob(f'{output_dir}/*.csv')

for csv_file in csv_files:
    temp_file = csv_file + '.tmp'
    try:
        with open(csv_file, 'r', encoding='utf-8') as infile:
            with open(temp_file, 'w', encoding='utf-8', newline='') as outfile:
                reader = csv.reader(infile, delimiter=';')
                writer = csv.writer(outfile, delimiter=';', quoting=csv.QUOTE_MINIMAL)
                for row in reader:
                    cleaned_row = [field.replace('\n', ' ').replace('\r', '') for field in row]
                    writer.writerow(cleaned_row)
        os.replace(temp_file, csv_file)
        print(f"✓ Cleaned: {csv_file}")
    except Exception as e:
        print(f"✗ Error cleaning {csv_file}: {e}")
        if os.path.exists(temp_file):
            os.remove(temp_file)

print(f"CSV cleaning completed. Processed {len(csv_files)} files.")
EOF

echo "Prowler execution and CSV cleaning completed"
