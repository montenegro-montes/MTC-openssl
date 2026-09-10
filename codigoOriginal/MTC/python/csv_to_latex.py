from pathlib import Path
import pandas as pd
import argparse
import sys


# ---------------------------------------------------
# Auxiliary functions
# ---------------------------------------------------
def export_table(
    df: pd.DataFrame,   # DataFrame containing the data
    values: str,        # Column name from df for the values to summarize
    index: str,         # Column name from df for the rows in latex table
    columns: str,       # Column name from df for the columns in latex table
    output_file: Path,  # Path to the output LaTeX file
    filters=None,       # Dictionary of column names and allowed values
    caption=None,       # Caption for the LaTeX table
    label=None,         # Label for the LaTeX table
):

    # Apply filters if provided
    if filters:
        for column, allowed_values in filters.items():
            df = df[df[column].isin(allowed_values)]

    # Create a pivot table to summarize the data
    summary = df.pivot(
        index=index,
        columns=columns,
        values=values
    )

    # Write the LaTeX table to the output file
    with open(output_file, "w") as f:
        f.write(
            summary.to_latex(
                caption=caption,
                label=label,
                float_format="%.2f"
            )
        )

    print(f"[OK] Generated {output_file}")


# Function to parse command-line arguments
def parse_arguments():

    parser = argparse.ArgumentParser(
    description="Generate LaTeX tables from a CSV file",
    epilog="""
Examples:

  Assume you have a CSV file named results.csv with the following columns:
    - algorithm, chain, length, keys_bytes, certs_bytes, chain_bytes, avg_cert_bytes 

  Generate a table using chain_bytes values presented by algorithm (rows) and chain (columns):
    python3 csv_to_latex.py results.csv \\
        --rows algorithm \\
        --columns chain \\
        --values chain_bytes

  Generate multiple (3) tables using the layout as in the previous example:
    python3 csv_to_latex.py results.csv \\
        --rows algorithm \\
        --columns chain \\
        --values certs_bytes chain_bytes

  Same as first example, but filtering specific chain configurations:
    python3 csv_to_latex.py results.csv \\
        --rows algorithm \\
        --columns chain \\
        --values chain_bytes \\
        --filter chain=3:3,1:5,3,1

  Print the contents of the CSV file to learn about its structure and available columns:
    python3 csv_to_latex.py results.csv --print""",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        "csv",
        help="Input CSV file"
    )

    parser.add_argument(
        "--rows",
        help="CSV column whose unique values will become the table rows"
    )

    parser.add_argument(
        "--columns",
        help="CSV column whose unique values will become the table columns"
    )

    parser.add_argument(
        "--values",
        nargs="+",
        help="CSV column(s) containing the values shown in the table cells. "
        "One LaTeX table will be generated for each specified column."
    )

    parser.add_argument(
        "--filter",
        nargs="+",
        help="Filter rows based on column values. Keep those specified as 'column_name=value1:value2:...'." 
    )

    parser.add_argument(
        "--print",
        action="store_true", # No value needed, just a flag
        help="Print the table to console"
    )

    return parser.parse_args()


# Function to build filters from command-line arguments
def build_filters(filter_args):
    filters = {}
    if filter_args:
        for f in filter_args:
            column, values = f.split("=")
            filters[column] = values.split(":")
    return filters

# ---------------------------------------------------
# Main function to execute the script
# ---------------------------------------------------

# Get command-line arguments
args = parse_arguments()
    
# Read the CSV file into a DataFrame
csv_file = Path(args.csv)
if not csv_file.is_file():
    print(f"[ERROR] CSV file not found: {csv_file}")
    sys.exit(1)
df = pd.read_csv(csv_file)

# If the --print flag is set, print the DataFrame and exit
if args.print:
    print(df)
    exit(0)

# Build filters from command-line arguments
filters = build_filters(args.filter)
print(f"[INFO] Filters applied: {filters}")

# Export each specified metric to a LaTeX table
for value in args.values:
    export_table(df=df,
        values=value,           # Values will be the specified column
        index=args.rows,        # Rows will be the algorithms
        columns=args.columns,   # Columns will be the certificate chains
        output_file=f"{csv_file.stem}_{value}.tex",
        filters=filters
)