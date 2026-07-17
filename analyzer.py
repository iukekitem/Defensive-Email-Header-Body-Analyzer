import argparse
import sys
import os

from parser import parse_eml_file
from rules import analyze_email_data
from reporter import print_dashboard, print_json_report

def main():
    parser = argparse.ArgumentParser(
        description="Defensive Email Header & Body Analyzer - Analyze .eml files for phishing indicators."
    )
    parser.add_argument(
        "email_path",
        help="Path to the raw email (.eml) file to analyze"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output structured analysis in JSON format instead of a CLI dashboard"
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=7,
        help="Threshold score to classify an email as High Risk (default: 7)"
    )

    args = parser.parse_args()

    if not os.path.exists(args.email_path):
        print(f"Error: File '{args.email_path}' not found.", file=sys.stderr)
        sys.exit(1)

    try:
        # Phase 1: Parse the eml file
        parsed_data = parse_eml_file(args.email_path)

        # Phase 2: Run the rules/analysis engine
        analysis = analyze_email_data(parsed_data)

        # Custom threshold adjustment if supplied
        if args.threshold != 7:
            score = analysis['score']
            if score >= args.threshold:
                analysis['risk_level'] = 'High Risk'
            elif score >= max(1, args.threshold // 2):
                analysis['risk_level'] = 'Medium Risk'
            else:
                analysis['risk_level'] = 'Low Risk'

        # Phase 3: Reporting
        if args.json:
            print_json_report(parsed_data, analysis)
        else:
            print_dashboard(parsed_data, analysis, args.email_path)

    except Exception as e:
        print(f"Critical error analyzing email: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
