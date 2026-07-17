import os
import sys

from parser import parse_eml_file
from rules import analyze_email_data

# ANSI styling
RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"

def run_test_case(name, file_path, expected_min_score, expected_risk_level, expected_indicators):
    print(f"{BOLD}{CYAN}Testing {name}...{RESET}")
    if not os.path.exists(file_path):
        print(f"  {RED}FAIL: Test file {file_path} not found!{RESET}")
        return False

    try:
        parsed_data = parse_eml_file(file_path)
        analysis = analyze_email_data(parsed_data)
        
        score = analysis['score']
        risk_level = analysis['risk_level']
        indicators = [ind['name'] for ind in analysis['indicators']]

        # Verifications
        success = True
        
        # Check score
        if score < expected_min_score:
            print(f"  {RED}FAIL: Expected score >= {expected_min_score}, got {score}{RESET}")
            success = False
            
        # Check risk level
        if risk_level != expected_risk_level:
            print(f"  {RED}FAIL: Expected risk level '{expected_risk_level}', got '{risk_level}'{RESET}")
            success = False
            
        # Check expected indicators
        for exp_ind in expected_indicators:
            if exp_ind not in indicators:
                print(f"  {RED}FAIL: Expected indicator '{exp_ind}' not found in {indicators}{RESET}")
                success = False

        if success:
            print(f"  {GREEN}PASS: Score: {score}, Risk: {risk_level}{RESET}")
            print(f"  Indicators triggered: {indicators}")
            return True
        else:
            return False

    except Exception as e:
        print(f"  {RED}FAIL: Exception raised during analysis: {e}{RESET}")
        import traceback
        traceback.print_exc()
        return False

def main():
    print("=" * 60)
    print(f"{BOLD}RUNNING EMAIL ANALYZER TEST SUITE{RESET}")
    print("=" * 60)

    test_cases = [
        {
            'name': 'Safe Email',
            'file_path': 'samples/safe_email.eml',
            'expected_min_score': 0,
            'expected_risk_level': 'Low Risk',
            'expected_indicators': []
        },
        {
            'name': 'Spoofed Sender Email',
            'file_path': 'samples/spoofed_sender.eml',
            'expected_min_score': 10,
            'expected_risk_level': 'High Risk',
            'expected_indicators': ['Sender Domain Mismatch', 'SPF Authentication Failure']
        },
        {
            'name': 'Phishing Scam Email',
            'file_path': 'samples/phishing_scam.eml',
            'expected_min_score': 13,
            'expected_risk_level': 'High Risk',
            'expected_indicators': ['Urgent Language Detected', 'Raw IP Address Link', 'Mismatched Link Domain']
        },
        {
            'name': 'Malicious Attachment Email',
            'file_path': 'samples/malicious_attachment.eml',
            'expected_min_score': 5,
            'expected_risk_level': 'Medium Risk',
            'expected_indicators': ['Suspicious Attachment Detected']
        }
    ]

    all_passed = True
    for tc in test_cases:
        passed = run_test_case(
            tc['name'],
            tc['file_path'],
            tc['expected_min_score'],
            tc['expected_risk_level'],
            tc['expected_indicators']
        )
        if not passed:
            all_passed = False
        print("-" * 60)

    if all_passed:
        print(f"{BOLD}{GREEN}ALL TESTS PASSED SUCCESSFULLY!{RESET}")
        sys.exit(0)
    else:
        print(f"{BOLD}{RED}SOME TESTS FAILED!{RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()
