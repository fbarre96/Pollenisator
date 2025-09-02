#!/usr/bin/env python3
"""
Test runner script for Pollenisator API tests
"""
import sys
import subprocess
import argparse


def run_tests(test_type=None, coverage=True, verbose=False, parallel=False):
    """Run tests with specified configuration."""
    cmd = ["python", "-m", "pytest"]
    
    # Base arguments
    if verbose:
        cmd.append("-v")
    
    if parallel:
        cmd.extend(["-n", "auto"])
    
    # Test type selection
    if test_type == "unit":
        cmd.extend(["-m", "unit", "tests/api/"])
    elif test_type == "integration":
        cmd.extend(["-m", "integration", "tests/integration/"])
    elif test_type == "performance":
        cmd.extend(["-m", "performance", "tests/performance/"])
    elif test_type == "smoke":
        cmd.extend(["-m", "smoke"])
    elif test_type == "security":
        cmd.extend(["-m", "security"])
    elif test_type == "auth":
        cmd.extend(["-m", "auth"])
    else:
        cmd.append("tests/")
    
    # Coverage options
    if coverage and test_type != "performance":
        cmd.extend([
            "--cov=pollenisator",
            "--cov-report=term-missing",
            "--cov-report=html:htmlcov",
        ])
    
    print(f"Running command: {' '.join(cmd)}")
    return subprocess.run(cmd, check=False)


def setup_test_environment():
    """Set up test environment."""
    # Install test dependencies
    subprocess.run([
        sys.executable, "-m", "pip", "install", "-r", "test-requirements.txt", "--break-system-packages"
    ], check=True)
    


def generate_test_report():
    """Generate comprehensive test report."""
    print("Generating comprehensive test report...")
    
    # Run all test categories and collect results
    test_results = {}
    
    test_categories = [
        ("unit", "Unit Tests"),
        ("integration", "Integration Tests"),
        ("performance", "Performance Tests"),
        ("auth", "Authentication Tests"),
        ("security", "Security Tests")
    ]
    
    for category, description in test_categories:
        print(f"\nRunning {description}...")
        result = run_tests(test_type=category, coverage=False, verbose=True)
        test_results[category] = result.returncode == 0
    
    # Generate summary
    print("\n" + "="*50)
    print("TEST SUMMARY")
    print("="*50)
    
    for category, description in test_categories:
        status = "PASS" if test_results.get(category, False) else "FAIL"
        print(f"{description:20} : {status}")
    
    total_passed = sum(test_results.values())
    total_tests = len(test_results)
    
    print(f"\nOverall: {total_passed}/{total_tests} test categories passed")
    
    if total_passed == total_tests:
        print("🎉 All test categories passed!")
        return 0
    else:
        print("❌ Some test categories failed")
        return 1


def main():
    parser = argparse.ArgumentParser(description="Pollenisator API Test Runner")
    parser.add_argument(
        "--type", 
        choices=["unit", "integration", "performance", "smoke", "security", "auth", "all"],
        default="all",
        help="Type of tests to run"
    )
    parser.add_argument(
        "--no-coverage", 
        action="store_true",
        help="Disable coverage reporting"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output"
    )
    parser.add_argument(
        "--parallel", "-j",
        action="store_true",
        help="Run tests in parallel"
    )
    parser.add_argument(
        "--setup",
        action="store_true",
        help="Set up test environment"
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Generate comprehensive test report"
    )
    
    args = parser.parse_args()
    
    if args.setup:
        print("Setting up test environment...")
        setup_test_environment()
        return 0
    
    if args.report:
        return generate_test_report()
    
    # Run specified tests
    result = run_tests(
        test_type=args.type if args.type != "all" else None,
        coverage=not args.no_coverage,
        verbose=args.verbose,
        parallel=args.parallel
    )
    
    return result.returncode


if __name__ == "__main__":
    exit(main())
