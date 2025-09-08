#!/bin/bash

# Test runner script for Pollenisator
# Provides easy commands for running different test suites

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if virtual environment is activated
check_venv() {
    if [[ -z "$VIRTUAL_ENV" ]]; then
        print_warning "No virtual environment detected. Consider activating one by settings your mongodb uri as TEST_MONGO_URI."
    else
        print_status "Using virtual environment: $VIRTUAL_ENV"
    fi
}

# Install test dependencies
install_deps() {
    print_status "Installing test dependencies..."
    pip install -r test-requirements.txt
    print_success "Test dependencies installed"
}

# Run unit tests (fast, isolated, no external dependencies)
run_unit_tests() {
    print_status "Running unit tests..."
    python -m pytest tests/ -m "unit or (not integration and not slow)" -v
    print_success "Unit tests completed"
}

# Run integration tests (may require external services)
run_integration_tests() {
    print_status "Running integration tests..."
    python -m pytest tests/ -m "integration" -v
    print_success "Integration tests completed"
}

# Run throwable database tests
run_throwable_db_tests() {
    print_status "Running throwable database tests..."
    python -m pytest tests/test_mongo_throwable.py -m "not integration" -v
    print_success "Throwable database tests completed"
}

# Run real database tests (requires MongoDB)
run_real_db_tests() {
    print_status "Checking MongoDB availability..."
    
    print_status "Running real database tests..."
    python -m pytest tests/test_mongo_throwable.py -m "integration" -v
    print_success "Real database tests completed"
}

# Run all database tests
run_all_db_tests() {
    print_status "Running all database tests..."
    run_throwable_db_tests
    run_real_db_tests
    print_success "All database tests completed"
}

# Run performance tests
run_performance_tests() {
    print_status "Running performance tests..."
    python -m pytest tests/performance/ -v --benchmark-only
    print_success "Performance tests completed"
}

# Run security tests
run_security_tests() {
    print_status "Running security tests..."
    python -m pytest tests/security/ -v
    print_success "Security tests completed"
}

# Run all tests
run_all_tests() {
    print_status "Running complete test suite..."
    python -m pytest tests/ -v
    print_success "Complete test suite completed"
}

# Run tests with coverage
run_tests_with_coverage() {
    print_status "Running tests with coverage report..."
    python -m pytest tests/ --cov=pollenisator --cov-report=html:htmlcov --cov-report=term-missing --cov-fail-under=70
    print_success "Tests with coverage completed"
    print_status "Coverage report generated in htmlcov/index.html"
}

# Clean up test artifacts
cleanup() {
    print_status "Cleaning up test artifacts..."
    
    # Remove coverage files
    rm -f .coverage
    rm -rf htmlcov/
    
    # Remove pytest cache
    rm -rf .pytest_cache/
    
    # Remove Python cache
    find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    find . -type f -name "*.pyc" -delete
    
    # Remove test databases (if any)
    rm -rf test_mongo_data/
    
    print_success "Cleanup completed"
}

# Show help
show_help() {
    echo "Pollenisator Test Runner"
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  install       Install test dependencies"
    echo "  unit         Run unit tests (fast, isolated)"
    echo "  integration  Run integration tests (may require external services)"
    echo "  throwable-db Run throwable database tests (uses mongomock)"
    echo "  real-db      Run real database tests (requires MongoDB)"
    echo "  all-db       Run all database tests"
    echo "  performance  Run performance tests"
    echo "  security     Run security tests"
    echo "  all          Run all tests"
    echo "  coverage     Run tests with coverage report"
    echo "  cleanup      Clean up test artifacts"
    echo "  help         Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 unit                # Run only unit tests"
    echo "  $0 throwable-db        # Run database tests with mongomock"
    echo "  $0 coverage           # Run tests with coverage"
    echo "  $0 cleanup            # Clean up after testing"
    echo ""
    echo "Environment Variables:"
    echo "  TEST_MONGO_URI        # MongoDB URI for real database tests"
    echo "                        # Default: mongodb://localhost:27018/"
}

# Main script logic
main() {
    check_venv
    
    case "${1:-help}" in
        install)
            install_deps
            ;;
        unit)
            run_unit_tests
            ;;
        integration)
            run_integration_tests
            ;;
        throwable-db)
            run_throwable_db_tests
            ;;
        real-db)
            run_real_db_tests
            ;;
        all-db)
            run_all_db_tests
            ;;
        performance)
            run_performance_tests
            ;;
        security)
            run_security_tests
            ;;
        all)
            run_all_tests
            ;;
        coverage)
            run_tests_with_coverage
            ;;
        cleanup)
            cleanup
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            print_error "Unknown command: $1"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
