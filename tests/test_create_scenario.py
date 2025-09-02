"""
Simple test to verify create_test_scenario functionality.
"""
import pytest

from tests.fixtures.database_fixtures import (
    create_test_scenario,
    assert_scenario_created,
    get_scenario_summary,
    test_data_builder
)


def test_web_server_scenario_creation(test_data_builder):
    """Test creating a web server scenario using create_test_scenario."""
    # Create a web server scenario
    scenario_data = create_test_scenario(test_data_builder, "web_server")
    
    # Verify the scenario was created correctly
    assert_scenario_created(test_data_builder.db, scenario_data)
    
    # Check specific details
    assert scenario_data["scenario"] == "web_server"
    assert scenario_data["primary_ip"] == "192.168.1.200"
    assert len(scenario_data["ports"]) >= 3  # HTTP, HTTPS, SSH
    assert len(scenario_data["defects"]) >= 2  # XSS, SQLi
    
    # Print summary
    summary = get_scenario_summary(scenario_data)
    print(f"Created scenario summary:\n{summary}")
    
    print("✓ Web server scenario creation test passed!")


def test_domain_controller_scenario_creation(test_data_builder):
    """Test creating a domain controller scenario."""
    scenario_data = create_test_scenario(test_data_builder, "domain_controller")
    
    # Verify the scenario
    assert_scenario_created(test_data_builder.db, scenario_data)
    
    # Check DC-specific details
    assert scenario_data["scenario"] == "domain_controller"
    assert scenario_data["primary_ip"] == "10.0.0.10"
    assert len(scenario_data["ports"]) >= 6  # LDAP, Kerberos, DNS, SMB, etc.
    
    # Verify AD-specific ports exist
    ports = test_data_builder.db.find("ports", {"ip": "10.0.0.10"})
    port_numbers = [p["port"] for p in ports]
    assert "389" in port_numbers  # LDAP
    assert "88" in port_numbers   # Kerberos
    assert "445" in port_numbers  # SMB
    
    print("✓ Domain controller scenario creation test passed!")


def test_multiple_scenarios_isolation(test_data_builder):
    """Test that multiple scenarios don't interfere with each other."""
    # Create multiple scenarios
    web_scenario = create_test_scenario(test_data_builder, "web_server")
    db_scenario = create_test_scenario(test_data_builder, "database_server")
    
    # Verify both scenarios exist
    assert_scenario_created(test_data_builder.db, web_scenario)
    assert_scenario_created(test_data_builder.db, db_scenario)
    
    # Check they have different IPs
    assert web_scenario["primary_ip"] != db_scenario["primary_ip"]
    
    # Count total objects
    total_ips = len(list(test_data_builder.db.find("ips", {})))
    total_ports = len(list(test_data_builder.db.find("ports", {})))
    total_tools = len(list(test_data_builder.db.find("tools", {})))
    total_defects = len(list(test_data_builder.db.find("defects", {})))
    
    print(f"Multiple scenarios created:")
    print(f"- Total IPs: {total_ips}")
    print(f"- Total ports: {total_ports}")
    print(f"- Total tools: {total_tools}")
    print(f"- Total defects: {total_defects}")
    
    assert total_ips >= 2  # At least 2 IPs from 2 scenarios
    assert total_ports >= 6  # Multiple ports per scenario
    assert total_defects >= 4  # Multiple defects per scenario
    
    print("✓ Multiple scenarios isolation test passed!")


def test_scenario_types_available():
    """Test that all expected scenario types are available."""
    # Test with invalid scenario to get the error message
    try:
        create_test_scenario(None, "invalid_scenario")
        assert False, "Should have raised ValueError for invalid scenario"
    except ValueError as e:
        error_msg = str(e)
        print(f"Error message for invalid scenario: {error_msg}")
        
        # Check that error message lists available scenarios
        expected_scenarios = ["web_server", "domain_controller", "database_server", 
                             "mail_server", "dns_server", "ftp_server"]
        for scenario in expected_scenarios:
            assert scenario in error_msg, f"Scenario {scenario} should be listed in error message"
    
    print("✓ Scenario types validation test passed!")
