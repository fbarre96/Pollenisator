"""
Database fixtures for testing with throwable MongoDB instances.
"""
import pytest
import os
import tempfile
import uuid
import shutil
from typing import Generator, Optional
from unittest.mock import patch, Mock
import mongomock
from pymongo import MongoClient
from bson import ObjectId

from pollenisator.core.components.mongo import DBClient


class ThrowableDBClient(DBClient):
    """
    A throwable database client that can be easily created and destroyed for testing.
    Uses mongomock for isolated testing or can connect to a test MongoDB instance.
    """
    
    def __init__(self, use_real_mongo: bool = False, test_db_name: str = "test_pollenisator"):
        self.use_real_mongo = use_real_mongo
        self.test_db_name = test_db_name
        self.temp_files_dir: Optional[str] = None
        
        # Bypass the singleton pattern for testing
        import os
        from pollenisator.core.components.cacher import Cacher
        
        # Initialize instance variables without calling super().__init__()
        pid = os.getpid()
        self.cacher = Cacher()
        self.client = None
        self.current_pentest = None
        self.db = None
        self.host = "localhost"
        self.port = 27017
        self.user = ""
        self.password = ""
        self.ssl = ""
        self.ssldir = ""
        self.forbiddenNames = ["admin", "config", "local", "pollenisator"]
        if not use_real_mongo:
            # Use mongomock for fast, isolated tests
            print(f"Creating ThrowableDBClient as mock")

            self.client = mongomock.MongoClient()
        else:
            # Use real MongoDB for integration tests
            mongo_uri = os.getenv('TEST_MONGO_URI', 'mongodb://localhost:27018/')
            from pymongo import MongoClient
            self.client = MongoClient(mongo_uri)
            print(f"Creating ThrowableDBClient with real MongoDB at {mongo_uri}")
        
        # Create temporary files directory
        self.temp_files_dir = tempfile.mkdtemp(prefix="pollenisator_test_")
        
        # Mock notification system to avoid SocketIO issues in tests
        self.send_notify = Mock()
    
    def setup_test_data(self, pentest_name = "test-pentest-setup", pentest_uuid = "3f9c2d7e-6c1a-4b8e-9f2d-1a7c3e5b8f90") -> str:
        """
        Set up a test pentest with basic data structure.
        
        Args:
            pentest_uuid: UUID for the test pentest
            
        Returns:
            str: The pentest UUID
        """
        # Create pentest record - use pentest_name as the UUID so tests can
        pentest_data = {
            "uuid": pentest_uuid,
            "nom": pentest_name,
            "owner": "admin",
            "creation_date": "2024-01-01T00:00:00",
            "pentesters": ["admin", "pentester1"]
        }
        
        self.client.pollenisator.pentests.insert_one(pentest_data)
        
        # Connect to the test pentest
        self.connectToDb(pentest_uuid)
        
        # Create basic collections structure
        self._create_test_collections(pentest_uuid)
        
        return pentest_uuid
    
    def _create_test_collections(self, pentest_uuid: str):
        """Create basic test collections with sample data."""
        db = self.client[pentest_uuid]
        
        # Sample IPs
        ips_data = [
            {"_id": ObjectId(), "ip": "192.168.1.1", "in_scopes": ["Main"], "notes": "Gateway"},
            {"_id": ObjectId(), "ip": "192.168.1.100", "in_scopes": ["Main"], "notes": "Web Server"},
            {"_id": ObjectId(), "ip": "10.0.0.1", "in_scopes": ["Internal"], "notes": "Internal Server"}
        ]
        db.ips.insert_many(ips_data)
        
        # Sample Ports
        ports_data = [
            {"_id": ObjectId(), "ip": "192.168.1.1", "port": "22", "proto": "tcp", "service": "ssh"},
            {"_id": ObjectId(), "ip": "192.168.1.1", "port": "80", "proto": "tcp", "service": "http"},
            {"_id": ObjectId(), "ip": "192.168.1.100", "port": "443", "proto": "tcp", "service": "https"}
        ]
        db.ports.insert_many(ports_data)
        
        # Sample Tools
        tools_data = [
            {
                "_id": ObjectId(), 
                "name": "nmap",
                "wave": "Main",
                "scope": "192.168.1.0/24",
                "status": "running",
                "dated": "2024-01-01T10:00:00",
                "datef": "2024-01-01T10:05:00"
            }
        ]
        db.tools.insert_many(tools_data)
        
        # Sample Defects
        defects_data = [
            {
                "_id": ObjectId(),
                "title": "Test SQL Injection",
                "description": "A test SQL injection vulnerability",
                "impact": "Major",
                "ease": "Difficult",
                "risk": "Major",
                "cvss": 8.5,
                "type": ["Web"],
                "proofs": []
            }
        ]
        db.defects.insert_many(defects_data)
        
        # Sample Settings
        settings_data = [
            {"key": "tags", "value": {"critical": {"color": "#ff0000", "level": 5}}},
            {"key": "mission_name", "value": "Test Mission"}
        ]
        db.settings.insert_many(settings_data)
    
    def cleanup(self):
        """Clean up the test database and temporary files."""
        if self.client:
            if self.use_real_mongo and self.current_pentest:
                # Drop test databases when using real MongoDB
                self.client.drop_database(self.current_pentest)
                self.client.drop_database("test_pollenisator")
            self.client.close()
        
        # Clean up temporary files
        if self.temp_files_dir and os.path.exists(self.temp_files_dir):
            shutil.rmtree(self.temp_files_dir)
    
    def get_files_dir(self) -> str:
        """Get the temporary files directory for testing."""
        return self.temp_files_dir or tempfile.gettempdir()


@pytest.fixture(scope="function")
def throwable_db() -> Generator[ThrowableDBClient, None, None]:
    """
    Create a throwable database instance for testing.
    Uses mongomock by default for fast isolated tests.
    """
    db_client = ThrowableDBClient(use_real_mongo=False)
    
    # Patch the singleton to return our test instance
    # Access the private attribute using name mangling
    with patch.object(DBClient, '_DBClient__instances', {os.getpid(): db_client}):
        with patch.object(DBClient, 'getInstance', return_value=db_client):
            yield db_client
    
    # Cleanup after test
    db_client.cleanup()


@pytest.fixture(scope="function") 
def throwable_db_with_data() -> Generator[ThrowableDBClient, None, None]:
    """
    Create a throwable database instance with test data for testing.
    """
    db_client = ThrowableDBClient(use_real_mongo=False)
    pentest_uuid = db_client.setup_test_data()
    
    # Patch the singleton to return our test instance
    with patch.object(DBClient, '_DBClient__instances', {os.getpid(): db_client}):
        with patch.object(DBClient, 'getInstance', return_value=db_client):
            yield db_client
    
    # Cleanup after test
    db_client.cleanup()


@pytest.fixture(scope="function")
def real_throwable_db() -> Generator[ThrowableDBClient, None, None]:
    """
    Create a throwable database instance using real MongoDB for integration tests.
    Requires TEST_MONGO_URI environment variable or MongoDB running on localhost.
    """
    # Skip if no MongoDB available
    mongo_uri = os.getenv('TEST_MONGO_URI', 'mongodb://localhost:27018/')
    
    try:
        # Test connection
        from pymongo import MongoClient
        test_client = MongoClient(mongo_uri, serverSelectionTimeoutMS=1000)
        test_client.admin.command('ping')
        test_client.close()
    except Exception:
        pytest.skip("MongoDB not available for integration tests")
    
    db_client = ThrowableDBClient(use_real_mongo=True)
    
    # Patch the singleton to return our test instance
    with patch.object(DBClient, '_DBClient__instances', {os.getpid(): db_client}):
        with patch.object(DBClient, 'getInstance', return_value=db_client):
            yield db_client
    
    # Cleanup after test
    db_client.cleanup()


@pytest.fixture(scope="function")
def real_throwable_db_with_data() -> Generator[ThrowableDBClient, None, None]:
    """
    Create a throwable database instance with real MongoDB and test data.
    """
    # Skip if no MongoDB available
    mongo_uri = os.getenv('TEST_MONGO_URI', 'mongodb://localhost:27018/')
    
    try:
        # Test connection
        from pymongo import MongoClient
        test_client = MongoClient(mongo_uri, serverSelectionTimeoutMS=1000)
        test_client.admin.command('ping')
        test_client.close()
    except Exception:
        pytest.skip("MongoDB not available for integration tests")
    
    db_client = ThrowableDBClient(use_real_mongo=True)
    pentest_uuid = db_client.setup_test_data()
    
    # Patch the singleton to return our test instance  
    with patch.object(DBClient, '_DBClient__instances', {os.getpid(): db_client}):
        with patch.object(DBClient, 'getInstance', return_value=db_client):
            yield db_client
    
    # Cleanup after test
    db_client.cleanup()


class TestDataBuilder:
    """Builder class for creating test data objects."""
    
    def __init__(self, db_client: ThrowableDBClient):
        self.db = db_client
    
    def create_ip(self, ip: str = "192.168.1.50", scopes: list = None, **kwargs):
        """Create a test IP address."""
        if scopes is None:
            scopes = ["Main"]
        
        ip_data = {
            "ip": ip,
            "in_scopes": scopes,
            "notes": kwargs.get("notes", f"Test IP {ip}"),
            **kwargs
        }
        
        result = self.db.insert("ips", ip_data)
        return result.inserted_id
    
    def create_port(self, ip: str = "192.168.1.50", port: str = "8080", **kwargs):
        """Create a test port."""
        port_data = {
            "ip": ip,
            "port": port,
            "proto": kwargs.get("proto", "tcp"),
            "service": kwargs.get("service", "unknown"),
            "product": kwargs.get("product", ""),
            "notes": kwargs.get("notes", f"Test port {port}"),
            **kwargs
        }
        
        result = self.db.insert("ports", port_data)
        return result.inserted_id
    
    def create_tool(self, name: str = "test_tool", **kwargs):
        """Create a test tool."""
        tool_data = {
            "name": name,
            "wave": kwargs.get("wave", "Main"),
            "scope": kwargs.get("scope", "192.168.1.0/24"),
            "status": kwargs.get("status", "ready"),
            "dated": kwargs.get("dated", "2024-01-01T10:00:00"),
            **kwargs
        }
        
        result = self.db.insert("tools", tool_data)
        return result.inserted_id
    
    def create_defect(self, title: str = "Test Defect", **kwargs):
        """Create a test defect."""
        defect_data = {
            "title": title,
            "description": kwargs.get("description", f"Description for {title}"),
            "impact": kwargs.get("impact", "Major"),
            "ease": kwargs.get("ease", "Moderate"),
            "risk": kwargs.get("risk", "Major"),
            "cvss": kwargs.get("cvss", 7.0),
            "type": kwargs.get("type", ["Web"]),
            "proofs": kwargs.get("proofs", []),
            **kwargs
        }
        
        result = self.db.insert("defects", defect_data)
        return result.inserted_id


def create_test_scenario(builder: TestDataBuilder, scenario_name: str):
    """
    Create a predefined test scenario with related data.
    
    This function creates common penetration testing scenarios with realistic
    related data objects. It's useful for testing complex workflows and
    ensuring data relationships are properly maintained.
    
    Args:
        builder: TestDataBuilder instance to create the objects
        scenario_name: Name of the scenario to create
        
    Available scenarios:
        - "web_server": Web application server with HTTP/HTTPS ports
        - "domain_controller": Active Directory domain controller
        - "database_server": Database server with common DB ports
        - "mail_server": Email server with SMTP/IMAP/POP3 ports
        - "dns_server": DNS server configuration
        - "ftp_server": FTP server with common vulnerabilities
        
    Returns:
        dict: Dictionary with created object IDs and details
        
    Raises:
        ValueError: If scenario_name is not recognized
        
    Example:
        >>> scenario_data = create_test_scenario(builder, "web_server")
        >>> ip_id = scenario_data["ip_id"]
        >>> ports = scenario_data["ports"]
    """
    if scenario_name == "web_server":
        # Create a web server scenario with HTTP/HTTPS and common vulnerabilities
        ip_id = builder.create_ip("192.168.1.200", ["DMZ"], notes="Web application server")
        http_port = builder.create_port("192.168.1.200", "80", service="http", product="Apache 2.4.41")
        https_port = builder.create_port("192.168.1.200", "443", service="https", product="Apache 2.4.41")
        ssh_port = builder.create_port("192.168.1.200", "22", service="ssh", product="OpenSSH 8.2")
        
        # Web scanning tools
        nmap_tool = builder.create_tool("nmap", wave="Discovery", status="completed", 
                                       scope="192.168.1.200", ip="192.168.1.200")
        web_scan_tool = builder.create_tool("web_scan", wave="Main", status="completed",
                                          scope="192.168.1.200", port="80,443")
        
        # Common web vulnerabilities
        xss_defect = builder.create_defect("Cross-Site Scripting (XSS)", 
                                         impact="Medium", cvss=6.1, type=["Web"],
                                         description="Reflected XSS vulnerability in search parameter")
        sqli_defect = builder.create_defect("SQL Injection", 
                                          impact="High", cvss=8.2, type=["Web"],
                                          description="SQL injection in login form")
        
        return {
            "scenario": "web_server",
            "ip_id": ip_id,
            "ports": [http_port, https_port, ssh_port],
            "tools": [nmap_tool, web_scan_tool],
            "defects": [xss_defect, sqli_defect],
            "primary_ip": "192.168.1.200"
        }
    
    elif scenario_name == "domain_controller":
        # Create a Windows Active Directory domain controller scenario
        ip_id = builder.create_ip("10.0.0.10", ["Internal"], notes="Windows Domain Controller")
        
        # AD-specific ports
        ldap_port = builder.create_port("10.0.0.10", "389", service="ldap", product="Microsoft Windows Active Directory LDAP")
        ldaps_port = builder.create_port("10.0.0.10", "636", service="ldaps", product="Microsoft Windows Active Directory LDAP SSL")
        kerberos_port = builder.create_port("10.0.0.10", "88", service="kerberos-sec", product="Microsoft Windows Kerberos")
        dns_port = builder.create_port("10.0.0.10", "53", service="domain", product="Microsoft DNS")
        smb_port = builder.create_port("10.0.0.10", "445", service="microsoft-ds", product="Microsoft Windows SMB")
        rpc_port = builder.create_port("10.0.0.10", "135", service="msrpc", product="Microsoft Windows RPC")
        
        # AD scanning tools
        ad_enum_tool = builder.create_tool("ad_enum", wave="Discovery", status="completed",
                                         scope="10.0.0.10", ip="10.0.0.10")
        kerberos_tool = builder.create_tool("kerberos_enum", wave="Main", status="completed",
                                          scope="10.0.0.10", port="88")
        
        # AD-specific vulnerabilities
        weak_kerberos = builder.create_defect("Weak Kerberos Configuration",
                                            impact="High", cvss=7.5, type=["Active Directory"],
                                            description="Kerberos pre-authentication disabled for some accounts")
        smb_signing = builder.create_defect("SMB Signing Not Required",
                                          impact="Medium", cvss=5.4, type=["Network"],
                                          description="SMB signing is not enforced, allowing relay attacks")
        
        return {
            "scenario": "domain_controller", 
            "ip_id": ip_id,
            "ports": [ldap_port, ldaps_port, kerberos_port, dns_port, smb_port, rpc_port],
            "tools": [ad_enum_tool, kerberos_tool],
            "defects": [weak_kerberos, smb_signing],
            "primary_ip": "10.0.0.10"
        }
    
    elif scenario_name == "database_server":
        # Create a database server scenario
        ip_id = builder.create_ip("10.0.1.50", ["Internal"], notes="Database server cluster")
        
        # Database ports
        mysql_port = builder.create_port("10.0.1.50", "3306", service="mysql", product="MySQL 8.0.25")
        postgres_port = builder.create_port("10.0.1.50", "5432", service="postgresql", product="PostgreSQL 13.3")
        mssql_port = builder.create_port("10.0.1.50", "1433", service="ms-sql-s", product="Microsoft SQL Server 2019")
        ssh_port = builder.create_port("10.0.1.50", "22", service="ssh", product="OpenSSH 8.4")
        
        # Database scanning tools
        db_scan_tool = builder.create_tool("database_scan", wave="Main", status="completed",
                                         scope="10.0.1.50", ip="10.0.1.50")
        
        # Database vulnerabilities
        weak_creds = builder.create_defect("Weak Database Credentials",
                                         impact="Critical", cvss=9.1, type=["Database"],
                                         description="Default or weak credentials found on database services")
        unencrypted_conn = builder.create_defect("Unencrypted Database Connections",
                                                impact="Medium", cvss=5.9, type=["Database"],
                                                description="Database connections not using SSL/TLS encryption")
        
        return {
            "scenario": "database_server",
            "ip_id": ip_id,
            "ports": [mysql_port, postgres_port, mssql_port, ssh_port],
            "tools": [db_scan_tool],
            "defects": [weak_creds, unencrypted_conn],
            "primary_ip": "10.0.1.50"
        }
    
    elif scenario_name == "mail_server":
        # Create an email server scenario
        ip_id = builder.create_ip("192.168.2.100", ["DMZ"], notes="Email server")
        
        # Mail server ports
        smtp_port = builder.create_port("192.168.2.100", "25", service="smtp", product="Postfix 3.6.4")
        smtps_port = builder.create_port("192.168.2.100", "465", service="smtps", product="Postfix 3.6.4")
        submission_port = builder.create_port("192.168.2.100", "587", service="submission", product="Postfix 3.6.4")
        imap_port = builder.create_port("192.168.2.100", "143", service="imap", product="Dovecot 2.3.16")
        imaps_port = builder.create_port("192.168.2.100", "993", service="imaps", product="Dovecot 2.3.16")
        pop3_port = builder.create_port("192.168.2.100", "110", service="pop3", product="Dovecot 2.3.16")
        pop3s_port = builder.create_port("192.168.2.100", "995", service="pop3s", product="Dovecot 2.3.16")
        
        # Mail server tools
        mail_enum_tool = builder.create_tool("mail_enum", wave="Discovery", status="completed",
                                           scope="192.168.2.100", ip="192.168.2.100")
        
        # Mail server vulnerabilities
        open_relay = builder.create_defect("SMTP Open Relay",
                                         impact="High", cvss=7.5, type=["Email"],
                                         description="SMTP server configured as open relay")
        weak_ssl = builder.create_defect("Weak SSL/TLS Configuration",
                                       impact="Medium", cvss=6.1, type=["Cryptography"],
                                       description="Mail server using outdated SSL/TLS protocols")
        
        return {
            "scenario": "mail_server",
            "ip_id": ip_id,
            "ports": [smtp_port, smtps_port, submission_port, imap_port, imaps_port, pop3_port, pop3s_port],
            "tools": [mail_enum_tool],
            "defects": [open_relay, weak_ssl],
            "primary_ip": "192.168.2.100"
        }
    
    elif scenario_name == "dns_server":
        # Create a DNS server scenario
        ip_id = builder.create_ip("10.0.0.2", ["Internal"], notes="Primary DNS server")
        
        # DNS ports
        dns_tcp_port = builder.create_port("10.0.0.2", "53", service="domain", product="BIND 9.16.1", proto="tcp")
        dns_udp_port = builder.create_port("10.0.0.2", "53", service="domain", product="BIND 9.16.1", proto="udp")
        ssh_port = builder.create_port("10.0.0.2", "22", service="ssh", product="OpenSSH 8.2")
        
        # DNS tools
        dns_enum_tool = builder.create_tool("dns_enum", wave="Discovery", status="completed",
                                          scope="10.0.0.2", ip="10.0.0.2")
        
        # DNS vulnerabilities
        zone_transfer = builder.create_defect("DNS Zone Transfer Allowed",
                                            impact="Medium", cvss=5.3, type=["DNS"],
                                            description="DNS server allows unauthorized zone transfers")
        dns_cache_poison = builder.create_defect("DNS Cache Poisoning Vulnerability",
                                                impact="High", cvss=7.1, type=["DNS"],
                                                description="DNS server vulnerable to cache poisoning attacks")
        
        return {
            "scenario": "dns_server",
            "ip_id": ip_id,
            "ports": [dns_tcp_port, dns_udp_port, ssh_port],
            "tools": [dns_enum_tool],
            "defects": [zone_transfer, dns_cache_poison],
            "primary_ip": "10.0.0.2"
        }
    
    elif scenario_name == "ftp_server":
        # Create an FTP server scenario
        ip_id = builder.create_ip("192.168.3.50", ["DMZ"], notes="File transfer server")
        
        # FTP ports
        ftp_port = builder.create_port("192.168.3.50", "21", service="ftp", product="vsftpd 3.0.3")
        ftps_port = builder.create_port("192.168.3.50", "990", service="ftps", product="vsftpd 3.0.3")
        sftp_port = builder.create_port("192.168.3.50", "22", service="ssh", product="OpenSSH 8.2")
        
        # FTP tools
        ftp_enum_tool = builder.create_tool("ftp_enum", wave="Discovery", status="completed",
                                          scope="192.168.3.50", ip="192.168.3.50")
        
        # FTP vulnerabilities
        anon_login = builder.create_defect("Anonymous FTP Login Allowed",
                                         impact="Medium", cvss=5.3, type=["FTP"],
                                         description="FTP server allows anonymous login with read/write access")
        ftp_bounce = builder.create_defect("FTP Bounce Attack",
                                         impact="Medium", cvss=6.4, type=["FTP"],
                                         description="FTP server vulnerable to bounce attacks")
        
        return {
            "scenario": "ftp_server",
            "ip_id": ip_id,
            "ports": [ftp_port, ftps_port, sftp_port],
            "tools": [ftp_enum_tool],
            "defects": [anon_login, ftp_bounce],
            "primary_ip": "192.168.3.50"
        }
    
    else:
        available_scenarios = ["web_server", "domain_controller", "database_server", 
                             "mail_server", "dns_server", "ftp_server"]
        raise ValueError(f"Unknown scenario: {scenario_name}. Available scenarios: {available_scenarios}")


# Helper functions for scenario validation
def assert_scenario_created(db: ThrowableDBClient, scenario_data: dict):
    """
    Assert that a test scenario was created correctly.
    
    Args:
        db: ThrowableDBClient instance
        scenario_data: Dictionary returned from create_test_scenario
    """
    from bson import ObjectId
    
    # Check that IP exists
    ip_id = scenario_data["ip_id"]
    found_ip = db.find("ips", {"_id": ObjectId(ip_id)}, multi=False)
    assert found_ip is not None, f"IP with ID {ip_id} not found"
    assert found_ip["ip"] == scenario_data["primary_ip"]
    
    # Check that all ports exist
    for port_id in scenario_data["ports"]:
        found_port = db.find("ports", {"_id": ObjectId(port_id)}, multi=False)
        assert found_port is not None, f"Port with ID {port_id} not found"
        assert found_port["ip"] == scenario_data["primary_ip"]
    
    # Check that all tools exist
    for tool_id in scenario_data["tools"]:
        found_tool = db.find("tools", {"_id": ObjectId(tool_id)}, multi=False)
        assert found_tool is not None, f"Tool with ID {tool_id} not found"
    
    # Check that all defects exist
    for defect_id in scenario_data["defects"]:
        found_defect = db.find("defects", {"_id": ObjectId(defect_id)}, multi=False)
        assert found_defect is not None, f"Defect with ID {defect_id} not found"


def get_scenario_summary(scenario_data: dict) -> str:
    """
    Get a human-readable summary of a created scenario.
    
    Args:
        scenario_data: Dictionary returned from create_test_scenario
        
    Returns:
        str: Human-readable summary
    """
    summary = f"Scenario: {scenario_data['scenario']}\n"
    summary += f"Primary IP: {scenario_data['primary_ip']}\n"
    summary += f"Ports created: {len(scenario_data['ports'])}\n"
    summary += f"Tools created: {len(scenario_data['tools'])}\n"
    summary += f"Defects created: {len(scenario_data['defects'])}\n"
    return summary


@pytest.fixture
def test_data_builder(throwable_db_with_data) -> TestDataBuilder:
    """
    Fixture providing a TestDataBuilder instance with scenario creation capabilities.
    
    This combines the throwable database with the data builder and scenario creation
    functions for comprehensive test data setup.
    
    Returns:
        TestDataBuilder: Configured builder with database access
        
    Example:
        def test_complex_scenario(test_data_builder):
            scenario = create_test_scenario(test_data_builder, "web_server")
            assert_scenario_created(test_data_builder.db, scenario)
            # Test scenario-specific logic...
    """
    if isinstance(throwable_db_with_data, tuple):
        db, _ = throwable_db_with_data
    else:
        db = throwable_db_with_data
    return TestDataBuilder(db)
