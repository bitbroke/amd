import pytest
from unittest.mock import MagicMock, patch, mock_open
from engine.detective import Detective

@pytest.fixture
def detective():
    """Fixture to initialize Detective with a dummy path."""
    return Detective("fake_path.exe")

# --- String Scan Tests ---

def test_scan_strings_identifies_ipv4(detective):
    """Verifies that IPv4 addresses are correctly extracted from binary noise."""
    fake_content = b"Noise... 192.168.1.1 ...Noise"
    with patch("builtins.open", mock_open(read_data=fake_content)):
        results = detective._scan_strings()
        assert any("STR_IPv4_192.168.1.1" in r for r in results)

def test_scan_strings_identifies_url(detective):
    """Verifies that URLs are identified (matching the current regex domain-logic)."""
    fake_content = b"Check out http://malicious-site.com/payload"
    with patch("builtins.open", mock_open(read_data=fake_content)):
        results = detective._scan_strings()
        # Note: Current regex stops at the '/' before 'payload'
        assert any("STR_URL_http://malicious-site.com" in r for r in results)

def test_scan_strings_identifies_base64(detective):
    """
    Verifies Base64 detection with a string long enough (>40 chars) 
    to satisfy the {10,} regex requirement.
    """
    # 44 characters long
    encoded_val = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpBQkNERUZHSElKS0xNTk8=" 
    fake_content = f"Secret: {encoded_val}".encode()
    
    with patch("builtins.open", mock_open(read_data=fake_content)):
        results = detective._scan_strings()
        assert any(f"STR_Base64_{encoded_val}" in r for r in results)

# --- API Scan Tests (PE Analysis) ---

@patch("pefile.PE")
def test_scan_apis_detects_networking(mock_pe_class, detective):
    """Verifies that watched API calls in the PE structure are flagged."""
    # 1. Setup the mock hierarchy
    mock_pe = MagicMock()
    mock_import = MagicMock()
    mock_func = MagicMock()
    
    # 2. Configure the mock to mimic a PE import table
    mock_func.name = b"InternetOpenA"
    mock_import.imports = [mock_func]
    
    # Ensure the Detective's loop finds this list
    mock_pe.DIRECTORY_ENTRY_IMPORT = [mock_import]
    mock_pe_class.return_value = mock_pe

    results = detective._scan_apis()
    assert "API_InternetOpenA" in results

@patch("pefile.PE")
def test_scan_apis_no_imports(mock_pe_class, detective):
    """Covers the safety check for PEs with no Import Directory."""
    mock_pe = MagicMock()
    # Explicitly remove the attribute to test 'hasattr' check
    if hasattr(mock_pe, "DIRECTORY_ENTRY_IMPORT"):
        del mock_pe.DIRECTORY_ENTRY_IMPORT
        
    mock_pe_class.return_value = mock_pe

    results = detective._scan_apis()
    assert results == []

@patch("pefile.PE")
def test_scan_apis_exception_handling(mock_pe_class, detective):
    """Ensures that a corrupted PE file doesn't crash the engine."""
    mock_pe_class.side_effect = Exception("Corrupt PE")
    
    results = detective._scan_apis()
    assert results == []