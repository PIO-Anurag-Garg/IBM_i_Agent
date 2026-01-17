import os
import sys
from dotenv import load_dotenv

load_dotenv()

print("=" * 70)
print("MAPEPIRE CONNECTION DIAGNOSTIC")
print("=" * 70)

# Check environment variables
print("\n1️⃣ Checking Environment Variables...")
print("-" * 70)

required_vars = ["IBMI_HOST", "IBMI_PORT", "IBMI_USER", "IBMI_PASSWORD"]
env_ok = True

for var in required_vars:
    value = os.getenv(var)
    if value:
        if "PASSWORD" in var:
            print(f"✅ {var}: ****** (hidden)")
        else:
            print(f"✅ {var}: {value}")
    else:
        print(f"❌ {var}: NOT SET")
        env_ok = False

if not env_ok:
    print("\n❌ Missing environment variables. Check your .env file.")
    sys.exit(1)

# Check network connectivity
print("\n2️⃣ Testing Network Connectivity...")
print("-" * 70)

import socket

host = os.getenv("IBMI_HOST")
port = int(os.getenv("IBMI_PORT", "8076"))

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    result = sock.connect_ex((host, port))
    sock.close()
    
    if result == 0:
        print(f"✅ Port {port} is OPEN on {host}")
    else:
        print(f"❌ Port {port} is CLOSED on {host}")
        print(f"\nTroubleshooting:")
        print(f"  - Verify Mapepire server is running on IBM i")
        print(f"  - Check firewall rules")
        print(f"  - Verify port number is correct (default: 8076)")
        sys.exit(1)
except socket.gaierror:
    print(f"❌ Cannot resolve hostname: {host}")
    print(f"\nCheck:")
    print(f"  - Hostname/IP is correct in .env")
    print(f"  - DNS is working")
    sys.exit(1)
except Exception as e:
    print(f"❌ Network error: {e}")
    sys.exit(1)

# Test HTTPS/TLS connection
print("\n3️⃣ Testing HTTPS/TLS Connection...")
print("-" * 70)

import ssl
import urllib.request

url = f"https://{host}:{port}"

try:
    # Try with certificate verification disabled
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    req = urllib.request.Request(url)
    response = urllib.request.urlopen(req, context=context, timeout=10)
    
    print(f"✅ HTTPS connection successful")
    print(f"   Status: {response.status}")
    print(f"   URL: {url}")
    
except urllib.error.URLError as e:
    print(f"❌ HTTPS connection failed: {e.reason}")
    if "certificate" in str(e.reason).lower():
        print(f"\n   This might be a certificate issue.")
        print(f"   Solution: Set ignoreUnauthorized: True in credentials")
except Exception as e:
    print(f"❌ HTTPS error: {e}")

# Test Mapepire connection
print("\n4️⃣ Testing Mapepire Connection...")
print("-" * 70)

try:
    from mapepire_python import connect
    
    creds = {
        "host": host,
        "port": port,
        "user": os.getenv("IBMI_USER"),
        "password": os.getenv("IBMI_PASSWORD"),
        "ignoreUnauthorized": True,  # Important for self-signed certs
    }
    
    print(f"Connecting to {host}:{port}...")
    print(f"User: {creds['user']}")
    print(f"Ignore SSL cert: {creds['ignoreUnauthorized']}")
    
    with connect(creds) as conn:
        print("✅ Mapepire connection successful!")
        
        # Test a simple query
        print("\n5️⃣ Testing SQL Query...")
        print("-" * 70)
        
        with conn.execute("SELECT CURRENT_SERVER, CURRENT_USER, CURRENT_TIMESTAMP FROM SYSIBM.SYSDUMMY1") as cur:
            result = cur.fetchone()
            print(f"✅ Query executed successfully!")
            print(f"   Server: {result[0]}")
            print(f"   User: {result[1]}")
            print(f"   Timestamp: {result[2]}")
    
    print("\n" + "=" * 70)
    print("✅ ALL TESTS PASSED - Mapepire is working!")
    print("=" * 70)
    
except ImportError:
    print("❌ mapepire_python not installed")
    print("\nInstall with: pip install mapepire-python")
    sys.exit(1)
    
except Exception as e:
    print(f"❌ Mapepire connection failed!")
    print(f"   Error type: {type(e).__name__}")
    print(f"   Error message: {e}")
    
    print("\n" + "=" * 70)
    print("TROUBLESHOOTING GUIDE")
    print("=" * 70)
    
    error_str = str(e).lower()
    
    if "connection refused" in error_str:
        print("\n🔴 Connection Refused")
        print("   Possible causes:")
        print("   1. Mapepire server is not running")
        print("   2. Wrong port number")
        print("   3. Firewall blocking connection")
        print("\n   On IBM i, run:")
        print("   NETSTAT *CNN")
        print("   Look for port 8076 in LISTEN state")
        
    elif "timeout" in error_str:
        print("\n🔴 Connection Timeout")
        print("   Possible causes:")
        print("   1. Firewall blocking traffic")
        print("   2. Incorrect hostname/IP")
        print("   3. Network routing issue")
        
    elif "authentication" in error_str or "password" in error_str:
        print("\n🔴 Authentication Failed")
        print("   Possible causes:")
        print("   1. Incorrect username or password")
        print("   2. User profile doesn't exist on IBM i")
        print("   3. User profile disabled")
        print("\n   On IBM i, verify:")
        print("   DSPUSRPRF USRPRF(youruser)")
        
    elif "ssl" in error_str or "certificate" in error_str:
        print("\n🔴 SSL/Certificate Issue")
        print("   Solution:")
        print("   Add 'ignoreUnauthorized': True to credentials")
        print("   Already set in this test - check your main code")
        
    else:
        print("\n🔴 Unknown Error")
        print("   Full error details above")
        print("\n   Common fixes:")
        print("   1. Restart Mapepire server on IBM i")
        print("   2. Check IBM i job logs: DSPJOBLOG")
        print("   3. Verify Mapepire config in /www/mapepire/server/config")
    
    print("\n" + "=" * 70)
    sys.exit(1)