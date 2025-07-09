#!/usr/bin/env python3
import time
import subprocess
import threading
from protoinspector.injector import UnrealInjector
from protoinspector.mock_server import MockUnrealServer

def test_full_system():
    print("[*] Starting Unreal Engine Protocol Test")
    
    # Start mock server
    server = MockUnrealServer()
    server_thread = threading.Thread(target=server.start)
    server_thread.daemon = True
    server_thread.start()
    print("[✓] Mock UE server started on 127.0.0.1:7777")
    
    time.sleep(1)  # Let server start
    
    # Initialize injector
    injector = UnrealInjector()
    
    # Test sequence
    print("\n[*] Testing UE4 Protocol Sequence:")
    
    # 1. Send Hello
    print("  1. Sending Hello packet...")
    result = injector.inject_hello("127.0.0.1", 7777)
    print(f"     Result: {'✓' if result.success else '✗'}")
    time.sleep(0.5)
    
    # 2. Send Login
    print("  2. Sending Login packet...")
    result = injector.inject_login("127.0.0.1", 7777, "TestPlayer")
    print(f"     Result: {'✓' if result.success else '✗'}")
    time.sleep(0.5)
    
    # 3. Send movement updates
    print("  3. Sending movement updates...")
    for i in range(5):
        x = 1000 + i * 10
        y = 2000 + i * 10
        z = 100
        result = injector.inject_movement("127.0.0.1", 7777, x, y, z)
        print(f"     Movement {i+1}: {'✓' if result.success else '✗'} - Pos({x}, {y}, {z})")
        time.sleep(0.2)
    
    # 4. Send RPC
    print("  4. Sending RPC call...")
    result = injector.inject_rpc("127.0.0.1", 7777, 0x100, b"TestRPCData")
    print(f"     Result: {'✓' if result.success else '✗'}")
    
    print("\n[*] Test complete! Check packet captures.")

if __name__ == "__main__":
    test_full_system()