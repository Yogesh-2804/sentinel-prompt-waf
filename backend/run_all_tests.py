import sys
import os

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

import pytest

if __name__ == "__main__":
    print("=========================================================")
    print("      SentinelPrompt WAF - Automated Test Suite        ")
    print("=========================================================\n")
    sys.stdout.flush()
    
    # Run pytest directly with verbose output and stdout streaming
    test_dir = os.path.join(os.path.dirname(__file__), "tests")
    exit_code = pytest.main(["-v", test_dir])
    
    print("\n=========================================================")
    if exit_code == 0:
        print("  RESULT: ALL 16 TESTS PASSED SUCCESSFULLY! [100% OK]   ")
    else:
        print(f"  RESULT: TEST SUITE FINISHED WITH EXIT CODE {exit_code}   ")
    print("=========================================================")
    sys.stdout.flush()
    sys.exit(exit_code)
