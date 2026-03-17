
import sys
import os
sys.path.append(os.getcwd())
from dashboard.app import dashboard
import asyncio

async def test():
    try:
        res = await dashboard()
        print("Success")
    except Exception as e:
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test())
