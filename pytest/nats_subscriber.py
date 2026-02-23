#!/usr/bin/env python3
import asyncio
import nats
from nats.errors import Error as NATSError
import json
import sys

async def main():
    nats_url = "nats://localhost:4222"  
    subject = "scan.port.enriched"
    queue_name = "exemple_queue" 

    try:
        nc = await nats.connect(nats_url, name="python-sub")
        done = asyncio.Future()
        async def message_handler(msg):
            data = msg.data.decode()
            try:
                obj = json.loads(data)
                if obj["service"] == "ssh":
                    if obj["data"] != None:
                        print(f"{json.dumps(obj, indent=2, ensure_ascii=False)}")           
            except json.JSONDecodeError:
                pass  

        await nc.subscribe(
            subject=subject,
            queue=queue_name,
            cb=message_handler
        )

        await done

    except NATSError as e:
        print(f"nats error : {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("exiting ...")
    except Exception as e:
        print(f"error : {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        if 'nc' in locals():
            await nc.close()
            
if __name__ == "__main__":
    asyncio.run(main())