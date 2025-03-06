import asyncio
import sys
from network import P2PNode

async def run_node(host: str, seeds: list):
    # Initialize node with host IP and seed
    node = P2PNode(host=host, port=8333, seeds=seeds)
    asyncio.create_task(node.start())
    
    # Wait for node to connect
    await asyncio.sleep(5)
    print(f"Your public address: {node.public_address}")
    
    # Simple CLI loop
    while True:
        try:
            command = input("Enter command (send/check/exit): ").strip().lower()
            if command == "send":
                recipient = input("Recipient public address: ").strip()
                message = input("Message: ").strip()
                await node.send_chat(recipient, message)
            elif command == "check":
                messages = node.get_messages(node.public_address)
                if messages:
                    print("Received messages:")
                    for msg in messages:
                        print(f"- {msg}")
                else:
                    print("No new messages.")
            elif command == "exit":
                break
            else:
                print("Commands: send, check, exit")
            await asyncio.sleep(1)  # Avoid hogging CPU
        except KeyboardInterrupt:
            break
    
    await node.stop()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python main.py <laptop1|laptop2>")
        sys.exit(1)
    
    if sys.argv[1] == "laptop1":
        host = "192.168.100.195"
        seeds = [("192.168.100.237", 8333)]
    elif sys.argv[1] == "laptop2":
        host = "192.168.100.237"
        seeds = [("192.168.100.195", 8333)]
    else:
        print("Use 'laptop1' or 'laptop2'")
        sys.exit(1)
    
    asyncio.run(run_node(host, seeds))