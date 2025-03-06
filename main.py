import asyncio
import sys
import os
import json
import time
from datetime import datetime
from network import P2PNode

class ChatInterface:
    def __init__(self, node: P2PNode):
        self.node = node
        self.contacts = {}
        self.load_contacts()
        self.command_history = []
        self.history_index = 0
        self.unread_messages = set()
        
    def load_contacts(self):
        """Load contacts from a JSON file"""
        try:
            if os.path.exists("contacts.json"):
                with open("contacts.json", "r") as f:
                    self.contacts = json.load(f)
                print(f"Loaded {len(self.contacts)} contacts")
        except Exception as e:
            print(f"Error loading contacts: {e}")
            
    def save_contacts(self):
        """Save contacts to a JSON file"""
        try:
            with open("contacts.json", "w") as f:
                json.dump(self.contacts, f, indent=2)
        except Exception as e:
            print(f"Error saving contacts: {e}")
            
    def add_contact(self, name, address):
        """Add a contact to the address book"""
        self.contacts[name] = address
        self.save_contacts()
        print(f"Added contact: {name} ({address})")
        
    def display_help(self):
        """Display help information"""
        help_text = """
Available commands:
  /send <contact|address> <message> - Send a message to a contact or address
  /check                           - Check for new messages
  /contacts                        - View your contacts
  /add <name> <address>            - Add a new contact
  /find <address>                  - Find a node in the network
  /info                            - Show node information
  /history                         - Show message history
  /clear                           - Clear the screen
  /help                            - Show this help
  /exit                            - Exit the application
"""
        print(help_text)
        
    async def handle_command(self, command):
        """Handle a chat command"""
        self.command_history.append(command)
        self.history_index = len(self.command_history)
        
        parts = command.split()
        if not parts:
            return
            
        cmd = parts[0].lower()
        
        if cmd == "/send" and len(parts) >= 3:
            recipient = parts[1]
            message = " ".join(parts[2:])
            # Check if recipient is a contact name
            if recipient in self.contacts:
                recipient_address = self.contacts[recipient]
                print(f"Sending to {recipient} ({recipient_address})")
            else:
                recipient_address = recipient
                
            try:
                await self.node.send_chat(recipient_address, message)
                print(f"Message sent at {datetime.now().strftime('%H:%M:%S')}")
            except Exception as e:
                print(f"Error sending message: {e}")
                
        elif cmd == "/check":
            await self.check_messages()
            
        elif cmd == "/contacts":
            if not self.contacts:
                print("No contacts saved")
            else:
                print("\nContacts:")
                for name, address in self.contacts.items():
                    print(f"  {name}: {address}")
                print()
                
        elif cmd == "/add" and len(parts) == 3:
            name, address = parts[1], parts[2]
            self.add_contact(name, address)
            
        elif cmd == "/find" and len(parts) == 2:
            address = parts[1]
            print(f"Searching for node with address {address}...")
            result = await self.node.find_node(address)
            if result:
                host, port = result
                print(f"Node found at {host}:{port}")
            else:
                print("Node not found in the network")
                
        elif cmd == "/info":
            print(f"\nNode Information:")
            print(f"  Host: {self.node.host}:{self.node.port}")
            print(f"  Public Address: {self.node.public_address}")
            print(f"  Connected Peers: {len(self.node.peers)}")
            print(f"  Blockchain Length: {len(self.node.blockchain.chain)}")
            print(f"  Pending Messages: {len(self.node.pending_messages)}")
            print()
            
        elif cmd == "/history":
            print("\nMessage History:")
            for address in self.node.blockchain.chain:
                messages = self.node.get_messages(self.node.public_address)
                for msg in messages:
                    print(f"  {msg}")
            print()
            
        elif cmd == "/clear":
            os.system('cls' if os.name == 'nt' else 'clear')
            
        elif cmd == "/help":
            self.display_help()
            
        elif cmd == "/exit":
            return False
            
        else:
            print("Unknown command. Type /help for available commands.")
            
        return True
        
    async def check_messages(self):
        """Check for new messages"""
        try:
            messages = self.node.get_messages(self.node.public_address)
            if messages:
                print("\nReceived messages:")
                for msg in messages:
                    if msg not in self.unread_messages:
                        print(f"  - {msg}")
                        self.unread_messages.add(msg)
                print()
            else:
                print("No new messages.")
        except Exception as e:
            print(f"Error checking messages: {e}")
            
    async def background_check(self):
        """Periodically check for new messages in the background"""
        while True:
            try:
                new_count = 0
                messages = self.node.get_messages(self.node.public_address)
                for msg in messages:
                    if msg not in self.unread_messages:
                        new_count += 1
                        self.unread_messages.add(msg)
                
                if new_count > 0:
                    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] You have {new_count} new message(s). Type /check to view them.")
                    print("> ", end="", flush=True)
            except Exception as e:
                print(f"Error in background check: {e}")
                
            await asyncio.sleep(10)  # Check every 10 seconds
            
async def run_node(host: str, seeds: list):
    # Initialize node with host IP and seed
    node = P2PNode(host=host, port=8333, seeds=seeds)
    asyncio.create_task(node.start())
    
    # Wait for node to connect
    await asyncio.sleep(5)
    print(f"Your public address: {node.public_address}")
    
    # Initialize chat interface
    chat = ChatInterface(node)
    
    # Start background message checking
    asyncio.create_task(chat.background_check())
    
    # Display help on startup
    chat.display_help()
    
    # Command loop
    running = True
    while running:
        try:
            print("> ", end="", flush=True)
            command = await asyncio.get_event_loop().run_in_executor(None, input)
            
            if command.strip():
                running = await chat.handle_command(command)
                
        except KeyboardInterrupt:
            print("\nExiting...")
            break
        except Exception as e:
            print(f"Error: {e}")
    
    print("Shutting down node...")
    await node.stop()
    print("Goodbye!")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python main.py <laptop1|laptop2|custom>")
        print("       For custom: python main.py custom <host_ip> <seed_ip> <seed_port>")
        sys.exit(1)
    
    if sys.argv[1] == "laptop1":
        host = "192.168.100.195"
        seeds = [("192.168.100.237", 8333)]
    elif sys.argv[1] == "laptop2":
        host = "192.168.100.237"
        seeds = [("192.168.100.195", 8333)]
    elif sys.argv[1] == "custom" and len(sys.argv) >= 5:
        host = sys.argv[2]
        seed_ip = sys.argv[3]
        seed_port = int(sys.argv[4])
        seeds = [(seed_ip, seed_port)]
    else:
        print("Use 'laptop1', 'laptop2', or 'custom <host_ip> <seed_ip> <seed_port>'")
        sys.exit(1)
    
    try:
        asyncio.run(run_node(host, seeds))
    except KeyboardInterrupt:
        print("\nExiting...")