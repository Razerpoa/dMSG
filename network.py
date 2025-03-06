import asyncio
import json
import hashlib
import base64
from typing import List, Tuple, Dict
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from crypto import DoubleRatchet  # Using the improved version
from blockchain import Block, Blockchain

class P2PNode:
    def __init__(self, host: str, port: int = 8333, max_peers: int = 8, k: int = 20, seeds: List[Tuple[str, int]] = None):
        self.host = host
        self.port = port
        self.max_peers = max_peers
        self.peers: List[Tuple[str, int]] = []
        self.known_peers = set()
        self.seed_nodes = seeds or []
        self.running = False
        self.server = None
        
        self.blockchain = Blockchain()
        self.pending_messages: List[Dict] = []
        self.seen_messages: set = set()

        # Encryption and identity
        self.x25519_priv = x25519.X25519PrivateKey.generate()
        self.x25519_pub = self.x25519_priv.public_key()
        self.ed25519_priv = ed25519.Ed25519PrivateKey.generate()
        self.ed25519_pub = self.ed25519_priv.public_key()
        self.public_address = self.ed25519_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ).hex()
        self.ratchets: Dict[str, DoubleRatchet] = {}  # Keyed by public_address
        self.peer_public_keys: Dict[Tuple[str, int], x25519.X25519PublicKey] = {}
        self.peer_addresses: Dict[Tuple[str, int], str] = {}

        # DHT
        self.k = k
        self.routing_table: List[List[Tuple[str, int, str]]] = [[] for _ in range(256)]
        self.dht_store: Dict[str, Tuple[str, int]] = {self.public_address: (self.host, self.port)}

    def xor_distance(self, addr1: str, addr2: str) -> int:
        a1 = int(addr1, 16)
        a2 = int(addr2, 16)
        return a1 ^ a2

    def bucket_index(self, distance: int) -> int:
        if distance == 0:
            return 0
        return min(255, distance.bit_length() - 1)

    def update_routing_table(self, peer: Tuple[str, int], address: str):
        distance = self.xor_distance(self.public_address, address)
        bucket_idx = self.bucket_index(distance)
        bucket = self.routing_table[bucket_idx]
        peer_entry = (peer[0], peer[1], address)
        
        if peer_entry in bucket:
            bucket.remove(peer_entry)
            bucket.append(peer_entry)
        elif len(bucket) < self.k:
            bucket.append(peer_entry)
        else:
            bucket.pop(0)
            bucket.append(peer_entry)

    async def find_node(self, target_address: str) -> Tuple[str, int] | None:
        closest = [(self.host, self.port, self.public_address)]
        visited = set()

        while closest:
            peer_host, peer_port, peer_addr = closest.pop(0)
            if peer_addr == target_address:
                return (peer_host, peer_port)
            if (peer_host, peer_port) in visited:
                continue
            visited.add((peer_host, peer_port))

            try:
                reader, writer = await asyncio.open_connection(peer_host, peer_port)
                await self.send_message(writer, {
                    "type": "FIND_NODE",
                    "target": target_address,
                    "sender": (self.host, self.port)
                })
                data = await reader.read(1024)
                response = json.loads(data.decode())
                if response["type"] == "NODE_FOUND":
                    for node in response["nodes"]:
                        host, port, addr = node
                        if addr == target_address:
                            writer.close()
                            await writer.wait_closed()
                            return (host, port)
                        distance = self.xor_distance(addr, target_address)
                        closest.append((host, port, addr))
                        self.update_routing_table((host, port), addr)
                writer.close()
                await writer.wait_closed()
            except Exception as e:
                print(f"Error querying {peer_host}:{peer_port}: {e}")
            closest.sort(key=lambda x: self.xor_distance(x[2], target_address))
            closest = closest[:self.k]
        return None

    async def start(self):
        self.running = True
        self.server = await asyncio.start_server(self.handle_client, self.host, self.port)
        print(f"Node started at {self.host}:{self.port} with address {self.public_address}")
        await self.discover_peers()
        await self.connect_to_peers()
        asyncio.create_task(self.mine_blocks())
        async with self.server:
            await self.server.serve_forever()

    async def stop(self):
        self.running = False
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        print("Node stopped")

    async def discover_peers(self):
        for seed in self.seed_nodes:
            if len(self.peers) < self.max_peers and seed not in self.peers and seed != (self.host, self.port):
                self.peers.append(seed)
                self.known_peers.add(seed)

    async def connect_to_peers(self):
        for peer in self.peers[:]:
            try:
                reader, writer = await asyncio.open_connection(peer[0], peer[1])
                print(f"Connected to peer {peer}")
                pub_key = self.x25519_pub.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                ).hex()
                await self.send_message(writer, {
                    "type": "VERSION",
                    "node": (self.host, self.port),
                    "pub_key": pub_key,
                    "address": self.public_address
                })
                asyncio.create_task(self.handle_reader(reader, writer, peer))
            except Exception as e:
                print(f"Failed to connect to {peer}: {e}")
                if peer in self.peers:
                    self.peers.remove(peer)

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info('peername')
        print(f"New connection from {addr}")
        await self.handle_reader(reader, writer, addr)

    async def handle_reader(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, addr: Tuple[str, int]):
        while self.running:
            try:
                data = await reader.read(4096)  # Increased buffer size for larger messages
                if not data:
                    break
                message = json.loads(data.decode())
                print(f"Received bytes from {addr}: {message}")
                await self.process_message(message, addr, writer)
            except Exception as e:
                print(f"Error reading from {addr}: {e}")
                break
        writer.close()
        await writer.wait_closed()

    async def process_message(self, message: Dict, addr: Tuple[str, int], writer: asyncio.StreamWriter):
        msg_type = message.get("type")
        msg_id = hashlib.sha256(json.dumps(message).encode()).hexdigest()

        if msg_id in self.seen_messages:
            return

        self.seen_messages.add(msg_id)

        if msg_type == "VERSION":
            peer = tuple(message["node"])
            if peer not in self.peers and len(self.peers) < self.max_peers and peer != (self.host, self.port):
                self.peers.append(peer)
                self.known_peers.add(peer)
            
            # Process peer's X25519 public key
            their_x25519_pub = x25519.X25519PublicKey.from_public_bytes(
                bytes.fromhex(message["pub_key"])
            )
            self.peer_public_keys[peer] = their_x25519_pub
            peer_address = message["address"]
            self.peer_addresses[peer] = peer_address
            self.update_routing_table(peer, peer_address)
            self.dht_store[peer_address] = peer
            
            # Generate shared secret using X3DH (extended triple DH)
            shared_secret = self.x25519_priv.exchange(their_x25519_pub)
            
            # Initialize Double Ratchet with the shared secret
            if peer_address not in self.ratchets:
                self.ratchets[peer_address] = DoubleRatchet(shared_secret=shared_secret)
            
            # Respond with our public key
            pub_key = self.x25519_pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ).hex()
            await self.send_message(writer, {
                "type": "PEERS",
                "peers": list(self.known_peers),
                "pub_key": pub_key,
                "address": self.public_address
            })

        elif msg_type == "PEERS":
            for peer in message["peers"]:
                peer_tuple = tuple(peer)
                if peer_tuple not in self.known_peers and len(self.peers) < self.max_peers and peer_tuple != (self.host, self.port):
                    self.known_peers.add(peer_tuple)
                    self.peers.append(peer_tuple)

        elif msg_type == "FIND_NODE":
            target = message["target"]
            if target in self.dht_store:
                await self.send_message(writer, {
                    "type": "NODE_FOUND",
                    "nodes": [(self.dht_store[target][0], self.dht_store[target][1], target)]
                })
            else:
                closest = []
                for bucket in self.routing_table:
                    for host, port, addr in bucket:
                        if (host, port) != (self.host, self.port):
                            closest.append((host, port, addr))
                closest.sort(key=lambda x: self.xor_distance(x[2], target))
                await self.send_message(writer, {
                    "type": "NODE_FOUND",
                    "nodes": closest[:self.k]
                })

        elif msg_type == "NEW_MESSAGE":
            # Extract message components
            sender_addr = message["sender_addr"]
            recipient_addr = message["recipient_addr"]
            encrypted_msg = message["encrypted_msg"]
            sig = bytes.fromhex(message["sig"])
            
            try:
                # Verify message signature using the sender's Ed25519 key
                sender_pub_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(sender_addr))
                # Create signature data that includes all the necessary components
                sig_data = f"{sender_addr}{recipient_addr}{json.dumps(encrypted_msg)}".encode()
                sender_pub_key.verify(sig, sig_data)
                
                # Process verified message
                if message not in self.pending_messages:
                    self.pending_messages.append({
                        "sender_addr": sender_addr,
                        "recipient_addr": recipient_addr,
                        "encrypted_msg": encrypted_msg,
                        "sig": message["sig"]
                    })
                    print(f"Verified message from {sender_addr} to {recipient_addr}")
                    await self.broadcast_message(message)
            except Exception as e:
                print(f"Signature verification failed: {e}")

        elif msg_type == "NEW_BLOCK":
            block = Block(message["previous_hash"], message["messages"])
            block.nonce = message["nonce"]
            block.hash = block.compute_hash()
            if self.blockchain.add_block(block):
                print(f"Accepted new block with hash {block.hash}")
                self.pending_messages = [m for m in self.pending_messages if m not in block.messages]

    async def send_message(self, writer: asyncio.StreamWriter, message: Dict):
        try:
            writer.write(json.dumps(message).encode())
            await writer.drain()
        except Exception as e:
            print(f"Error sending message: {e}")

    async def broadcast_message(self, message: Dict):
        msg_id = hashlib.sha256(json.dumps(message).encode()).hexdigest()
        if msg_id in self.seen_messages:
            return
        self.seen_messages.add(msg_id)
        
        for peer in self.peers[:]:
            if peer != (self.host, self.port):
                try:
                    reader, writer = await asyncio.open_connection(peer[0], peer[1])
                    await self.send_message(writer, message)
                    writer.close()
                    await writer.wait_closed()
                except Exception as e:
                    print(f"Failed to broadcast to {peer}: {e}")

    async def mine_blocks(self):
        while self.running:
            if self.pending_messages:
                block = Block(self.blockchain.chain[-1].hash, self.pending_messages[:10])
                block.mine(difficulty=4)
                if self.blockchain.add_block(block):
                    print(f"Mined block with hash {block.hash}")
                    self.pending_messages = self.pending_messages[10:]
                    await self.broadcast_message({
                        "type": "NEW_BLOCK",
                        "previous_hash": block.previous_hash,
                        "messages": block.messages,
                        "nonce": block.nonce,
                        "hash": block.hash
                    })
            await asyncio.sleep(1)

    def get_messages(self, public_address: str) -> List[str]:
        """Retrieve and decrypt messages for a given address"""
        messages = []
        for msg in self.blockchain.get_messages_for_address(public_address):
            sender_addr = msg["sender_addr"]
            if sender_addr not in self.ratchets:
                print(f"No ratchet for sender {sender_addr}. Skipping message.")
                continue
            
            ratchet = self.ratchets[sender_addr]
            try:
                # Get the encrypted message dictionary
                encrypted_msg = msg["encrypted_msg"]
                
                # Deserialize the message parts from JSON to bytes where needed
                msg_dict = {
                    'dh_public': bytes.fromhex(encrypted_msg['dh_public']),
                    'counter': encrypted_msg['counter'],
                    'nonce': bytes.fromhex(encrypted_msg['nonce']),
                    'tag': bytes.fromhex(encrypted_msg['tag']),
                    'ciphertext': bytes.fromhex(encrypted_msg['ciphertext'])
                }
                
                # Decrypt the message
                plaintext = ratchet.decrypt_message(msg_dict)
                if plaintext:
                    messages.append(plaintext.decode())
                else:
                    print(f"Could not decrypt message from {sender_addr}")
            except Exception as e:
                print(f"Failed to decrypt message from {sender_addr}: {e}")
        
        return messages

    async def send_chat(self, recipient_address: str, message: str):
        """Send an encrypted chat message to a recipient"""
        # Find the recipient in the network
        recipient_peer = await self.find_node(recipient_address)
        if not recipient_peer:
            print(f"Recipient {recipient_address} not found in network")
            return
        
        # Ensure we have a ratchet for this recipient
        if recipient_address not in self.ratchets:
            print(f"No ratchet initialized for {recipient_address}. Ensure key exchange completed.")
            return
        
        # Encrypt the message
        ratchet = self.ratchets[recipient_address]
        encrypted_msg = ratchet.encrypt_message(message.encode())
        
        # Convert binary data to hex strings for JSON serialization
        serialized_msg = {
            'dh_public': encrypted_msg['dh_public'].hex(),
            'counter': encrypted_msg['counter'],
            'nonce': encrypted_msg['nonce'].hex(),
            'tag': encrypted_msg['tag'].hex(),
            'ciphertext': encrypted_msg['ciphertext'].hex()
        }
        
        # Create message signature
        sig_data = f"{self.public_address}{recipient_address}{json.dumps(serialized_msg)}".encode()
        sig = self.ed25519_priv.sign(sig_data).hex()
        
        # Prepare the message packet
        msg = {
            "type": "NEW_MESSAGE",
            "sender_addr": self.public_address,
            "recipient_addr": recipient_address,
            "encrypted_msg": serialized_msg,
            "sig": sig
        }
        
        print(f"Sending chat to {recipient_address}: {message}")
        await self.broadcast_message(msg)