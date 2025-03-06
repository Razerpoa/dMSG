import hashlib
import json
from typing import List, Dict
import asyncio

class Block:
    def __init__(self, previous_hash: str, messages: List[Dict]):
        self.previous_hash = previous_hash
        self.messages = messages  # List of [sender_addr, recipient_addr, enc_msg, sig]
        self.timestamp = asyncio.get_event_loop().time()
        self.nonce = 0
        self.hash = self.compute_hash()

    def compute_hash(self) -> str:
        """Compute SHA-256 hash of the block."""
        block_string = f"{self.previous_hash}{json.dumps(self.messages)}{self.timestamp}{self.nonce}"
        return hashlib.sha256(block_string.encode()).hexdigest()

    def mine(self, difficulty: int = 4):
        """Mine the block with Proof of Work."""
        target = "0" * difficulty
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.compute_hash()

class Blockchain:
    def __init__(self):
        self.chain: List[Block] = [self.create_genesis_block()]

    def create_genesis_block(self) -> Block:
        """Create the genesis block."""
        return Block("0" * 64, [])

    def add_block(self, block: Block) -> bool:
        """Add a block if valid."""
        if self.is_valid_block(block, self.chain[-1]):
            self.chain.append(block)
            return True
        return False

    def is_valid_block(self, block: Block, previous_block: Block) -> bool:
        """Validate a block."""
        if block.previous_hash != previous_block.hash:
            print("Invalid previous hash")
            return False
        if block.hash != block.compute_hash():
            print("Invalid block hash")
            return False
        if block.hash[:4] != "0000":  # Assuming difficulty=4
            print("Block not mined correctly")
            return False
        return True

    def get_messages_for_address(self, address: str) -> List[Dict]:
        """Retrieve messages for a given address."""
        messages = []
        for block in self.chain:
            for msg in block.messages:
                if msg["recipient_addr"] == address:
                    messages.append(msg)
        return messages