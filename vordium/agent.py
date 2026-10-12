import os
import asyncio
import requests
from web3 import Web3
from .network import get_network
from .wallet import Wallet


class Agent:
    """
    Vordium AI Agent

    Usage:
        agent = Agent()
        print(agent.address)
        print(agent.balance)
        await agent.run()
    """

    def __init__(self, private_key: str = None):
        self._net = get_network()  # resolve_network() at client init
        self._w3 = Web3(Web3.HTTPProvider(self._net.rpc_url))

        if private_key:
            self._wallet = Wallet.from_key(private_key)
        elif os.getenv('VORDIUM_PRIVATE_KEY'):
            self._wallet = Wallet.from_key(os.getenv('VORDIUM_PRIVATE_KEY'))
        else:
            self._wallet = Wallet.create()
            print("New agent wallet created!")
            print(f"Address:     {self._wallet.address}")
            print(f"Private Key: {self._wallet.private_key}")
            print("Save this to your .env file:")
            print(f"VORDIUM_PRIVATE_KEY={self._wallet.private_key}")

    @property
    def address(self) -> str:
        return self._wallet.address

    @property
    def private_key(self) -> str:
        return self._wallet.private_key

    @property
    def balance(self) -> float:
        from .config import native_balance
        return native_balance(self.address)

    @property
    def block(self) -> int:
        return self._w3.eth.block_number

    def send(self, to: str, amount: float) -> str:
        """Send VORD to an address."""
        nonce = self._w3.eth.get_transaction_count(self.address)
        tx = {
            'to': Web3.to_checksum_address(to),
            'value': self._w3.to_wei(amount, 'ether'),
            'gas': 21000,
            'gasPrice': self._w3.eth.gas_price,
            'nonce': nonce,
            'chainId': self._net.chain_id
        }
        signed = self._w3.eth.account.sign_transaction(tx, self.private_key)
        raw = getattr(signed, 'raw_transaction', None) or signed.rawTransaction
        tx_hash = self._w3.eth.send_raw_transaction(raw)
        tx_hex = tx_hash.hex()
        self._w3.eth.wait_for_transaction_receipt(tx_hash)
        print(f"Sent {amount} VORD")
        print(f"TX: {self._net.explorer_url}/tx/{tx_hex}")
        return tx_hex

    def is_healthy(self) -> bool:
        try:
            return self._w3.is_connected() and self.block > 0
        except Exception:
            return False

    async def run(self, strategy=None, interval: float = 1.0):
        """Run agent autonomously."""
        print(f"\nAgent: {self.address}")
        print(f"Balance: {self.balance} VORD")
        print(f"Block: {self.block:,}")
        status = 'Healthy' if self.is_healthy() else 'Unhealthy'
        print(f"Status: {status}")
        print("\nRunning... (Ctrl+C to stop)\n")

        while True:
            try:
                if strategy:
                    await strategy(self)
                else:
                    print(f"Block {self.block:,} | {self.balance:.4f} VORD")
                await asyncio.sleep(interval)
            except KeyboardInterrupt:
                print("\nAgent stopped.")
                break
            except Exception as e:
                print(f"Error: {e}")
                await asyncio.sleep(5)

    def register_on_chain(self, name: str, strategy_type: str = "trading") -> str:
        """Not available: agents are not registered on a contract.

        An agent on Vordium is an account operated through a session key with
        opt-in caps that the account sets -- there is no registry to register
        with. Authority is granted by signing ``SetAgentCaps`` / ``SetAgentMode``
        (see :mod:`vordium.eip712`).
        """
        raise NotImplementedError(
            "Agents are not registered on-chain. Vordium uses native session "
            "keys with caps the account sets (SetAgentCaps/SetAgentMode); the engine "
            "route for those ops is not live yet."
        )

    def is_registered(self) -> bool:
        """Always False -- there is no agent registry. See register_on_chain."""
        return False

    def get_registration(self):
        """Always None -- there is no agent registry. See register_on_chain."""
        return None


    def __repr__(self):
        return f"Agent(address={self.address})"
