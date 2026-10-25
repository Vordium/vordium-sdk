import os
import asyncio
import warnings
import requests
from web3 import Web3
from .network import get_network
from .wallet import Wallet


class Agent:
    """
    Vordium AI Agent

    Usage:
        agent = Agent(key_file="~/.vordium/<address>.key")   # or Agent(private_key), or VORDIUM_PRIVATE_KEY
        print(agent.address)
        print(agent.balance)
        await agent.run()

    With no key at all, the agent makes a new key held only in memory and exposes its address; nothing is printed or
    written. Keep it with ``agent.save(path)`` (a new 0600 file) before you fund it.
    """

    def __init__(self, private_key: str = None, key_file: str = None):
        self._net = get_network()  # resolve_network() at client init
        self._w3 = Web3(Web3.HTTPProvider(self._net.rpc_url))

        if private_key and key_file:
            raise ValueError("pass private_key or key_file, not both")
        if private_key:
            self._wallet = Wallet.from_key(private_key)
        elif key_file:
            self._wallet = Wallet.load(key_file)
        elif os.getenv('VORDIUM_PRIVATE_KEY'):
            self._wallet = Wallet.from_key(os.getenv('VORDIUM_PRIVATE_KEY'))
        else:
            self._wallet = Wallet.create()
            warnings.warn(
                "no key given: this agent uses a new key held only in memory. "
                "Call agent.save(path) to keep it before you fund its address.",
                stacklevel=2)

    @property
    def address(self) -> str:
        return self._wallet.address

    @property
    def private_key(self) -> str:
        return self._wallet.private_key

    def save(self, path: str = None) -> str:
        """Write this agent's key to a NEW file with mode 0600 (default ``~/.vordium/<address>.key``); returns the path."""
        return self._wallet.save(path)

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
        """Not available here: an agent is not registered on a contract.

        An agent on Vordium is a key that signs as a session key of its owner. The
        owner registers it with a name (``RegisterAgentV2``) and limits it with a
        policy (``SetAgentPolicyV1``) and per-market limits
        (``SetAgentMarketLimit``); see :mod:`vordium.agent_ops` and
        :func:`vordium.eip712.sign_agent_op`.
        """
        raise NotImplementedError(
            "Agents are not registered on a contract. The owner registers an agent "
            "with RegisterAgentV2 (vordium.agent_ops) and sets its policy with "
            "SetAgentPolicyV1, signed by the owner key."
        )

    def is_registered(self) -> bool:
        """Always False -- there is no agent registry. See register_on_chain."""
        return False

    def get_registration(self):
        """Always None -- there is no agent registry. See register_on_chain."""
        return None


    def __repr__(self):
        return f"Agent(address={self.address})"

    __str__ = __repr__
