from web3 import Web3
from .network import get_network


class Chain:
    def __init__(self):
        self._net = get_network()  # resolve_network() at client init
        self._w3 = Web3(Web3.HTTPProvider(self._net.rpc_url))

    @property
    def connected(self) -> bool:
        return self._w3.is_connected()

    @property
    def block_number(self) -> int:
        return self._w3.eth.block_number

    @property
    def gas_price(self) -> float:
        return float(self._w3.from_wei(self._w3.eth.gas_price, 'gwei'))

    def get_balance(self, address: str) -> float:
        from .config import native_balance
        return native_balance(address)
        return float(self._w3.from_wei(raw, 'ether'))

    def get_transaction(self, tx_hash: str):
        return self._w3.eth.get_transaction(tx_hash)

    def get_block(self, number: int = None):
        if number is None:
            return self._w3.eth.get_block('latest')
        return self._w3.eth.get_block(number)

    def explorer_url(self, tx_hash: str) -> str:
        return f"{self._net.explorer_url}/tx/{tx_hash}"

    def __repr__(self):
        return f"Chain(block={self.block_number}, connected={self.connected})"
