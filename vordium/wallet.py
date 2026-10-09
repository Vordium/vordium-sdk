import json
from eth_account import Account
from web3 import Web3
from .network import get_network

Account.enable_unaudited_hdwallet_features()


class Wallet:
    def __init__(self, private_key: str = None):
        self._w3 = Web3(Web3.HTTPProvider(get_network().rpc_url))
        if private_key:
            self._account = Account.from_key(private_key)
        else:
            self._account = Account.create()

    @classmethod
    def create(cls) -> 'Wallet':
        return cls()

    @classmethod
    def from_key(cls, private_key: str) -> 'Wallet':
        return cls(private_key=private_key)

    @classmethod
    def from_mnemonic(cls, mnemonic: str) -> 'Wallet':
        account = Account.from_mnemonic(mnemonic)
        return cls(private_key=account.key.hex())

    @property
    def address(self) -> str:
        return self._account.address

    @property
    def private_key(self) -> str:
        return self._account.key.hex()

    def balance(self) -> float:
        raw = self._w3.eth.get_balance(self.address)
        return float(self._w3.from_wei(raw, 'ether'))

    def save(self, path: str):
        with open(path, 'w') as f:
            json.dump({
                'address': self.address,
                'private_key': self.private_key
            }, f, indent=2)
        print(f"Wallet saved to {path}")

    def __repr__(self):
        return f"Wallet(address={self.address})"
