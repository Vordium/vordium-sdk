"""Agent quickstart: load a key from the environment and read your account.

    export VORDIUM_PRIVATE_KEY=0x...      # your session/agent key (never hardcode)
    python examples/agent_quickstart.py

Writes (place/cancel orders) are EIP-712 signed and bounded by on-chain agent
caps that the account sets; they take effect once agent trading is enabled for
the account. This example only READS, so it is safe to run with any key.
"""
import os
from vordium import Agent, Vordex

pk = os.environ.get("VORDIUM_PRIVATE_KEY")
if not pk:
    raise SystemExit("set VORDIUM_PRIVATE_KEY (a hex private key) first")

agent = Agent(pk)
print("address:", agent.address)
print("VORD balance:", agent.balance)

dex = Vordex()
print("USDC collateral:", dex.balance(agent.address))
print("open positions:", dex.positions(agent.address))
