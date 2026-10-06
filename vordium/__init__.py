"""
Vordium SDK — Python library for AI agents on Vordium Chain.

Usage:
    from vordium import Agent
    agent = Agent()
    print(agent.address)
    print(agent.balance)

Docs: https://docs.vordium.com
"""

# The network is discovered at runtime, never hardcoded. See vordium.network.
from .network import (
    Network,
    NetworkResolutionError,
    BridgeRefused,
    current_bridge,
    require_current_bridge,
    resolve_network,
    get_network,
    set_network,
    reset_network,
)
from .agent import Agent
from .wallet import Wallet
from .chain import Chain
from .dex import Vordex

# Agent operator extension: session-key trading bounded by on-chain caps.
from .caps import (
    AgentCaps,
    AgentMode,
    CandidateOrder,
    CapError,
    OrderType,
    PlaceOrderType,
    Side,
    agent_cap_check,
    domain_separator,          # resolved at runtime
    place_order_digest,
    cancel_order_digest,
    modify_order_digest,
    set_agent_caps_digest,
    set_agent_mode_digest,
    set_tpsl_digest,
)
from .operator import AgentBox, Operator, SessionSigner

# Signing phase: the signing format switches at the activation height read live from releases.json.
from .rollb import SigningPhase, SigningPaused, read_signing_phase, signing_phase
from .names import InvalidAgentName, normalize_name, check_name, prepare_name, refusal_step, agent_display_name
from .agent_ops import registration, rename, set_policy, clear_lock, submit_body, sign_owner_op, sign_agent_policy
from .policy import PolicyV1, policy_problems, loosens, policy_from_read, lock_since_from_read
from .money import MoneyOpError, money_message, money_body, sign_money_op
from .referral import register_trader_message, register_code_message, claim_earnings_message, sign_referral_message

# The deposit bridge: deposits into the vault on Arbitrum (from Arbitrum or Arc) and withdrawals to Arbitrum.
from . import bridge_v4

# Market makers: signed batches, cancel-all, modify, Market Maker Protection, account reads and live feeds.
from .mm import (MarketMaker, MMError, Mmp, Refusal, Submitted, NonceClock, next_mmp_nonce, pair_specs, nonce_clock,
                 round_price, round_size, OpenOrder, Position)
from .network import NetworkMismatch
from .node_domain import NodeDomain, NodeIdentity, node_identity
from .feeds import Feeds, FeedError, SeqTracker, Book

__version__ = "1.4.1"
__author__ = "Vordium"
__all__ = [
    "Agent", "Wallet", "Chain", "Vordex",
    # network discovery
    "Network", "NetworkResolutionError", "resolve_network", "get_network",
    "set_network", "reset_network",
    # the deposit bridge: only the address the live network spec names
    "BridgeRefused", "current_bridge", "require_current_bridge",
    # operator extension
    "SessionSigner", "AgentBox", "Operator",
    "AgentCaps", "AgentMode", "CandidateOrder", "CapError",
    "OrderType", "PlaceOrderType", "Side", "agent_cap_check", "domain_separator",
    "place_order_digest", "cancel_order_digest", "modify_order_digest",
    "set_agent_caps_digest", "set_agent_mode_digest", "set_tpsl_digest",
    # signing phase, agent names and policies, money and referral messages
    "SigningPhase", "SigningPaused", "read_signing_phase", "signing_phase",
    "InvalidAgentName", "normalize_name", "check_name", "prepare_name", "refusal_step", "agent_display_name",
    "registration", "rename", "set_policy", "clear_lock", "submit_body", "sign_owner_op", "sign_agent_policy",
    "PolicyV1", "policy_problems", "loosens", "policy_from_read", "lock_since_from_read",
    "MoneyOpError", "money_message", "money_body", "sign_money_op",
    "register_trader_message", "register_code_message", "claim_earnings_message", "sign_referral_message",
    # the deposit bridge (vault on Arbitrum)
    "bridge_v4",
    # market makers
    "MarketMaker", "MMError", "Mmp", "Refusal", "Submitted", "NonceClock", "next_mmp_nonce", "pair_specs",
    "nonce_clock", "round_price", "round_size", "OpenOrder", "Position", "NetworkMismatch", "NodeDomain", "NodeIdentity",
    "node_identity",
    "Feeds", "FeedError", "SeqTracker", "Book",
]
