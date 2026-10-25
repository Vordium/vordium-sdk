import argparse
import os
import sys
from .agent import Agent
from .chain import Chain
from .network import get_network
from .wallet import KeyFileError, default_key_dir, generate_key_file

KEY_HELP = ("key file written by 'vordium init' (mode 0600); without it the key is read from the "
            "VORDIUM_PRIVATE_KEY environment variable")

BANNER = """
==========================================
         VORDIUM AGENT TERMINAL
        The AI Layer for Crypto
           docs.vordium.com
==========================================
"""


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='vordium',
        description='Vordium Agent CLI - The AI Layer'
    )
    subparsers = parser.add_subparsers(dest='command')

    init = subparsers.add_parser(
        'init', help='Create a new key and write it to a key file (mode 0600)',
        description=("Create a new key and write it to a NEW key file with mode 0600. Only the address and the "
                     f"file's path are printed, never the key. Default file: {default_key_dir()}/<address>.key"))
    init.add_argument('--out', metavar='PATH',
                      help=f'where to write the key file (default {default_key_dir()}/<address>.key); '
                           'an existing file is never overwritten')
    subparsers.add_parser('status', help='Check chain status')

    bal = subparsers.add_parser('balance', help='Check the VORD balance of an address')
    bal.add_argument('address', nargs='?', help='the address to read (required)')

    send = subparsers.add_parser('send', help='Send VORD')
    send.add_argument('to')
    send.add_argument('amount', type=float)
    send.add_argument('--key-file', metavar='PATH', help=KEY_HELP)

    run = subparsers.add_parser('run', help='Run agent script')
    run.add_argument('script')

    reg = subparsers.add_parser('register', help='Register agent on-chain')
    reg.add_argument('--name', required=True)
    reg.add_argument('--strategy', default='trading')

    parser.add_argument('--key-file', metavar='PATH', dest='key_file_main',
                        help=KEY_HELP + ' (for the interactive terminal)')

    args = parser.parse_args(argv)
    print(BANNER)

    if args.command == 'init':
        return cmd_init(args)
    elif args.command == 'status':
        return cmd_status()
    elif args.command == 'balance':
        return cmd_balance(args)
    elif args.command == 'send':
        return cmd_send(args)
    elif args.command == 'run':
        return cmd_run(args)
    elif args.command == 'register':
        return cmd_register(args)
    else:
        return cmd_interactive(args)


def _refuse(message: str) -> int:
    print(message, file=sys.stderr)
    return 2


def _agent_with_key(key_file):
    """An Agent from a key file or VORDIUM_PRIVATE_KEY -- never a new key. None when neither is given."""
    if key_file:
        return Agent(key_file=key_file)
    if os.getenv('VORDIUM_PRIVATE_KEY'):
        return Agent()
    return None


NO_KEY = ("no key: pass --key-file PATH (a file written by 'vordium init') or set VORDIUM_PRIVATE_KEY. "
          "The CLI never makes a new key for this.")


def cmd_init(args=None):
    print("Creating a new agent key...\n")
    try:
        address, path = generate_key_file(getattr(args, 'out', None))
    except (KeyFileError, OSError) as e:
        return _refuse(f"Not written: {e}")
    print(f"Address:  {address}")
    print(f"Key file: {path}  (mode 0600; the key is not shown)")
    print("\nKeep this file private and back it up. Use it with:")
    print(f"  vordium send <to> <amount> --key-file {path}")
    print(f"  Agent(key_file=\"{path}\")   # in Python")
    return 0


def cmd_status():
    chain = Chain()
    net = get_network()
    status = 'Online' if chain.connected else 'Offline'
    print(f"Chain:     {net.chain_name}")
    print(f"Chain ID:  {net.chain_id}  (resolved from: {net.source})")
    print(f"RPC:       {net.rpc_url}")
    if net.api_url:
        print(f"API:       {net.api_url}")
    print(f"Block:     {chain.block_number:,}")
    print(f"Gas Price: {chain.gas_price:.2f} gwei")
    print(f"Status:    {status}")
    print(f"Explorer:  {net.explorer_url}")


def cmd_balance(args):
    if not args.address:
        return _refuse("vordium balance needs an address: vordium balance 0x...")
    chain = Chain()
    print(f"Address: {args.address}")
    print(f"Balance: {chain.get_balance(args.address)} VORD")
    return 0


def cmd_send(args):
    try:
        agent = _agent_with_key(args.key_file)
    except (KeyFileError, OSError, ValueError) as e:
        return _refuse(f"Not sent: {e}")
    if agent is None:
        return _refuse(f"Not sent: {NO_KEY}")
    print(f"Sending {args.amount} VORD to {args.to} from {agent.address}...")
    agent.send(args.to, args.amount)
    return 0


def cmd_register(args):
    return _refuse(
        "Agents are not registered on a contract. The owner registers an agent with RegisterAgentV2 "
        "(vordium.agent_ops) and sets its policy with SetAgentPolicyV1, signed by the owner key.")


def cmd_run(args):
    print(f"Running {args.script}...\n")
    with open(args.script) as f:
        exec(f.read())


def cmd_interactive(args=None):
    try:
        agent = _agent_with_key(getattr(args, 'key_file_main', None))
    except (KeyFileError, OSError, ValueError) as e:
        return _refuse(str(e))
    if agent is None:
        return _refuse(f"{NO_KEY}\nRun 'vordium --help' for the commands.")
    chain = Chain()
    print(f"Connected: {get_network().chain_name}")
    print(f"Block:     {chain.block_number:,}")
    print(f"Address:   {agent.address}")
    print(f"Balance:   {agent.balance} VORD")
    print("\nCommands: status, balance, send <to> <amount>, exit\n")

    while True:
        try:
            cmd = input("vordium> ").strip()
            if not cmd:
                continue
            if cmd == 'status':
                print(f"Block: {chain.block_number:,} | Gas: {chain.gas_price:.2f} gwei")
            elif cmd == 'balance':
                print(f"{agent.balance} VORD")
            elif cmd.startswith('send '):
                parts = cmd.split()
                if len(parts) == 3:
                    agent.send(parts[1], float(parts[2]))
            elif cmd in ('exit', 'quit'):
                print("Goodbye.")
                break
            else:
                print("Commands: status, balance, send <to> <amount>, exit")
        except KeyboardInterrupt:
            print("\nGoodbye.")
            break
        except Exception as e:
            print(f"Error: {e}")


if __name__ == '__main__':
    sys.exit(main())
