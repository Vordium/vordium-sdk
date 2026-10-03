import argparse
from .agent import Agent
from .chain import Chain
from .network import get_network

BANNER = """
==========================================
         VORDIUM AGENT TERMINAL
        The AI Layer for Crypto
           docs.vordium.com
==========================================
"""


def main():
    parser = argparse.ArgumentParser(
        prog='vordium',
        description='Vordium Agent CLI - The AI Layer'
    )
    subparsers = parser.add_subparsers(dest='command')

    subparsers.add_parser('init', help='Create new agent wallet')
    subparsers.add_parser('status', help='Check chain status')

    bal = subparsers.add_parser('balance', help='Check VORD balance')
    bal.add_argument('address', nargs='?')

    send = subparsers.add_parser('send', help='Send VORD')
    send.add_argument('to')
    send.add_argument('amount', type=float)

    run = subparsers.add_parser('run', help='Run agent script')
    run.add_argument('script')

    reg = subparsers.add_parser('register', help='Register agent on-chain')
    reg.add_argument('--name', required=True)
    reg.add_argument('--strategy', default='trading')

    args = parser.parse_args()
    print(BANNER)

    if args.command == 'init':
        cmd_init()
    elif args.command == 'status':
        cmd_status()
    elif args.command == 'balance':
        cmd_balance(args)
    elif args.command == 'send':
        cmd_send(args)
    elif args.command == 'run':
        cmd_run(args)
    elif args.command == 'register':
        cmd_register(args)
    else:
        cmd_interactive()


def cmd_init():
    print("Initializing new agent...\n")
    agent = Agent()
    print(f"\n{'='*50}")
    print(f"Address:     {agent.address}")
    print(f"Private Key: {agent.private_key}")
    print(f"{'='*50}")
    print("\nSave your private key to .env:")
    print(f"VORDIUM_PRIVATE_KEY={agent.private_key}\n")
    print(f"Balance: {agent.balance} VORD")
    print(f"Explorer: {get_network().explorer_url}/address/{agent.address}")
    print("\nAgent ready to trade.")


def cmd_status():
    chain = Chain()
    net = get_network()
    status = 'Online' if chain.connected else 'Offline'
    print(f"Chain:     {net.chain_name}")
    print(f"Chain ID:  {net.chain_id}  (resolved from: {net.source})")
    print(f"RPC:       {net.rpc_url}")
    print(f"Block:     {chain.block_number:,}")
    print(f"Gas Price: {chain.gas_price:.2f} gwei")
    print(f"Status:    {status}")
    print(f"Explorer:  {net.explorer_url}")


def cmd_balance(args):
    chain = Chain()
    addr = args.address if args.address else Agent().address
    print(f"Address: {addr}")
    print(f"Balance: {chain.get_balance(addr)} VORD")


def cmd_send(args):
    agent = Agent()
    print(f"Sending {args.amount} VORD to {args.to}...")
    agent.send(args.to, args.amount)


def cmd_register(args):
    agent = Agent()
    if agent.is_registered():
        reg = agent.get_registration()
        print(f"Already registered: Agent #{reg['id']} '{reg['name']}' ({reg['strategy_type']})")
        return
    print(f"Registering '{args.name}' (strategy: {args.strategy}) on-chain...")
    agent.register_on_chain(args.name, args.strategy)
    reg = agent.get_registration()
    print(f"Agent #{reg['id']} registered.")


def cmd_run(args):
    print(f"Running {args.script}...\n")
    with open(args.script) as f:
        exec(f.read())


def cmd_interactive():
    chain = Chain()
    agent = Agent()
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
    main()
