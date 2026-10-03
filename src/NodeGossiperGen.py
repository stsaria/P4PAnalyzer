import asyncio
import sys
import warnings
from P4PCore.P4PRunner import P4PRunner
from P4PCore.model.NodeIdentify import NodeIdentify
from P4PCore.model.HashableEd25519PublicKey import HashableEd25519PublicKey
from P4PNodeGossiper.NodeGossiper import NodeGossiper

warnings.filterwarnings("ignore", category=UserWarning, module="nltk")

BOOTSTRAP_IP = sys.argv[1]
BOOTSTRAP_PORT = int(sys.argv[2])
BOOTSTRAP_ED25519_PUBLIC_KEY = bytes.fromhex(sys.argv[3])
NODES = int(sys.argv[4])


async def startGossipLoop(nodeGossiper: NodeGossiper):
    while True:
        try:
            await asyncio.sleep(1.0)
            if hasattr(nodeGossiper, "sync"):
                if asyncio.iscoroutinefunction(nodeGossiper.sync):
                    await nodeGossiper.sync()
                else:
                    nodeGossiper.sync()
        except asyncio.CancelledError:
            break
        except Exception:
            pass


async def addNodeTask(i, nodes):
    runner = await P4PRunner.create()
    nodeGossiper = await NodeGossiper.create(runner, syncIntervalSeconds=1, maximumNodesCount=2000, gossipTTLSeconds=2)

    bootstrap_identity = NodeIdentify(
        ip=BOOTSTRAP_IP,
        port=BOOTSTRAP_PORT,
        hashableEd25519PublicKey=HashableEd25519PublicKey(
            BOOTSTRAP_ED25519_PUBLIC_KEY
        ),
    )
    await nodeGossiper.addNode(bootstrap_identity)

    await runner.begin()

    bindPort = runner.net._protocolV4.transport.get_extra_info("sockname")[1]

    gossipTask = asyncio.create_task(startGossipLoop(nodeGossiper))

    nodes.append((runner, nodeGossiper, gossipTask))
    print(
        f"Node {i} started on port {bindPort} and connected to bootstrap node."
    )


async def amain():
    print(
        f"Starting {NODES} pure gossip nodes connecting to bootstrap node at {BOOTSTRAP_IP}:{BOOTSTRAP_PORT}..."
    )
    await asyncio.sleep(1)  # Small delay to allow the print statement to flush
    nodes: list[tuple[P4PRunner, NodeGossiper, asyncio.Task]] = []

    for i in range(NODES):
        await addNodeTask(i, nodes)
        await asyncio.sleep(0.02)

    print("\nAll nodes are running. Press Ctrl+C to exit.")

    try:
        await asyncio.Event().wait()
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("\nStopping all nodes and releasing sockets...")
        for runner, _, gossipTask in nodes:
            gossipTask.cancel()
            try:
                if (
                    hasattr(runner.net._protocolV4, "transport")
                    and runner.net._protocolV4.transport
                ):
                    runner.net._protocolV4.transport.close()
            except Exception:
                pass

        for runner, _, _ in nodes:
            try:
                await runner.end()
            except Exception:
                pass
        print("Shutdown complete.")


if __name__ == "__main__":
    asyncio.run(amain())
