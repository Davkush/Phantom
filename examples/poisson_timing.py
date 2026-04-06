import random
import math
import time

def simulate_poisson_dispatch(mean_interval_ms=100.0, duration_secs=5):
    """
    Demonstrates the Poisson distribution heartbeat used by Phantom Protocol.
    This creates an unpredictable dispatch pattern that prevents timing correlation.
    """
    print(f"=== Phantom Heartbeat Simulator (Lambda = {mean_interval_ms}ms) ===")
    print("Each [X] represents a 9KB Sphinx Packet being dispatched.")
    
    start_time = time.time()
    packet_count = 0
    
    while (time.time() - start_time) < duration_secs:
        # 1. Calculate next delay using the Exponential Distribution (inverse of Poisson)
        # Formula: -ln(U) / lambda where U is a random number [0,1]
        u = random.random()
        delay_ms = -math.log(u) * mean_interval_ms
        
        # 2. Wait for the jittered interval
        time.sleep(delay_ms / 1000.0)
        
        # 3. "Dispatch" packet
        print(f"[{time.strftime('%H:%M:%S')}] DISPATCH: 9216 bytes [X]")
        packet_count += 1

    print(f"\nSimulation Complete. Packets Dispatched: {packet_count}")
    print("To a Global Passive Adversary (GPA), this looks like a continuous, ")
    print("uncorrelated stream of identical pulses.")

if __name__ == "__main__":
    simulate_poisson_dispatch()
