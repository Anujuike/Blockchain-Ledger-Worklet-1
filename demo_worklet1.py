"""
Worklet 1 demo: Cryptographic foundations & transactions (Discrete + OOP).

Walks through the five guideline tasks using only the code in this folder:
  1. Modular arithmetic and fast modular exponentiation
  2. Miller-Rabin primality, large primes, RSA key pair
  3. Transaction / Input / Output / Wallet model
  4. Sign with the private key, verify with the public key, canonical serialization
  5. Tamper detection and double-spend prevention within a block

Run from this folder:  python demo_worklet1.py
"""

from __future__ import annotations

import time

from blockchain_lite.crypto.asymmetric import RSACryptoEngine
from blockchain_lite.crypto.number_theory import (
    extended_gcd,
    generate_large_prime,
    is_probable_prime_miller_rabin,
    mod_inverse,
    pow_mod,
    pow_mod_with_trace,
)
from blockchain_lite.interfaces import DoubleSpendError, TamperDetectedError
from blockchain_lite.models.transaction import (
    Transaction,
    TxOutput,
    validate_block_transactions_no_double_spend,
    validate_transaction_integrity,
)
from blockchain_lite.wallet.wallet import SpendableUTXO, Wallet

RSA_BITS = 384  # educational demo size; real systems need >= 2048 bits
T0 = 1700000000


def section(title: str) -> None:
    print("\n" + "=" * 78 + f"\n{title}\n" + "=" * 78)


def task1_modular_arithmetic() -> None:
    section("TASK 1 - Modular arithmetic & fast modular exponentiation")
    print(f"  pow_mod(4, 13, 497)        = {pow_mod(4, 13, 497)}  (textbook answer: 445)")
    print(f"  pow_mod matches Python pow  : {pow_mod(7, 10**6, 1000003) == pow(7, 10**6, 1000003)}")
    g, x, y = extended_gcd(240, 46)
    print(f"  extended_gcd(240, 46)       = gcd {g}, 240*({x}) + 46*({y}) = {240 * x + 46 * y}")
    print(f"  mod_inverse(17, 3120)       = {mod_inverse(17, 3120)}  (17 * 2753 mod 3120 = 1)")

    base, exp, mod = 0x9876543210FEDCBA, (1 << 255) + 123456789, (1 << 521) - 1
    trace = pow_mod_with_trace(base, exp, mod)
    print(f"  256-bit exponent: {trace.squarings} squarings + {trace.multiplications} multiplications "
          f"= {trace.total_modular_ops} modular ops")
    print("  (naive repeated multiplication would need ~2^255 multiplications)")


def task2_primes_and_keys() -> RSACryptoEngine:
    section("TASK 2 - Miller-Rabin primality, large primes, RSA key pair")
    carmichael = [561, 1105, 1729, 2465, 6601]
    print("  Carmichael numbers fool Fermat's test but not Miller-Rabin:")
    for n in carmichael:
        print(f"    {n:>5}: probable prime? {is_probable_prime_miller_rabin(n)}")
    print(f"  M61 = 2^61-1 prime? {is_probable_prime_miller_rabin((1 << 61) - 1)}")

    t = time.perf_counter()
    p = generate_large_prime(bit_length=192)
    print(f"  generate_large_prime(192 bits) in {1000 * (time.perf_counter() - t):.0f} ms: "
          f"{p.bit_length()}-bit prime ...{str(p)[-12:]}")

    engine = RSACryptoEngine()
    t = time.perf_counter()
    pub, priv = engine.generate_keypair_objects(bit_length=RSA_BITS)
    print(f"  RSA-{pub.bit_length} key pair in {1000 * (time.perf_counter() - t):.0f} ms: "
          f"e = {pub.e}, n has {pub.n.bit_length()} bits")
    print(f"  Key check: (e * d) mod lcm(p-1, q-1) == 1 -> "
          f"{(pub.e * priv.d) % (((priv.p - 1) * (priv.q - 1)) // extended_gcd(priv.p - 1, priv.q - 1)[0]) == 1}")
    return engine


def task3_model(engine: RSACryptoEngine) -> tuple:
    section("TASK 3 - Transaction, Input/Output and Wallet classes")
    alice = Wallet.generate("Alice", bit_length=RSA_BITS, crypto_engine=engine)
    bob = Wallet.generate("Bob", bit_length=RSA_BITS, crypto_engine=engine)
    print(f"  Alice address = SHA-256(public key) = {alice.address_hex[:32]}...")
    print(f"  Bob   address                      = {bob.address_hex[:32]}...")

    # Alice owns one 100-unit output from an earlier (funding) transaction.
    funding = Transaction.create_coinbase(alice.address, 100, timestamp=T0)
    utxo = SpendableUTXO(tx_id=funding.tx_id, output_index=0, amount=100, recipient_address=alice.address)
    tx = alice.create_signed_transfer(bob.address, amount=30, spendable_utxos=[utxo], fee=2, timestamp=T0 + 1)
    print(f"  Transfer: {len(tx.inputs)} input (100) -> outputs "
          f"{[o.amount for o in tx.outputs]} (30 to Bob, 68 change), fee = 100 - 98 = 2")
    return alice, bob, funding, utxo, tx


def task4_sign_verify_serialize(engine: RSACryptoEngine, tx: Transaction) -> None:
    section("TASK 4 - Sign / verify / canonical serialization")
    pub, priv = engine.generate_keypair_objects(bit_length=RSA_BITS)
    msg = b"pay Bob 30"
    sig = engine.sign(priv.to_bytes(), msg)
    print(f"  Signature of {msg!r}: {len(sig)} bytes")
    print(f"  verify(original message)  -> {engine.verify(pub.to_bytes(), msg, sig)}")
    print(f"  verify(altered message)   -> {engine.verify(pub.to_bytes(), b'pay Bob 31', sig)}")

    raw = tx.to_bytes()
    back = Transaction.from_bytes(raw)
    print(f"  Transaction serializes to {len(raw)} bytes (big-endian, length-prefixed fields)")
    print(f"  Round trip: from_bytes(to_bytes(tx)) == tx -> {back == tx}; identical bytes -> {back.to_bytes() == raw}")
    print(f"  tx_id = SHA-256(bytes) = {tx.tx_id_hex[:32]}...")
    print(f"  Transaction signatures verify -> {tx.verify_signatures(crypto_engine=engine)}")


def task5_tamper_and_double_spend(engine, alice, bob, funding, utxo, tx) -> None:
    section("TASK 5 - Tamper detection & double-spend prevention within a block")
    tampered = Transaction(
        tx_type=tx.tx_type, timestamp=tx.timestamp, inputs=tx.inputs,
        outputs=(TxOutput(amount=31, recipient_address=bob.address), tx.outputs[1]),
    )
    print("  Change Bob's output 30 -> 31 (signature left untouched):")
    try:
        validate_transaction_integrity(tampered, crypto_engine=engine)
        print("    NOT detected (unexpected)")
    except TamperDetectedError as exc:
        print(f"    TamperDetectedError: {str(exc)[:80]}...")

    second = alice.create_signed_transfer(bob.address, amount=50, spendable_utxos=[utxo], timestamp=T0 + 2)
    available = {(funding.tx_id, 0): funding.outputs[0]}
    print("  Two validly signed transactions spending the SAME output, in one block:")
    validate_block_transactions_no_double_spend([tx], available_utxos=available, crypto_engine=engine)
    print("    first transaction alone          -> accepted")
    try:
        validate_block_transactions_no_double_spend([tx, second], available_utxos=available, crypto_engine=engine)
        print("    both together -> NOT detected (unexpected)")
    except DoubleSpendError as exc:
        print(f"    both together -> DoubleSpendError: {str(exc)[:70]}...")


def main() -> None:
    print("WORKLET 1 - Cryptographic foundations & transactions (Discrete + OOP)")
    task1_modular_arithmetic()
    engine = task2_primes_and_keys()
    alice, bob, funding, utxo, tx = task3_model(engine)
    task4_sign_verify_serialize(engine, tx)
    task5_tamper_and_double_spend(engine, alice, bob, funding, utxo, tx)
    print("\nAll five Worklet 1 tasks demonstrated.")


if __name__ == "__main__":
    main()
