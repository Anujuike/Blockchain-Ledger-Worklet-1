# Worklet 1 — Cryptographic foundations & transactions (Discrete + OOP)

> *Build the number-theory core and the signed-transaction model, so a wallet can sign and
> verify and tampering is caught.* (Guidelines to Students, Mini Project 5, §4)

This folder is the Worklet 1 team's standalone build. It contains this worklet's code, the two
shared files it depends on, its own tests and a demo, so the team can be reviewed on its own.
The integrated system (all three worklets plus the client-server layer and web dashboard)
lives in `..\Worklet 5 Blockchain-Lite Ledger & Digital Wallet\`.

## Run it (PowerShell, from this folder)

```powershell
cd "$env:USERPROFILE\Desktop\Worklet 5 Blockchain-Lite Ledger & Digital Wallet\Worklet 1"
python run_tests.py        # 15 tests, under a second
python demo_worklet1.py    # walks through the 5 tasks below
```

Python 3.11+ only; no packages to install.

## Tasks → code → evidence

| # | Guideline task | Code | Tests | Demo |
| :- | :--- | :--- | :--- | :--- |
| 1 | Modular arithmetic and fast modular exponentiation | `blockchain_lite/crypto/number_theory.py` (`mod_add/sub/mul`, `pow_mod`, `pow_mod_with_trace`, `extended_gcd`, `mod_inverse`) | `TestWorklet1NumberTheoryAndRSA` | Task 1: 272 modular ops for a 256-bit exponent |
| 2 | Miller–Rabin, large primes, RSA key pair | `number_theory.py` (`is_probable_prime_miller_rabin`, `generate_large_prime`), `crypto/asymmetric.py` (`RSACryptoEngine`, `RSAPublicKey`, `RSAPrivateKey`) | `TestWorklet1NumberTheoryAndRSA`, `TestPhase2CryptographicHardening` | Task 2: Carmichael numbers rejected, RSA-384 key pair |
| 3 | Transaction, Input/Output, Wallet classes | `models/transaction.py` (`TxInput`, `TxOutput`, `Transaction`), `wallet/wallet.py` (`Wallet`, coin selection, change) | `TestWorklet1TransactionsWalletAndDoubleSpend` | Task 3: 100 → 30 to Bob + 68 change + fee 2 |
| 4 | Sign with private key, verify with public key; canonical serialization | `asymmetric.py` (`sign`, `verify`), `serialization.py` (`ByteBuffer`), `Transaction.signing_preimage_bytes/to_bytes/from_bytes` | `TestCanonicalByteBuffer`, transaction tests | Task 4: verify true/false, byte-identical round trip |
| 5 | Detect tampering; prevent double-spending within a block | `transaction.py` (`validate_transaction_integrity`, `validate_block_transactions_no_double_spend`) | `TestWorklet1TransactionsWalletAndDoubleSpend` | Task 5: `TamperDetectedError`, `DoubleSpendError` |

`run_tests.py` also runs `TestWorkletFoundationsFirst`, which fails if any file here imports a
crypto, blockchain, database, web or ML library.

## What this worklet owns vs uses

See [`FILES.md`](FILES.md). Summary:

- **Owned (this team):** `number_theory.py`, `asymmetric.py`, `serialization.py`, `transaction.py`, `wallet.py`.
- **Used, read-only:** `interfaces.py` (shared contracts agreed by all worklets) and
  `crypto/hashing.py` (Worklet 2's SHA-256, needed for addresses, `tx_id` and signatures).

## Interfaces

| Direction | Interface | Used by |
| :--- | :--- | :--- |
| Provides | `AsymmetricCryptoInterface` (`RSACryptoEngine.sign/verify/generate_keypair`) | Worklet 3 (signature checks during validation) |
| Provides | `Transaction`, `TxInput`, `TxOutput` + canonical bytes, `tx_id` | Worklet 2 (Merkle leaves, block bodies), Worklet 3 (UTXO set) |
| Provides | `Wallet.create_signed_transfer`, `SpendableUTXO` | Worklet 3 / integration (client wallet) |
| Consumes | `HashInterface` (`hash_bytes`) from Worklet 2 | addresses, `tx_id`, signature digest |

## Viva checks this worklet must answer

**1. Why is modular exponentiation cheap but factoring / discrete log hard?**
Square-and-multiply scans the exponent's bits: about log2(e) squarings plus one multiplication
per 1-bit, reducing mod n each step, so a 256-bit exponent takes 272 operations instead of 2^256.
Going backwards has no such shortcut: the best known classical factoring algorithm (the General
Number Field Sieve) is sub-exponential, and reducing mod n destroys the ordering that would let
you binary-search an answer.

**2. Change one byte of one transaction — what breaks first?**
The signing preimage changes, so the SHA-256 digest inside the signature representative changes
completely, and `s^e mod n` no longer equals it: `verify_signatures()` is False and validation
raises `TamperDetectedError`. The `tx_id` also changes, which is what breaks Worklet 2's Merkle
root and, through the header hash, Worklet 3's chain.

**5. What does a signature guarantee (vs proof-of-work)?**
Authenticity and authorization: only the holder of the private key could have produced it, and
it binds the exact inputs and outputs. It does **not** stop the same owner signing two
conflicting spends; that is why double-spend checks exist (task 5) and why proof-of-work orders
blocks.

**Also expect:** what the signature covers (domain tag + public key + unsigned preimage; the
signature fields themselves are excluded), why canonical serialization matters (every node must
hash identical bytes), and why 384-bit RSA is educational only (factorable; real systems need
2048+ bits and padding such as PSS). Full answers: `docs/Viva_Guide_and_Design_Journal.md` in the
integrated project.

## Changing code

The integrated project is the single source of truth. Edit the code there, then regenerate this
folder from the project folder:

```powershell
python tools/split_worklets.py
```

`run_tests.py`, `FILES.md`, `blockchain_lite/` and `tests/` are regenerated. This README and
`demo_worklet1.py` are never touched by the generator.
