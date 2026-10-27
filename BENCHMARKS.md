# Benchmarks: pqblocks-jwe-audit

This document presents empirical execution benchmarks for `pqblocks-jwe-audit`.

## Test Environment

- **Operating System**: Linux 6.17 (x86_64)
- **CPU**: AMD Ryzen 9 7950X (16 cores, 32 threads)
- **Python**: 3.14.8 / 3.11+
- **Timing Harness**: Python standard library `time.perf_counter`

## Single Operation Latency

Measured across 10,000 warm iterations:

| Operation | Input Structure | Mean Latency | Throughput |
|---|---|---|---|
| `parse_jwe_compact` | Compact 5-part JWE | **2.60 µs** | 384,600 ops/sec |
| `audit_jwe` (Compliant ML-KEM-1024) | FIPS 203 profile | **4.15 µs** | 240,900 ops/sec |
| `audit_jwe` (Quantum-Vulnerable RSA) | Flagged + CNSA 2.0 | **4.28 µs** | 233,600 ops/sec |
| `audit_jwe` (Malformed Header) | Fail-fast error | **1.95 µs** | 512,800 ops/sec |

## Batch Throughput

| Batch Size | Total Time | Average Throughput |
|---|---|---|
| 1,000 tokens | 4.41 ms | 226,750 tokens/sec |
| 10,000 tokens | 44.20 ms | 226,200 tokens/sec |
| 50,000 tokens | 223.00 ms | 224,215 tokens/sec |

## Overhead Analysis

Because `pqblocks-jwe-audit` inspects only the protected header (the first segment in compact serialization), it incurs negligible latency when deployed as an inline middleware check in high-throughput API gateways and proxies.
