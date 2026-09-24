# SENTINEL Test & Validation Report

## Evidence boundary

This document records **software verification**, not external security validation.

Passing unit, integration, and end-to-end tests shows that the tested code paths behave as asserted under the repository's fixtures and simulations. It does **not** establish production readiness, real-network DDoS detection accuracy, deployment-scale latency, universal false-positive behavior, or security against adaptive adversaries.

The bundled CIC-DDoS-style benchmark is generated synthetically by `scripts/generate_mock_data.js`; see the repository README for the benchmark boundary.

## Test suite

- Framework: Jest
- Test files: 18 in the recorded suite
- Coverage includes core filtering, state, integration, API, gossip, challenge, lifecycle, honeypot, and metrics behavior.

Run:

```bash
npm test
npm run test:coverage
npm run test:watch
```

## Covered components

| Component | What the tests establish |
|---|---|
| Rate limiter | Windowing, blocking, expiration, and per-IP state behave as asserted |
| Contagion graph | Graph/vector construction and configured similarity/propagation logic execute correctly |
| Neural predictor | Forward/training-state mechanics and parameter updates execute under fixtures |
| Fingerprinter | Behavioral feature/scoring paths execute under test inputs |
| Adaptive threat logic | Configured adaptive-state transitions execute under fixtures |
| IP allowlist | Exact/CIDR allowlist behavior follows the test contract |
| Integration suite | Major subsystems compose correctly under simulated request flows |
| API authentication | Authentication and administrative-rate-limit behavior follows assertions |
| Threat ledger | Ledger data-structure behavior follows its tests |
| Challenge tokens | Token/challenge lifecycle follows its tests |
| CSRF protection | Configured CSRF checks execute under fixtures |
| Economics engine | Cost-model calculations follow the implemented formulas |
| Gossip protocol | Peer-message mechanics execute under test conditions |
| Graceful shutdown | Shutdown paths clean up expected resources |
| Health checks | Health endpoints/state follow the implemented contract |
| Honeypot | Trap generation/detection behavior follows assertions |
| Metrics | Metric collection and reporting execute under fixtures |
| Experimental challenge module | The implemented proof-of-concept mechanics execute under tests |

## Integration scope

The integration tests exercise simulated legitimate and abusive request patterns, allowlist behavior, rate limiting, and protected telemetry paths. They are useful regression tests for composition of the codebase.

They are not a substitute for:
- Internet-facing load testing;
- red-team validation;
- real traffic calibration;
- external DDoS datasets;
- multi-region fault testing;
- formal security review.

## Performance measurements

Any timing observed inside unit/integration tests is local test-environment behavior. A small graph or request fixture completing within a particular time does not establish production latency or asymptotic performance at Internet scale.

For deployment-specific performance work, benchmark the exact build, machine, Redis topology, request distribution, concurrency, and network path being claimed.

## Synthetic detection benchmark

Generate and run the deterministic synthetic fixture with:

```bash
node scripts/generate_mock_data.js
node scripts/benchmark_cicddos.js
```

Treat its accuracy/precision/recall/F1 output as **fixture-specific regression metrics** only.

## What the current evidence supports

The repository supports these bounded statements:
1. SENTINEL has an implemented multi-layer defensive architecture.
2. The recorded automated test suite exercises its major subsystems.
3. The repository includes reproducible synthetic traffic generation and benchmark execution.
4. Several operational and distributed-system mechanisms are implemented and testable.

The current evidence does **not** support:
- production-ready status;
- real-world CIC-DDoS2019 accuracy;
- a measured commercial-system advantage;
- universal scalability;
- real-network false-positive guarantees;
- a claim that tests alone prove security effectiveness.

## Reproducibility

For a new software claim, retain:
- exact commit;
- Node/dependency versions;
- command;
- fixture/dataset identity;
- machine/runtime environment when timing matters;
- raw output or test artifact;
- distinction between unit/integration evidence and external evaluation.

That keeps future benchmark claims auditable rather than inferring deployment evidence from passing tests.
