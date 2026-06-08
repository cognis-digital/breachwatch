# Scenario: Annual employee credential audit

3 employees checked. Alice exposed in stealer log (assume full compromise). Bob in old Adobe leak.

## Expected findings

- BW-HIT-001 × 2
- BW-STEALER-001 (critical) — Alice

## Why this matters

Alice's full machine compromise needs IR. Force rotation for Bob too.
