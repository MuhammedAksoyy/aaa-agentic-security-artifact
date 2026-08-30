#!/usr/bin/env python3
"""Reproduce the blind D3 Cohen's kappa from d3-blind-ratings.csv."""
import csv
from collections import Counter

EXPAND = {"m": "mediated", "p": "partial", "u": "unmediated", "n/a": "n/a"}


def main():
    with open("d3-blind-ratings.csv", newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    first = {r["tool_id"]: EXPAND[r["muhammed_raw"].strip().lower()] for r in rows}
    second = {r["tool_id"]: r["yakup_raw"].strip().lower() for r in rows}
    assert set(first) == set(second)
    n = len(rows)
    agree = sum(first[k] == second[k] for k in first)
    po = agree / n
    c1, c2 = Counter(first.values()), Counter(second.values())
    pe = sum((c1.get(k, 0) / n) * (c2.get(k, 0) / n) for k in set(c1) | set(c2))
    kappa = (po - pe) / (1 - pe)
    print(f"n={n} agree={agree} po={po:.4f} pe={pe:.4f} kappa={kappa:.3f}")
    print("Muhammed:", c1)
    print("Yakup:", c2)


if __name__ == "__main__":
    main()
