"""Deterministic cross-credential access workloads."""
import random


def generate(name, leaves, accesses, seed):
    if leaves < 2 or accesses < 1: raise ValueError("leaves >= 2 and accesses >= 1 required")
    rng = random.Random(seed)
    if name == "uniform":
        return [rng.randrange(leaves) for _ in range(accesses)]
    if name == "zipf":
        popularity = list(range(leaves)); rng.shuffle(popularity)
        weights = [1 / ((rank + 1) ** 1.2) for rank in range(leaves)]
        return rng.choices(popularity, weights=weights, k=accesses)
    if name == "clustered":
        cluster = max(2, min(16, leaves // 4)); center = rng.randrange(leaves)
        result = []
        for _ in range(accesses):
            if rng.random() < .15: center = rng.randrange(leaves)
            start = min(max(0, center - cluster // 2), leaves - cluster)
            result.append(start + rng.randrange(cluster))
        return result
    if name == "targeted":
        base = [0, 0, 1, min(2, leaves-1), min(3, leaves-1), min(leaves//4, leaves-1), min(leaves//2, leaves-1), leaves-1]
        return [base[i % len(base)] for i in range(accesses)]
    raise ValueError("unknown workload")
