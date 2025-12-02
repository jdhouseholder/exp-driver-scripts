from typing import List
import xxhash


class HashTableClient:
    def __init__(self, seeds, capacity):
        self.seeds = seeds
        self.capacity = capacity

        self.digests = [xxhash.xxh64(seed=seed) for seed in seeds]

    def indicies_for(self, key):
        out = []
        for d in self.digests:
            d.reset()
            d.update(key)
            i = d.intdigest()
            out.append(i % self.capacity)
        return out


if __name__ == "__main__":
    htc = HashTableClient(seeds=[54, 23, 5], capacity=320_000_000)
    print(htc.indicies_for(b"wow"))
