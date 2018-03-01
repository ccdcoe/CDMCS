#!/usr/bin/env python

import mmh3 as murmur

m = 100
k = 5

def add(vector, pos):
    for p in pos:
        vector[p] = True
    return vector

item = "8.8.8.8"
h1 = murmur.hash64(item)
hashes = []
print(h1)
for i in range(1, k+1):
    uniq = ( h1[0] + i * h1[1]) % m
    hashes.append(uniq)
print(hashes)
     
bitvector = [ False for i in range(m) ]
bitvector = add(bitvector, hashes)

print(bitvector)
