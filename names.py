from string import digits, ascii_lowercase
from itertools import product

for r in range(4,5):
    for i in product(ascii_lowercase, repeat=r):
        print("".join(i))
