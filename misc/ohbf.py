from math import e
from math import log2
from primePy import primes


def generate_partition_list(list_of_primes, mp, k):
    print(len(list_of_primes))
    dis = 11111111111111111111111
    pdex = 0
    for (i,e) in enumerate(list_of_primes):
        if (abs(e-mp//k) < dis):
            dis = abs(e-mp//k)
            pdex = i


    sum =0
    diff = 0
    mf = 0

    for i in range(pdex-k,pdex):
        idx = i
        if idx<0:
            idx+=100000
        sum += list_of_primes[idx]


    min = abs(sum - mp)
    j = pdex
    while True:
        sum += list_of_primes[j] - list_of_primes[j-k]
        diff = abs(sum - mp)
        if diff >= min:
            break
        min = diff
        j += 1


    partitions = list()
    for i in range(0,k):
        print(j-k)
        partitions.append(list_of_primes[j-k+i])
        mf += list_of_primes[i]


    return partitions




def ohbf(mp, k , n):
    list_of_primes = []
    with open("primes.txt") as fh:
        list_of_primes = fh.readlines()
        list_of_primes = [int(e.strip()) for e in list_of_primes]


    partitions = generate_partition_list(list_of_primes, mp,k)
    print(partitions)
    print("SUM: ", sum(partitions))

    im = 1
    for p in partitions:
        im *= e**(-n/p)
    im = im ** (1/k)
    im = 1-im
    fpp = (1-im)**k

    # print("fpp: {}".format(fpp))
    #
    bit_security = -log2(fpp)
    print("bit: {}".format(bit_security))



ohbf(1024, 18, 64)





