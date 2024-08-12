from math import log2, e
from sys import maxsize


def generate_partition_list(list_of_primes, mp, k):
    """ Generating the list of partitions as in OHBF paper """

    # Finding the prime closest to [mp/k]
    dis = maxsize
    pdex = 0
    for (i, e) in enumerate(list_of_primes):
        if abs(e - mp // k) < dis:
            dis = abs(e - mp // k)
            pdex = i

    sum_v = 0
    mf = 0
    for i in range(pdex - k, pdex):
        sum_v += list_of_primes[i]

    min_v = abs(sum_v - mp)
    j = pdex
    while True:
        sum_v += list_of_primes[j] - list_of_primes[j - k]
        diff = abs(sum_v - mp)
        if diff >= min_v:
            break
        min_v = diff
        j += 1

    partitions = list()
    for i in range(0, k):
        partitions.append(list_of_primes[j - k + i])
        mf += list_of_primes[i]

    return partitions


def ohbf(total_size, k, n):
    list_of_primes = []
    with open("primes.txt") as fh:
        list_of_primes = fh.readlines()
        list_of_primes = [int(prime.strip()) for prime in list_of_primes]

    partitions = generate_partition_list(list_of_primes, total_size, k)

    temp = 1
    for part in partitions:
        temp *= e ** (-n / part)
    temp = temp ** (1 / k)
    fpp = (1 - temp) ** k
    bit_security = -log2(fpp)

    print("Fpp (bit): {}".format(bit_security))
    print("Partitions", partitions)
    print("Final Size: {0}-bits .. {1}-Bytes".format(sum(partitions),sum(partitions)/8))


if __name__ == '__main__':
    # Set the parameters of the OHBF to find the security level
    """
        total_size: Defines total size of the OHBF in bits (mp parameter)
        k: Number of partitions in the OHBF
        n: Number of elements to be inserted
        
        --------------- Example ---------------
        32-bit:
            total_size: 7960
            k: 8
            n: 64
            
        64-bit:
            total_size: 32192
            k = 28
            n = 256
            
        128-bit:
            total_size: 126920
            k = 33
            n = 256
    """

    ohbf(7960, 8, 64)
    print()
    ohbf(32192, 28, 256)
    print()
    ohbf(126920, 33, 256)
