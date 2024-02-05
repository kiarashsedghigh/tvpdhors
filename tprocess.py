#!/usr/bin/python3
import sys

timing_file = sys.argv[1]

fh = open(timing_file)
lines = fh.readlines()
fh.close()

s8_bit_timings = list()
s16_bit_timings = list()
s32_bit_timings = list()
s64_bit_timings = list()
s128_bit_timings = list()
s256_bit_timings = list()


hash_name = str()

for line in lines:
    if "---" in line:
        hash_name = line.split('-')[0]
    elif line.startswith("8-bit"):
        s8_bit_timings.append((hash_name,  float(line.split()[1])))
    elif line.startswith("16-bit"):
        s16_bit_timings.append((hash_name,  float(line.split()[1])))
    elif line.startswith("32-bit"):
        s32_bit_timings.append((hash_name,  float(line.split()[1])))
    elif line.startswith("64-bit"):
        s64_bit_timings.append((hash_name,  float(line.split()[1])))
    elif line.startswith("128-bit"):
        s128_bit_timings.append((hash_name,  float(line.split()[1])))
    elif line.startswith("256-bit"):
        s256_bit_timings.append((hash_name,  float(line.split()[1])))


print("8-bit Data: \n-------------------")
s8_bit_timings = sorted(s8_bit_timings, key=lambda x: x[1])

for hash_time in s8_bit_timings:
    print("{}: {:.8f}".format(hash_time[0], hash_time[1]))
print("\n")




print("16-bit Data: \n-------------------")
s16_bit_timings = sorted(s16_bit_timings, key=lambda x: x[1])

for hash_time in s16_bit_timings:
    print("{}: {:.8f}".format(hash_time[0], hash_time[1]))
print("\n")


print("32-bit Data: \n-------------------")
s32_bit_timings = sorted(s32_bit_timings, key=lambda x: x[1])

for hash_time in s32_bit_timings:
    print("{}: {:.8f}".format(hash_time[0], hash_time[1]))
print("\n")


print("64-bit Data: \n-------------------")
s64_bit_timings = sorted(s64_bit_timings, key=lambda x: x[1])

for hash_time in s64_bit_timings:
    print("{}: {:.8f}".format(hash_time[0], hash_time[1]))
print("\n")


print("128-bit Data: \n-------------------")
s128_bit_timings = sorted(s128_bit_timings, key=lambda x: x[1])

for hash_time in s128_bit_timings:
    print("{}: {:.8f}".format(hash_time[0], hash_time[1]))
print("\n")


print("256-bit Data: \n-------------------")
s256_bit_timings = sorted(s256_bit_timings, key=lambda x: x[1])

for hash_time in s256_bit_timings:
    print("{}: {:.8f}".format(hash_time[0], hash_time[1]))
print("\n")
