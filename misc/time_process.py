#!/usr/bin/python3
import sys

timing_file = sys.argv[1]

fh = open(timing_file)
lines = fh.readlines()
fh.close()

s1B_timings = list()
s2B_timings = list()
s4B_timings = list()
s8B_timings = list()
s16B_timings = list()
s32B_timings = list()
s64B_timings = list()
s128B_timings = list()
s256B_timings = list()
s512B_timings = list()

s1K_timings = list()
s2K_timings = list()
s4K_timings = list()
s8K_timings = list()
s16K_timings = list()
s32K_timings = list()
s64K_timings = list()
s128K_timings = list()
s256K_timings = list()
s512K_timings = list()

s1M_timings = list()
s2M_timings = list()
s4M_timings = list()
s8M_timings = list()
s16M_timings = list()
s32M_timings = list()
s64M_timings = list()
s128M_timings = list()
s256M_timings = list()

hash_name = str()

for line in lines:
    if "---" in line:
        hash_name = line.split('-')[0]
    elif line.startswith("1B"):
        s1B_timings.append((hash_name,  float(line.split()[1])))
    elif line.startswith("2B"):
        s2B_timings.append((hash_name,  float(line.split()[1])))
    elif line.startswith("4B"):
        s4B_timings.append((hash_name,  float(line.split()[1])))
    elif line.startswith("8B"):
        s8B_timings.append((hash_name,  float(line.split()[1])))
    elif line.startswith("16B"):
        s16B_timings.append((hash_name,  float(line.split()[1])))
    elif line.startswith("32B"):
        s32B_timings.append((hash_name,  float(line.split()[1])))
    elif line.startswith("64B"):
        s64B_timings.append((hash_name,  float(line.split()[1])))
    elif line.startswith("128B"):
        s128B_timings.append((hash_name,  float(line.split()[1])))
    elif line.startswith("256B"):
        s256B_timings.append((hash_name,  float(line.split()[1])))
    elif line.startswith("512B"):
        s512B_timings.append((hash_name,  float(line.split()[1])))

    elif line.startswith("1K"):
        s1K_timings.append((hash_name,  float(line.split()[1])))
    elif line.startswith("2K"):
        s2K_timings.append((hash_name,  float(line.split()[1])))
    elif line.startswith("4K"):
        s4K_timings.append((hash_name,  float(line.split()[1])))
    elif line.startswith("8K"):
        s8K_timings.append((hash_name,  float(line.split()[1])))
    elif line.startswith("16K"):
        s16K_timings.append((hash_name,  float(line.split()[1])))
    elif line.startswith("32K"):
        s32K_timings.append((hash_name,  float(line.split()[1])))
    elif line.startswith("64K"):
        s64K_timings.append((hash_name,  float(line.split()[1])))
    elif line.startswith("128K"):
        s128K_timings.append((hash_name,  float(line.split()[1])))
    elif line.startswith("256K"):
        s256K_timings.append((hash_name,  float(line.split()[1])))
    elif line.startswith("512K"):
        s512K_timings.append((hash_name,  float(line.split()[1])))


    elif line.startswith("1M"):
        s1M_timings.append((hash_name,  float(line.split()[1])))
    elif line.startswith("2M"):
        s2M_timings.append((hash_name,  float(line.split()[1])))
    elif line.startswith("4M"):
        s4M_timings.append((hash_name,  float(line.split()[1])))
    elif line.startswith("8M"):
        s8M_timings.append((hash_name,  float(line.split()[1])))
    elif line.startswith("16M"):
        s16M_timings.append((hash_name,  float(line.split()[1])))
    elif line.startswith("32M"):
        s32M_timings.append((hash_name,  float(line.split()[1])))
    elif line.startswith("64M"):
        s64M_timings.append((hash_name,  float(line.split()[1])))
    elif line.startswith("128M"):
        s128M_timings.append((hash_name,  float(line.split()[1])))
    elif line.startswith("256M"):
        s256M_timings.append((hash_name,  float(line.split()[1])))
    elif line.startswith("512M"):
        s512M_timings.append((hash_name,  float(line.split()[1])))





print("1B Data: \n-------------------")
s1B_timings = sorted(s1B_timings, key=lambda x: x[1])
print("X: {}\n##".format(s1B_timings[-1][1]//s1B_timings[0][1]))

for hash_time in s1B_timings:
    print("{}: {:.8f}".format(hash_time[0], hash_time[1]))
print("\n")


print("2B Data: \n-------------------")
s2B_timings = sorted(s2B_timings, key=lambda x: x[1])
print("X: {}\n##".format(s2B_timings[-1][1]//s2B_timings[0][1]))

for hash_time in s2B_timings:
    print("{}: {:.8f}".format(hash_time[0], hash_time[1]))
print("\n")


print("4B Data: \n-------------------")
s4B_timings = sorted(s4B_timings, key=lambda x: x[1])
print("X: {}\n##".format(s4B_timings[-1][1]//s4B_timings[0][1]))

for hash_time in s4B_timings:
    print("{}: {:.8f}".format(hash_time[0], hash_time[1]))
print("\n")


print("8B Data: \n-------------------")
s8B_timings = sorted(s8B_timings, key=lambda x: x[1])
print("X: {}\n##".format(s8B_timings[-1][1]//s8B_timings[0][1]))

for hash_time in s8B_timings:
    print("{}: {:.8f}".format(hash_time[0], hash_time[1]))
print("\n")


print("16B Data: \n-------------------")
s16B_timings = sorted(s16B_timings, key=lambda x: x[1])
print("X: {}\n##".format(s16B_timings[-1][1]//s16B_timings[0][1]))

for hash_time in s16B_timings:
    print("{}: {:.8f}".format(hash_time[0], hash_time[1]))
print("\n")


print("32B Data: \n-------------------")
s32B_timings = sorted(s32B_timings, key=lambda x: x[1])
print("X: {}\n##".format(s32B_timings[-1][1]//s32B_timings[0][1]))

for hash_time in s32B_timings:
    print("{}: {:.8f}".format(hash_time[0], hash_time[1]))
print("\n")

print("64B Data: \n-------------------")
s64B_timings = sorted(s64B_timings, key=lambda x: x[1])
print("X: {}\n##".format(s64B_timings[-1][1]//s64B_timings[0][1]))

for hash_time in s64B_timings:
    print("{}: {:.8f}".format(hash_time[0], hash_time[1]))
print("\n")


print("128B Data: \n-------------------")
s128B_timings = sorted(s128B_timings, key=lambda x: x[1])
print("X: {}\n##".format(s128B_timings[-1][1]//s128B_timings[0][1]))

for hash_time in s128B_timings:
    print("{}: {:.8f}".format(hash_time[0], hash_time[1]))
print("\n")

print("256B Data: \n-------------------")
s256B_timings = sorted(s256B_timings, key=lambda x: x[1])
print("X: {}\n##".format(s256B_timings[-1][1]//s256B_timings[0][1]))

for hash_time in s256B_timings:
    print("{}: {:.8f}".format(hash_time[0], hash_time[1]))
print("\n")


print("512B Data: \n-------------------")
s512B_timings = sorted(s512B_timings, key=lambda x: x[1])
print("X: {}\n##".format(s512B_timings[-1][1]//s512B_timings[0][1]))

for hash_time in s512B_timings:
    print("{}: {:.8f}".format(hash_time[0], hash_time[1]))
print("\n")









print("1K Data: \n-------------------")
s1K_timings = sorted(s1K_timings, key=lambda x: x[1])
print("X: {}\n##".format(s1K_timings[-1][1]//s1K_timings[0][1]))

for hash_time in s1K_timings:
    print("{}: {:.8f}".format(hash_time[0], hash_time[1]))
print("\n")


print("2K Data: \n-------------------")
s2K_timings = sorted(s2K_timings, key=lambda x: x[1])
print("X: {}\n##".format(s2K_timings[-1][1]//s2K_timings[0][1]))

for hash_time in s2K_timings:
    print("{}: {:.8f}".format(hash_time[0], hash_time[1]))
print("\n")


print("4K Data: \n-------------------")
s4K_timings = sorted(s4K_timings, key=lambda x: x[1])
print("X: {}\n##".format(s4K_timings[-1][1]//s4K_timings[0][1]))

for hash_time in s4K_timings:
    print("{}: {:.8f}".format(hash_time[0], hash_time[1]))
print("\n")


print("8K Data: \n-------------------")
s8K_timings = sorted(s8K_timings, key=lambda x: x[1])
print("X: {}\n##".format(s8K_timings[-1][1]//s8K_timings[0][1]))

for hash_time in s8K_timings:
    print("{}: {:.8f}".format(hash_time[0], hash_time[1]))
print("\n")


print("16K Data: \n-------------------")
s16K_timings = sorted(s16K_timings, key=lambda x: x[1])
print("X: {}\n##".format(s16K_timings[-1][1]//s16K_timings[0][1]))

for hash_time in s16K_timings:
    print("{}: {:.8f}".format(hash_time[0], hash_time[1]))
print("\n")


print("32K Data: \n-------------------")
s32K_timings = sorted(s32K_timings, key=lambda x: x[1])
print("X: {}\n##".format(s32K_timings[-1][1]//s32K_timings[0][1]))

for hash_time in s32K_timings:
    print("{}: {:.8f}".format(hash_time[0], hash_time[1]))
print("\n")

print("64K Data: \n-------------------")
s64K_timings = sorted(s64K_timings, key=lambda x: x[1])
print("X: {}\n##".format(s64K_timings[-1][1]//s64K_timings[0][1]))

for hash_time in s64K_timings:
    print("{}: {:.8f}".format(hash_time[0], hash_time[1]))
print("\n")


print("128K Data: \n-------------------")
s128K_timings = sorted(s128K_timings, key=lambda x: x[1])
print("X: {}\n##".format(s128K_timings[-1][1]//s128K_timings[0][1]))

for hash_time in s128K_timings:
    print("{}: {:.8f}".format(hash_time[0], hash_time[1]))
print("\n")

print("256K Data: \n-------------------")
s256K_timings = sorted(s256K_timings, key=lambda x: x[1])
print("X: {}\n##".format(s256K_timings[-1][1]//s256K_timings[0][1]))

for hash_time in s256K_timings:
    print("{}: {:.8f}".format(hash_time[0], hash_time[1]))
print("\n")


print("512K Data: \n-------------------")
s512K_timings = sorted(s512K_timings, key=lambda x: x[1])
print("X: {}\n##".format(s512K_timings[-1][1]//s512K_timings[0][1]))

for hash_time in s512K_timings:
    print("{}: {:.8f}".format(hash_time[0], hash_time[1]))
print("\n")







print("1M Data: \n-------------------")
s1M_timings = sorted(s1M_timings, key=lambda x: x[1])
print("X: {}\n##".format(s1M_timings[-1][1]//s1M_timings[0][1]))

for hash_time in s1M_timings:
    print("{}: {:.8f}".format(hash_time[0], hash_time[1]))
print("\n")


print("2M Data: \n-------------------")
s2M_timings = sorted(s2M_timings, key=lambda x: x[1])
print("X: {}\n##".format(s2M_timings[-1][1]//s2M_timings[0][1]))

for hash_time in s2M_timings:
    print("{}: {:.8f}".format(hash_time[0], hash_time[1]))
print("\n")


print("4M Data: \n-------------------")
s4M_timings = sorted(s4M_timings, key=lambda x: x[1])
print("X: {}\n##".format(s4M_timings[-1][1]//s4M_timings[0][1]))

for hash_time in s4M_timings:
    print("{}: {:.8f}".format(hash_time[0], hash_time[1]))
print("\n")


print("8M Data: \n-------------------")
s8M_timings = sorted(s8M_timings, key=lambda x: x[1])
print("X: {}\n##".format(s8M_timings[-1][1]//s8M_timings[0][1]))

for hash_time in s8M_timings:
    print("{}: {:.8f}".format(hash_time[0], hash_time[1]))
print("\n")


print("16M Data: \n-------------------")
s16M_timings = sorted(s16M_timings, key=lambda x: x[1])
print("X: {}\n##".format(s16M_timings[-1][1]//s16M_timings[0][1]))

for hash_time in s16M_timings:
    print("{}: {:.8f}".format(hash_time[0], hash_time[1]))
print("\n")


print("32M Data: \n-------------------")
s32M_timings = sorted(s32M_timings, key=lambda x: x[1])
print("X: {}\n##".format(s32M_timings[-1][1]//s32M_timings[0][1]))

for hash_time in s32M_timings:
    print("{}: {:.8f}".format(hash_time[0], hash_time[1]))
print("\n")

print("64M Data: \n-------------------")
s64M_timings = sorted(s64M_timings, key=lambda x: x[1])
print("X: {}\n##".format(s64M_timings[-1][1]//s64M_timings[0][1]))

for hash_time in s64M_timings:
    print("{}: {:.8f}".format(hash_time[0], hash_time[1]))
print("\n")


print("128M Data: \n-------------------")
s128M_timings = sorted(s128M_timings, key=lambda x: x[1])
print("X: {}\n##".format(s128M_timings[-1][1]//s128M_timings[0][1]))

for hash_time in s128M_timings:
    print("{}: {:.8f}".format(hash_time[0], hash_time[1]))
print("\n")



print("256M Data: \n-------------------")
s256M_timings = sorted(s256M_timings, key=lambda x: x[1])
print("X: {}\n##".format(s256M_timings[-1][1]//s256M_timings[0][1]))

for hash_time in s256M_timings:
    print("{}: {:.8f}".format(hash_time[0], hash_time[1]))
print("\n")







