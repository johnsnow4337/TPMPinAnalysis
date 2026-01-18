
a = "20 52 45 43 56 00 20 53 00 cd 12 34 00 00 ff 06 02 02 09 11 c0 14 00 00 20 00 dc 4e 00 00 80 02 00 00 00 52 00 50 50 00 be 18 b9 3b d9 01 0a 00 ea 54 f4 9a ef e7 15 ce el ba f5 68 45 01 69 48 3b 1f aa de 99 4d 21 b9 9c 85 b6 de 70 5e 00 20 9c 2d 6d 41 ad b7 15 5b d3 9b af 72 b5 2e 99 2f c5 9e 59 33 5e cf a9 9a 28 da 45 f2 c2 56 c7 1f"
b = "45 4e 44 00 08 00 45 00 91 f1 0a 01 01 01 0a 02 05 e0 00 00 17 9d 50 10 00 00 00 a5 00 00 00 00 00 00 05 00 00 00 90 d1 00 00 ad d2 00 b9 99 cf a2 7b 26 f3 5e f6 64 40 6b d5 fd d1 57 96 lc 62 1d f5 4a 09 e9 9a 4c 31 d7 e2 8e 76 65 73 32 fb ba 2d 29 00 9d df cd 29 00 00 20 2e co 3a b6 13 ec de 58 95 61 9f 45 66 a8 18 ad"
a_split = a.split(" ")
b_split = b.split(" ")
out = []
for i in range((len(a_split)//8)+1):
    try:
        out += a_split[i*8:i*8+8]
    except:
        out += a_split[i*8:-1]
    try:
        out += b_split[i*8:i*8+8]
    except:
        out += b_split[i*8:-1]
out = "".join([j for j in out])
print(out)
