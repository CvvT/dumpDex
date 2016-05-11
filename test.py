import struct

def writeunsignedleb128(num, file):
    if num <= 0x7f:
        file.write(struct.pack("B", num))
    else:
        cur = num & 0x7F | 0x80
        file.write(struct.pack("B", cur))
        num >>= 7
        if num <= 0x7f:
            file.write(struct.pack("B", num))
        else:
            cur = num & 0x7f | 0x80
            file.write(struct.pack("B", cur))
            num >>= 7
            if num <= 0x7f:
                file.write(struct.pack("B", num))
            else:
                cur = num & 0x7f | 0x80
                file.write(struct.pack("B", cur))
                num >>= 7
                if num <= 0x7f:
                    file.write(struct.pack("B", num))
                else:
                    cur = num & 0x7f | 0x80
                    file.write(struct.pack("B", cur))
                    num >>= 7
                    file.write(struct.pack("B", num))

# with open("test.dat", "wb") as file:
#     writeunsignedleb128(0x95ee, file)
#     writeunsignedleb128(0x10001, file)
#     writeunsignedleb128(0x620440, file)
def func():
    print("hello")

def test():
    print("yes")
    return 1

list = (test() for i in range(3))
print(type(list))
for j in list:
    print(j)