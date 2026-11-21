#!/usr/bin/env python3
"""Print the RGB of pixels in a PNG (stdlib only): png-pixel.py file.png x,y [x,y ...]"""
import struct, sys, zlib
def load(path):
    data = open(path, 'rb').read(); pos = 8; idat = b''; w = h = 0
    while pos < len(data):
        n, typ = struct.unpack('>I4s', data[pos:pos + 8]); body = data[pos + 8:pos + 8 + n]; pos += 12 + n
        if typ == b'IHDR': w, h, depth, ctype = struct.unpack('>IIBB', body[:10]); bpp = {2: 3, 6: 4}[ctype]
        elif typ == b'IDAT': idat += body
    raw = zlib.decompress(idat); stride = w * bpp; rows = []; prev = bytearray(stride); i = 0
    for _ in range(h):
        f = raw[i]; line = bytearray(raw[i + 1:i + 1 + stride]); i += 1 + stride
        for x in range(stride):
            a = line[x - bpp] if x >= bpp else 0; b = prev[x]; c = prev[x - bpp] if x >= bpp else 0
            if f == 1: line[x] = (line[x] + a) & 255
            elif f == 2: line[x] = (line[x] + b) & 255
            elif f == 3: line[x] = (line[x] + (a + b) // 2) & 255
            elif f == 4:
                p = a + b - c; pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                line[x] = (line[x] + (a if pa <= pb and pa <= pc else b if pb <= pc else c)) & 255
        rows.append(line); prev = line
    return rows, bpp
rows, bpp = load(sys.argv[1])
for xy in sys.argv[2:]:
    x, y = map(int, xy.split(',')); px = rows[y][x * bpp:x * bpp + 3]
    print(xy, 'rgb(%d, %d, %d)' % tuple(px))
