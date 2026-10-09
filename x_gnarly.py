import base64
import hashlib
import secrets
import struct
import time
import math


class sexer:
    const = [1196819126, 600974999, 3863347763, 1451689750]

    def __init__(self, key):
        self.key = [w & 0xffffffff for w in key]
        acc = 0
        for w in self.key:
            acc = (acc + (w & 0x0f)) & 0x0f
        self.rounds = acc + 5
        self.state = self.const + self.key

    @staticmethod
    def rotl(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xffffffff

    @classmethod
    def quarter(cls, s, a, b, c, d):
        s[a] = (s[a] + s[b]) & 0xffffffff; s[d] = cls.rotl(s[d] ^ s[a], 16)
        s[c] = (s[c] + s[d]) & 0xffffffff; s[b] = cls.rotl(s[b] ^ s[c], 12)
        s[a] = (s[a] + s[b]) & 0xffffffff; s[d] = cls.rotl(s[d] ^ s[a], 8)
        s[c] = (s[c] + s[d]) & 0xffffffff; s[b] = cls.rotl(s[b] ^ s[c], 7)

    @classmethod
    def block(cls, state, rounds):
        w = state.copy()
        r = 0
        while r < rounds:
            cls.quarter(w, 0, 4, 8, 12); cls.quarter(w, 1, 5, 9, 13)
            cls.quarter(w, 2, 6, 10, 14); cls.quarter(w, 3, 7, 11, 15)
            r += 1
            if r >= rounds:
                break
            cls.quarter(w, 0, 5, 10, 15); cls.quarter(w, 1, 6, 11, 12)
            cls.quarter(w, 2, 7, 12, 13); cls.quarter(w, 3, 4, 13, 14)
            r += 1
        return [(w[i] + state[i]) & 0xffffffff for i in range(16)]

    def encrypt(self, data: bytes) -> bytes:
        buf = bytearray(data)
        n_full = len(buf) // 4
        rem = len(buf) % 4
        words = [0] * ((len(buf) + 3) // 4)

        for i in range(n_full):
            j = 4 * i
            words[i] = buf[j] | (buf[j + 1] << 8) | (buf[j + 2] << 16) | (buf[j + 3] << 24)
        if rem:
            for c in range(rem):
                words[n_full] |= buf[4 * n_full + c] << (8 * c)

        state = self.state.copy()
        off = 0
        while off + 16 < len(words):
            stream = self.block(state, self.rounds)
            state[12] = (state[12] + 1) & 0xffffffff
            for k in range(16):
                words[off + k] ^= stream[k]
            off += 16
        stream = self.block(state, self.rounds)
        for k in range(len(words) - off):
            words[off + k] ^= stream[k]

        for i in range(n_full):
            j = 4 * i
            w = words[i]
            buf[j] = w & 0xff; buf[j + 1] = (w >> 8) & 0xff
            buf[j + 2] = (w >> 16) & 0xff; buf[j + 3] = (w >> 24) & 0xff
        if rem:
            w = words[n_full]
            for c in range(rem):
                buf[4 * n_full + c] = (w >> (8 * c)) & 0xff
        return bytes(buf)


prng_state = None
prng_pos = 0


def prng_init():
    global prng_state, prng_pos
    ts_ms = int(time.time() * 1000)
    prng_state = [
        2517678443, 2718276124, 3212677781, 2633865432,
        217618912, 2931180889, 1498001188, 2157053261,
        211147047, 185100057, 2903579748, 3732962506,
        0xffffffff & ts_ms,
        secrets.randbelow(4294967296),
        secrets.randbelow(4294967296),
        secrets.randbelow(4294967296),
    ]
    prng_pos = 0


def prng_next_float():
    global prng_state, prng_pos
    if prng_state is None:
        prng_init()
    block = sexer.block(prng_state, 8)
    hi = block[prng_pos]
    lo = (block[prng_pos + 8] & 0xfffffff0) >> 11
    if prng_pos == 7:
        prng_state[12] = (prng_state[12] + 1) & 0xffffffff
        prng_pos = 0
    else:
        prng_pos += 1
    return (hi + 4294967296 * lo) / (2 ** 53)


def prng_next_u32():
    return int(prng_next_float() * 4294967296)


def prng_shuffle(items, seed):
    state = int(seed) & 0xffffffff
    for i in range(len(items) - 1, 0, -1):
        state = (1664525 * state + 1013904223) & 0xffffffff
        j = (state * (i + 1)) // 4294967296
        items[i], items[j] = items[j], items[i]


def js_utf8(text):
    text = str(text)
    return text.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "replace").encode("utf-8")


_session_value = None


def session_value():
    global _session_value
    if _session_value is None:
        rng = secrets.SystemRandom()
        _session_value = math.floor(abs(((int(time.time() * 1000) + rng.random() + rng.random()) * 1000) % 2147483648))
    return _session_value


def gen_key():
    words = [prng_next_u32() for _ in range(12)]
    raw = bytearray()
    for w in words:
        raw.extend(struct.pack("<I", w))
    return words, raw


def calc_insert_pos(key_bytes, cipher_bytes):
    pos = 0
    mod = len(cipher_bytes) + 1
    for b in key_bytes:
        pos = (pos + b) % mod
    for b in cipher_bytes:
        pos = (pos + b) % mod
    return pos


def b64_custom(data: bytes) -> str:
    std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    alt = "u09tbS3UvgDEe6r-ZVMXzLpsAohTn7mdINQlW412GqBjfYiyk8JORCF5/xKHwacP="
    return base64.b64encode(data).decode("latin-1").translate(str.maketrans(std, alt))


def pack_uint_be(val):
    val = int(val) & 0xffffffff
    return struct.pack(">H", val) if val < 0xfe01 else struct.pack(">I", val)


def build_fields(query, body, ua, ts, f8, canvas=2316120563, version="5.3.2", scm_ver="1.0.0.417", envcode=65, flag=0, flag_32=0, flag_125=0, *, field15_mode=2, digests=None):
    digests = digests or {}
    def md5(name, text):
        value = digests.get(name)
        if value is None:
            return hashlib.md5(js_utf8(text)).hexdigest()
        return str(value)
    obj = {
        1: envcode,
        2: flag,
        3: md5("query", query),
        4: md5("body", body),
        5: md5("ua", ua),
        6: ts,
        7: canvas,
        8: f8,
        9: version,
        10: scm_ver,
        11: 1,
        12: flag_125,
        13: flag_32,
        14: (envcode << 16) | ((ts >> 16) ^ (f8 >> 16) ^ (ts & 0xffff) ^ (f8 & 0xffff)),
        15: (((((canvas if field15_mode == 2 else ts) & 0xffff) ^ (f8 >> 16)) & 0xffff) << 16) | ((ts & 0xffff) ^ (f8 & 0xffff)),
    }

    obj = {k: (v & 0xffffffff) if isinstance(v, int) else v for k, v in obj.items()}

    chk_all = 0
    for i in range(1, len(obj) + 1):
        v = obj[i]
        chk_all ^= v if isinstance(v, int) else int.from_bytes(js_utf8(v)[:4], "big")
    obj[len(obj) + 1] = chk_all

    chk_int = 0
    for i in range(1, len(obj) + 1):
        v = obj[i]
        if isinstance(v, int):
            chk_int ^= v
    obj[0] = chk_int

    order = list(range(len(obj)))
    prng_shuffle(order, f8)

    buf = bytearray([len(obj)])
    for idx in order:
        buf.append(idx)
        val = obj[idx]
        val_b = pack_uint_be(val) if isinstance(val, int) else js_utf8(val)
        buf.extend(pack_uint_be(len(val_b)))
        buf.extend(val_b)
    return bytes(buf)


def get_x_gnarly(query: str, x_dynosaur: str = "", ms_token: str = "", user_agent: str = "", body: str = "", **kwargs) -> str:
    ts = kwargs.get("timestamp", int(time.time()))
    f8 = int(kwargs["f8"]) if "f8" in kwargs else session_value()
    flag = kwargs.get("security_flag", 0)
    envcode = kwargs.get("envcode", 65)
    flag_32 = kwargs.get("flag_32", kwargs.get("fixed_32", kwargs.get("ixr", 0) + kwargs.get("ifr", 0)))
    flag_125 = kwargs.get("flag_125", kwargs.get("fixed_125", kwargs.get("txr", 0) + kwargs.get("tfr", 0)))
    canvas = kwargs.get("canvas", 2316120563)
    version = kwargs.get("version", "5.3.2")
    scm_ver = kwargs.get("scm_version", "1.0.0.417")

    payload = build_fields(
        query=query,
        body=body,
        ua=user_agent,
        ts=ts,
        f8=f8,
        canvas=canvas,
        version=version,
        scm_ver=scm_ver,
        envcode=envcode,
        field15_mode=kwargs.get("field15_mode", 2),
        digests=kwargs.get("digests"),
        flag=flag,
        flag_32=flag_32,
        flag_125=flag_125,
    )
    if kwargs.get("key_words") is None:
        key_words, key_bytes = gen_key()
    else:
        key_words = [int(w) & 0xffffffff for w in kwargs["key_words"]]
        if len(key_words) < 12:
            key_words.extend([0] * (12 - len(key_words)))
        elif len(key_words) > 12:
            key_words = key_words[:12]
        key_bytes = struct.pack("<12I", *key_words)

    cipher = sexer(key_words).encrypt(payload)
    pos = calc_insert_pos(key_bytes, cipher)

    packed = cipher[:pos] + key_bytes + cipher[pos:]
    return b64_custom(b"\x4b" + packed)


get_X_Gnarly = get_x_gnarly


if __name__ == "__main__":
    query = "aid=1988&app_name=tiktok_web"
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36"
    print(get_x_gnarly(query, user_agent=ua))
