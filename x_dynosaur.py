import base64
import secrets
import struct
import time
import math


class crypto:
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


def prng_next_u32():
    global prng_state, prng_pos
    if prng_state is None:
        prng_init()
    block = crypto.block(prng_state, 8)
    hi = block[prng_pos]
    lo = (block[prng_pos + 8] & 0xfffffff0) >> 11
    if prng_pos == 7:
        prng_state[12] = (prng_state[12] + 1) & 0xffffffff
        prng_pos = 0
    else:
        prng_pos += 1
    val = (hi + 4294967296 * lo) / (2 ** 53)
    return int(val * 4294967296)


def gen_key():
    words = [prng_next_u32() for _ in range(12)]
    raw = bytearray()
    for w in words:
        raw.extend(struct.pack("<I", w))
    return words, bytes(raw)


def b64_custom(data: bytes) -> str:
    std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    alt = "u09tbS3UvgDEe6r-ZVMXzLpsAohTn7mdINQlW412GqBjfYiyk8JORCF5/xKHwacP="
    return base64.b64encode(data).decode("latin-1").translate(str.maketrans(std, alt))


def js_utf8(text):
    text = str(text)
    return text.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "replace").encode("utf-8")


_session_value = None


def session_value():
    global _session_value
    if _session_value is None:
        rand = secrets.SystemRandom()
        _session_value = math.floor(abs(((int(time.time() * 1000) + rand.random() + rand.random()) * 1000) % 2147483648))
    return _session_value


def fnv1a(text: str) -> int:
    h = 2166136260
    for b in js_utf8(text):
        h = (((h ^ b) * 16777619) & 0xffffffff) * 33 & 0xffffffff
    return h


def encode_field(text, nonce=False) -> bytes:
    text = str(text)
    raw = text.encode("utf-16-le", "surrogatepass")
    units = struct.unpack('<%dH' % (len(raw) // 2), raw)
    out = bytearray(max(len(units), 4) + 2)
    for idx, ch in enumerate(units):
        if nonce:
            val = ((ch ^ (102 + idx)) + (idx & 0xaa)) ^ 0xa5
            val = (val << 1) + ((val << 1) >> 8)
            out[idx] = (val & 0xff) ^ 0xbb
        else:
            val = ((ch ^ ((103 + idx) & 0xff)) + ((idx & 0xaa) + 1)) & 0xff
            val = (val << 2) | (val >> 6)
            out[idx] = (((val & 0xff) ^ 0xbb) + 1) & 0xff
    for idx in range(len(units), 4):
        out[idx] = 0xdd + idx
    out[-2:] = (len(units) & 0xffff).to_bytes(2, "big")
    return bytes(out)


def build_payload(query: str, user_agent: str = "", body: str = "", ms_token: str = "", **kwargs) -> bytes:
    if query.startswith("http"):
        query = query.split("?", 1)[1] if "?" in query else query

    ts = int(kwargs.get("timestamp", time.time()))
    field8 = int(kwargs["f8"]) if "f8" in kwargs else session_value()
    canvas = kwargs.get("canvas", 2316120563)
    envcode = kwargs.get("envcode", 65)
    proof_result = str(kwargs.get("proof_result", "0"))
    
    page_url = kwargs.get("url", kwargs.get("referer", "www.tiktok.com/"))
    if "://" in page_url:
        page_url = page_url.split("://", 1)[1].split("?")[0]

    half = (ts >> 16) ^ (field8 >> 16) ^ (ts & 0xffff) ^ (field8 & 0xffff)
    field14 = ((envcode << 16) | half) & 0xffffffff

    fixed = bytes((94, 222, 223, 224, 0, 1))
    pack_hash = lambda v: (v & 0xffffffff).to_bytes(4, "big")

    flag = kwargs.get("security_flag", 0)
    flag_32 = kwargs.get("flag_32", kwargs.get("fixed_32", kwargs.get("ixr", 0) + kwargs.get("ifr", 0)))
    flag_125 = kwargs.get("flag_125", kwargs.get("fixed_125", kwargs.get("txr", 0) + kwargs.get("tfr", 0)))

    def hash_value(name, text):
        return int(kwargs[name]) & 0xffffffff if name in kwargs else fnv1a(text)

    entries = [
        (0x20, fixed),
        (0x21, fixed),
        (0x22, fixed),
        (0x23, encode_field("0")),
        (0x24, encode_field(field14)),
        (0x25, encode_field(flag_32)),
        (0x26, encode_field(envcode)),
        (0x27, encode_field(ts)),
        (0x28, encode_field(proof_result)),
        (0x29, encode_field("0")),
        (0x2a, encode_field(kwargs.get("version", "5.3.2"))),
        (0x2b, pack_hash(hash_value("body_hash", body))),
        (0x2c, encode_field(canvas)),
        (0x2d, encode_field("0")),
        (0x2e, pack_hash(hash_value("query_hash", query))),
        (0x2f, encode_field(flag_125)),
        (0x30, pack_hash(hash_value("ua_hash", user_agent))),
        (0x31, encode_field(kwargs.get("scm_version", "1.0.0.417"))),
        (0x32, encode_field(kwargs.get("ex_scm_version", kwargs.get("scm_sub_version", "1.0.0.2858")))),
        (0x33, encode_field(kwargs.get("ex_bundle_code", "0"))),
        (0x34, encode_field(field8)),
        (0x35, encode_field(page_url)),
        (0x36, encode_field(flag)),
        (0x37, encode_field("0")),
        (0x38, pack_hash(hash_value("proof_hash", kwargs.get("ex_bundle_proof", "")))),
    ]

    checksum = 0
    for _, val in entries:
        if len(val) > 1:
            checksum ^= val[1]
    entries[0] = (0x20, encode_field(checksum, nonce=True))

    payload = bytearray()
    for tag, val in entries:
        payload.append(tag)
        payload.extend(struct.pack(">H", len(val)) if len(val) < 0xfe01 else struct.pack(">I", len(val)))
        payload.extend(val)

    return bytes(payload)


def encrypt_payload(payload, key_words=None):
    if key_words is None:
        key_words, key_bytes = gen_key()
    else:
        key_words = [int(w) & 0xffffffff for w in key_words]
        if len(key_words) < 12:
            key_words.extend([0] * (12 - len(key_words)))
        elif len(key_words) > 12:
            key_words = key_words[:12]
        key_bytes = struct.pack("<12I", *key_words)
    cipher = crypto(key_words).encrypt(bytes(payload))
    pos = (sum(key_bytes) + sum(cipher)) % (len(cipher) + 1)
    return b64_custom(b"\x4b" + cipher[:pos] + key_bytes + cipher[pos:])


def get_x_dynosaur(query, user_agent="", body="", ms_token="", **kwargs):
    return encrypt_payload(build_payload(query, user_agent, body, ms_token, **kwargs),
                           kwargs.get("key_words"))


get_X_Dynosaur = get_x_dynosaur


if __name__ == "__main__":
    query = "aid=1988&app_name=tiktok_web"
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36"
    print(get_x_dynosaur(query, ua))
