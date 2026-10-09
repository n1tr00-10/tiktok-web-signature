TikTok Signature Generator

https://img.shields.io/badge/python-3.10%2B-blue
https://img.shields.io/badge/license-MIT-green
https://img.shields.io/github/stars/n1tr00-10/tiktok-signature?style=social
https://img.shields.io/github/forks/n1tr00-10/tiktok-signature?style=social
https://img.shields.io/github/issues/n1tr00-10/tiktok-signature

Generate valid X-Gnarly, X-Bogus, and X-Dynosaur signatures for TikTok Web API requests.

Supports SDK version 5.3.2 (build 1.0.0.417).

    Need more than signatures? Profiles, followers, videos, comments, live chat and search through one REST API:
    Unofficial TikTok API - dev.omar-thing.site

Features

    Generate X-Dynosaur signatures with ChaCha20 encryption and FNV-1a hashing

    Generate X-Gnarly signatures with ChaCha20 encryption, MD5 digests and PRNG shuffle

    Generate X-Bogus placeholder (legacy compatibility)

    Support for SDK version 5.3.2 (build 1.0.0.417)

    Custom Base64 alphabet encoding

    Pure Python implementation

    Lightweight and production-ready

    No external API calls — everything computed offline

    Deterministic with fixed inputs

Installation
bash

git clone https://github.com/n1tr00-10/tiktok-signature.git
cd tiktok-signature

No dependencies beyond the Python standard library.
Versions
Component	Version
SDK	5.3.2
SCM Version	1.0.0.417
SCM Sub Version	1.0.0.2858
Release Build	1.0.0.417
Slardar SDK	1.16.6
Files
text

tiktok-signature/
├── x_dynosaur.py    # X-Dynosaur generator
├── x_gnarly.py      # X-Gnarly generator
├── x_bogus.py       # X-Bogus placeholder (legacy)
└── README.md

Usage
X-Dynosaur
python

from x_dynosaur import get_x_dynosaur

query = "aid=1988&app_name=tiktok_web&device_platform=web_pc"
user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36"
body = ""

token = get_x_dynosaur(query, user_agent, body)
print(token)

X-Gnarly
python

from x_gnarly import get_x_gnarly

query = "aid=1988&app_name=tiktok_web&device_platform=web_pc"
user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36"
body = ""

token = get_x_gnarly(query, user_agent=user_agent, body=body)
print(token)

Both signatures together
python

from x_dynosaur import get_x_dynosaur
from x_gnarly import get_x_gnarly

query = "aid=1988&app_name=tiktok_web&device_platform=web_pc"
ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36"
body = ""

dynosaur = get_x_dynosaur(query, ua, body)
gnarly = get_x_gnarly(query, dynosaur, "", ua, body)

headers = {
    "User-Agent": ua,
    "X-Dynosaur": dynosaur,
    "X-Gnarly": gnarly,
}

Optional parameters
Parameter	Default	Description
timestamp	int(time.time())	Unix timestamp
f8	session value	32-bit session field
canvas	2316120563	Canvas fingerprint value
envcode	65	Environment code
version	"5.3.2"	SDK version
scm_version	"1.0.0.417"	SCM version
security_flag	0	Security flag
flag_32	0	32-bit flag
flag_125	0	125-bit flag
url / referer	"www.tiktok.com/"	Page URL
proof_result	"0"	Proof-of-work result
key_words	random	Custom ChaCha key (12 words)
How it works

Both signatures use the same ChaCha-based cipher with:

    4 constants: [1196819126, 600974999, 3863347763, 1451689750]

    12 key words: derived from a PRNG

    Round count: (sum(key) & 0x0f) + 5

    Insert position: (sum(key_bytes) + sum(cipher)) % (len(cipher) + 1)

X-Dynosaur payload

56 fields (tags 0x20 – 0x38) containing:

    timestamp, session value, canvas, envcode

    FNV-1a hashes of query, body, user-agent

    version strings

    checksum field (0x20)

X-Gnarly payload

16 fields (indexes 0 – 16) containing:

    MD5 digests of query, body, user-agent

    timestamp, session value, canvas

    version strings

    XOR checksum fields

Fields are shuffled using a PRNG seeded from f8 before serialization.
Custom Base64 alphabet
text

u09tbS3UvgDEe6r-ZVMXzLpsAohTn7mdINQlW412GqBjfYiyk8JORCF5/xKHwacP=

Example output
bash

$ python x_dynosaur.py
MRMP5V/Rt6PX2bn1ULidanqy7eacKEz2YBXgpH2j8HRx8EhW-ZzbkeoBqaR7dIsy/zpVY6HULwxz6to7ALkG8JlXHftAM2MQpEWNZ5ao/0bmv0xC72QyhTlEojBWyKQruFF5n9NsX3QTGs-KXkqwLIRlIrH-VtycnRe4ep4E16GXMd1rlaxlo4K/ZvVWbzd3fQZhbMtB6dxcgXDILR0tlxKdCWyvZyXZRa9VRh8sGJP6RHgCJ/qulsOCYyZWXiz99g0LDAL5qTcmj3/42VqBRK/xIptGP4Ufm1UDqhcYV3w8Iz0mfmZpXI/6e1xmiBMZvopdslZ0JuXFesjV-LCqnGfIOsdyj9es1w1k2B6HmhGBjFgvZX3fkYcfEBExaLW0JNEpHAd80gVXO8v3qhThhI6PQP/tVI==

$ python x_gnarly.py
M8XFWkw1iH6BJhFC7/co/elWmsB6OkSz5bg8mMW7Tqv4bMBbrxR2HZDCpvVTL5NPV/crLH4k0c5tSd5WHhUWTWClBI2uVYZtsQD9ToeJPKomtyZgOPsgruro9PQspANV-jZi7h06i4tkMVsuhLqVVIepOSn6Ar-SIcbezpGmt5rPZsihVNpOWWzYVMhqnRz-6mZlx/xYN24kHYuIJhPNR2zhhwwfr37K41cgeD-STO8ez1b3L0YXaEbAgrGLJQl2j2OX97ihw-nTRSpq8p4gRsd4zTTbrpu-Z/OZNQlttyHMTXsDHd15qHt3ugspM9e23wZn2cjVF/Iu

Token length

Token length is not fixed. It varies between 230–420 characters depending on:

    Payload content

    Field values (timestamp, canvas, envcode, etc.)

    PRNG randomness

    Base64 padding

This is normal and expected.
FAQ

Do I need a session ID?
No. Signatures are generated locally and do not require authentication.

Do these signatures expire?
Yes. TikTok validates the timestamp embedded in the signature. Generate fresh signatures for each request.

Why is my token a different length than someone else's?
The payload contains variable-length fields (hashes, timestamps, version strings). Different inputs produce different output lengths.

Which version does this support?
SDK 5.3.2, build 1.0.0.417.

Can I use this for automation?
Yes, but always respect TikTok's Terms of Service and rate limits.
Changelog
v1.0.0 — SDK 5.3.2

    X-Dynosaur generator (ChaCha20 + FNV-1a)

    X-Gnarly generator (ChaCha20 + MD5 + PRNG shuffle)

    X-Bogus placeholder

    Custom Base64 alphabet encoding

    Support for SDK version 5.3.2 (build 1.0.0.417)

Disclaimer

This project is provided for educational and research purposes only. It is not affiliated with, endorsed by, or sponsored by TikTok or ByteDance.

Use responsibly and in accordance with TikTok's Terms of Service. The authors are not responsible for any misuse of this software.
License

MIT License — see LICENSE for details.
Credits

Made by n1tr00
