+++
title = "CSAW CTF Qualification Round 2021 - Weak Password"
date = 2021-09-13
[taxonomies]
tags = ["ctf"]
+++

# Weak Password

## Task description

Can you crack Aaron’s password hash? He seems to like simple passwords. I’m sure he’ll use his name and birthday in it. Hint: Aaron writes important dates as YYYYMMDD rather than YYYY-MM-DD or any other special character separator. Once you crack the password, prepend it with flag{ and append it with } to submit the flag with our standard format. Hash: `7f4986da7d7b52fa81f98278e6ec9dcb`.

Author: moat, Pacific Northwest National Laboratory

## Solution

Using [hash identifier](https://hashes.com/en/tools/hash_identifier) I found out that it's a md5 hash.

And using [md5 decrypt](https://www.md5online.org/md5-decrypt.html) I got the flag: `flag{Aaron19800321}`
