+++
title = "CSAW CTF Qualification Round 2021 - ncore"
date = 2021-09-13
[taxonomies]
categories = ["ctfs"]
tags = ["csawctf2021", "fpga"]
+++

# ncore

## Task description

We have a very safe core with a very safe enclave.

[ncore_tb.v](/files/csawctf2021/ncore/ncore_tb.v)
[server.py](/files/csawctf2021/ncore/server.py)

## Solution

This is a tiny cpu core with a safe enclave containing private data. Now, let's see the details.

We have some instructions:

```
`define ADD  4'd0
`define SUB  4'd1
`define AND  4'd2
`define OR   4'd3
`define RES 4'd4
`define MOVF 4'd5
`define MOVT 4'd6
`define ENT  4'd7
`define EXT  4'd8
`define JGT  4'd9
`define JEQ  4'd10
`define JMP  4'd11
`define INC  4'd12
`define MOVFS 4'd13
```

Memory, registers:

```
reg [7:0] safe_rom [0:255];
reg [7:0] ram [0:255];
reg [31:0] regfile [0:3];
reg [31:0] key [0:0];
reg emode;
```

And the "main function":

```
initial
begin: initial_block
    // $monitor(,$time,": R0: %d,R1: %d,R2: %d,R3: %d",regfile[0],regfile[1],regfile[2],regfile[3]);
    init_regs();
    emode = 0;
    set_key();
    // $display("key: %d",key[0]);
    load_safeROM();
    load_ram();
    // $display("A %h, B: %h",safe_rom[0],safe_rom[1]);
    #1500000;
    print_res();
    $finish;
end :initial_block
```

What it does is it firstly zeros the registers and the special register called emode.
Then it loads the key with a 32 bit /dev/urandom value, loads the flag.hex to safe_rom and ram.hex to ram.
After that, it runs the code for some time and after that it prints out the last 64 bytes of the ram.

So what we have to do is just copy the safe_rom to the ram to read the flag! However, the instruction we have to use, MOVFS, only works when emode is 1 and to do that using the instruction ENT, we have to guess the bottom 14 bits of the random key.

Summing up, the pseudocode for what we have to do looks like this:

```py3
# bruteforce the key
R0 = 0
R3 = 1

while R3 == 1:
    ent()
    R0 += 1

# copy the flag from safe_rom to ram
for i in range(64):
    ram[192 + i] = safe_rom[i]

# loop in place so that we don't execute the flag
while True:
    pass
```

The problem is, however, that the MOVFS/MOVT instructions only support direct addressing, so what we have to do is self-modifying code.

This is the final pseudocode.

```py3
# bruteforce the key
R0 = 0 # the key value
R2 = 1 # for the loop
R3 = 1 # emode (0 - yes, 1 - no)

while R3 == R2:
    ent()
    R0 += 1

# copy the flag from safe_rom to ram
R0 = 0   # for copying bytes
R1 = 0   # safe_rom addr (for movfs)
R2 = 192 # ram addr (for movt)
R3 = 64  # for the loop

while R1 < R3:
    # move the byte
    R0 = movfs(0) # we save this instruction's address as movfs_addr
    movt(192, R0) # we save this instruction's address as movt_addr

    # increase the counters
    R1 += 1
    R2 += 1

    # modify the MOVFS/MOVT instructions (only the 2nd byte as it holds the address)
    movt(movfs_addr + 1, R1)
    movt(movt + 1, R2)

# loop in place so that we interpret the flag as code (and potentially corrupt something)
while True:
    pass
```

The implementation:

```py3
R0 = 0
R1 = 1
R2 = 2
R3 = 3


def ent():
    return [7, 0]


def add(r1, r2, r3):
    return [0 | (r1 << 4) | (r2 << 6), r3]


def inc(r):
    return [12 | (r << 4), 0]


def jeq(r1, r2, addr):
    return [10 | (r1 << 4) | (r2 << 6), addr]


def jgt(r1, r2, addr):
    return [9 | (r1 << 4) | (r2 << 6), addr]


def jmp(addr):
    return [11, addr]


def movfs(r, addr):
    return [13 | (r << 4), addr]


def movt(addr, r):
    return [6 | (r << 4), addr]


code = []

# bruteforce the key

# set registers
code += inc(R3)
code += inc(R2)

# the loop
bruteforce_loop = len(code)
code += ent()
code += inc(R0)
code += jeq(R2, R3, bruteforce_loop)


# copy the flag from safe_rom to ram

# set registers
code += add(R0, R1, R1)
code += add(R2, R1, R1)
code += inc(R3)
for i in range(6):
    code += add(R3, R3, R3)
code += add(R2, R2, R3)
code += add(R2, R2, R3)
code += add(R2, R2, R3)

# the loop
copy_loop = len(code)
movfs_addr = len(code)
code += movfs(R0, 0)
movt_addr = len(code)
code += movt(192, R0)

code += inc(R1)
code += inc(R2)

code += movt(movfs_addr + 1, R1)
code += movt(movt_addr + 1, R2)

code += jgt(R3, R1, copy_loop)


# the endless loop
code += jmp(len(code))


with open("ram.hex", "wb") as f:
    for c in code:
        f.write(f"{c:x} ".encode())
```

And the flag: `flag{d0nT_mESs_wiTh_tHe_sChLAmi}`
