+++
title = "YauzaCTF 2021 - ARC6969 P.2"
date = 2021-08-31
[taxonomies]
tags = ["ctf", "embedded"]
+++

# Task description

The ARC6969 is an old and forgotten architecture used in a military computers during Cold War. Although we don't have the computers anymore, we got CPU manual and a few programs.

[manual_2.pdf](/files/yauzactf2021/arc6969p2/manual_2.pdf)
[rom_2.bin](/files/yauzactf2021/arc6969p2/rom_2.bin)

# Solution

Now this CPU architecture is way more complicated than the first emulation task. It has 32 8bit registers, 4 flags (ZF, CF, SF and OF) and a 64x32 6bit color screen! The instructions are either 3 or 2 bytes (haven't noticed it at the beginning, lost me an hour).

This is the code.

```py3
import pygame

debug = False

pixel_width = 16
pixel_height = 16

width = 64 * pixel_width
height = 32 * pixel_height

gpu_x = 0
gpu_y = 0
screen = pygame.display.set_mode((width, height))

pc = 0
regs = [0] * 32
fr = [False] * 8
halt = False

serial_input = ""

rom = open("rom_1.bin", "rb").read()
ram = bytearray(rom) + bytearray([0] * (0xFFFF - len(rom)))

# print(rom[949 : 949 + 31])
# quit(0)


def add(reg1, reg2, reg3):
    global regs
    reg3 &= 0x1F
    regs[reg1] = regs[reg2] + regs[reg3]
    regs[reg1] &= 0xFF

    if debug:
        print(f"add r{reg1} r{reg2} r{reg3}")


def addi(reg1, reg2, imm8):
    global regs
    regs[reg1] = regs[reg2] + imm8
    regs[reg1] &= 0xFF

    if debug:
        print(f"addi r{reg1} r{reg2} {imm8}")


def sub(reg1, reg2, reg3):
    global regs
    reg3 &= 0x1F
    regs[reg1] = regs[reg2] - regs[reg3]
    regs[reg1] &= 0xFF

    if debug:
        print(f"sub r{reg1} r{reg2} r{reg3}")


def subi(reg1, reg2, imm8):
    global regs
    regs[reg1] = regs[reg2] - imm8
    regs[reg1] &= 0xFF

    if debug:
        print(f"subi r{reg1} r{reg2} {imm8}")


def or_op(reg1, reg2, reg3):
    global regs
    reg3 &= 0x1F
    regs[reg1] = regs[reg2] | regs[reg3]

    if debug:
        print(f"or r{reg1} r{reg2} r{reg3}")


def ori(reg1, reg2, imm8):
    global regs
    regs[reg1] = regs[reg2] | imm8

    if debug:
        print(f"ori r{reg1} r{reg2} {imm8}")


def and_op(reg1, reg2, reg3):
    global regs
    reg3 &= 0x1F
    regs[reg1] = regs[reg2] & regs[reg3]

    if debug:
        print(f"and r{reg1} r{reg2} r{reg3}")


def andi(reg1, reg2, imm8):
    global regs
    regs[reg1] = regs[reg2] & imm8

    if debug:
        print(f"andi r{reg1} r{reg2} {imm8}")


def xor(reg1, reg2, reg3):
    global regs
    reg3 &= 0x1F
    regs[reg1] = regs[reg2] ^ regs[reg3]

    if debug:
        print(f"xor r{reg1} r{reg2} r{reg3}")


def xori(reg1, reg2, imm8):
    global regs
    regs[reg1] = regs[reg2] ^ imm8

    if debug:
        print(f"xori r{reg1} r{reg2} {imm8}")


def shl(reg1, reg2, reg3):
    global regs
    reg3 &= 0x1F
    regs[reg1] = regs[reg2] << regs[reg3]

    if debug:
        print(f"shl r{reg1} r{reg2} r{reg3}")


def shr(reg1, reg2, reg3):
    global regs
    reg3 &= 0x1F
    regs[reg1] = regs[reg2] >> regs[reg3]

    if debug:
        print(f"shr r{reg1} r{reg2} r{reg3}")


def cmp(reg1, reg2):
    global regs, fr

    reg2 &= 0x1F

    fr[0] = regs[reg1] == regs[reg2]  # ZF
    fr[1] = abs(regs[reg1]) < abs(regs[reg2])  # CF
    fr[2] = regs[reg1] - regs[reg2] < 0  # SF
    fr[3] = regs[reg1] - regs[reg2] > 255  # OF

    if debug:
        print(f"cmp r{reg1} r{reg2}")


def cmpi(reg1, imm8):
    global regs, fr
    fr[0] = regs[reg1] == imm8  # ZF
    fr[1] = abs(regs[reg1]) < abs(imm8)  # CF
    fr[2] = regs[reg1] - imm8 < 0  # SF
    fr[3] = regs[reg1] - imm8 > 255  # OF

    if debug:
        print(f"cmpi r{reg1} {imm8}")


def call(imm16):
    global pc, regs
    regs[31] = pc + 3
    pc = imm16

    if debug:
        print(f"call {imm16}")


def ret():
    global pc, regs
    pc = regs[31]

    if debug:
        print("ret")


def jmp(imm16):
    global pc
    pc = imm16

    if debug:
        print(f"jmp {imm16}")


def je(imm16):
    global pc, fr
    if fr[0]:
        pc = imm16

    if debug:
        print(f"je {imm16}")


def jne(imm16):
    global pc, fr
    if not fr[0]:
        pc = imm16

    if debug:
        print(f"jne {imm16}")


def jb(imm16):
    global pc, fr
    if fr[1]:
        pc = imm16

    if debug:
        print(f"jb {imm16}")


def jl(imm16):
    global pc, fr
    if fr[2] != fr[3]:
        pc = imm16

    if debug:
        print(f"jl {imm16}")


def jg(imm16):
    global pc, fr
    if not fr[0] and fr[2] == fr[3]:
        pc = imm16

    if debug:
        print(f"jg {imm16}")


def ja(imm16):
    global pc, fr
    if not fr[0] and not fr[1]:
        pc = imm16

    if debug:
        print(f"ja {imm16}")


def rd(reg1, reg2, reg3):
    global ram, regs
    addr = regs[reg2] << 8 | regs[reg3]
    regs[reg1] = ram[addr]

    if debug:
        print(f"rd r{reg1} r{reg2} r{reg3}")


def wr(reg1, reg2, reg3):
    global ram, regs
    addr = regs[reg2] << 8 | regs[reg3]
    ram[addr] = regs[reg1]

    if debug:
        print(f"wr r{reg1} r{reg2} r{reg3}")


def io(reg, imm3):
    global screen, gpu_x, gpu_y, out, regs, halt, serial_input, c, debug

    if imm3 == 1:  # IO GPU SET X
        gpu_x = regs[reg]
        if debug:
            print(f"io gpu set x r{reg}")
    elif imm3 == 2:  # IO GPU SET Y
        gpu_y = regs[reg]
        if debug:
            print(f"io gpu set y r{reg}")
    elif imm3 == 3:  # IO GPU DRAW
        val = regs[reg]
        red = 85 * (val >> 4)
        green = 85 * ((val >> 2) & 3)
        blue = 85 * (val & 3)
        color = (red, green, blue)
        pygame.draw.rect(
            screen,
            color,
            pygame.Rect(
                gpu_x * pixel_width, gpu_y * pixel_height, pixel_width, pixel_height
            ),
        )
        if debug:
            print("io gpu draw")
    elif imm3 == 4:  # IO GPU UPDATE
        pygame.display.flip()
        if debug:
            print("io gpu update")
    elif imm3 == 5:  # IO SERIAL LENGTH
        regs[reg] = len(serial_input)
        if debug:
            print(f"io serial length r{reg}")
    elif imm3 == 6:  # IO SERIAL READ
        if serial_input:
            regs[reg] = ord(serial_input[0])
            serial_input = serial_input[1:]

            # debug = True

        if debug:
            print(f"io serial read r{reg}")
            print(regs)
    elif imm3 == 7:  # IO SERIAL WRITE
        print(chr(regs[reg]), end="")
        if debug:
            print(f"io serial write r{reg}")
    else:
        halt = True
        if debug:
            print("halt")


ops_arit = {
    0: add,
    1: addi,
    2: sub,
    3: subi,
    6: or_op,
    7: ori,
    8: xor,
    9: xori,
    10: and_op,
    11: andi,
    12: shl,
    13: shr,
}

ops_comp = {
    4: cmp,
    5: cmpi,
}

ops_ctrl = {
    24: call,
    25: ret,
    16: jmp,
    17: je,
    18: jne,
    19: jb,
    20: jl,
    26: jg,
    27: ja,
}

ops_mem = {
    14: rd,
    15: wr,
}

ops_io = {
    21: io,
}


def parse(op):
    global pc, halt

    x = int.from_bytes(op, byteorder="big")

    opcode = x >> 19

    if opcode in ops_arit:
        reg1 = (x >> 13) & 0x1F
        reg2 = (x >> 8) & 0x1F
        reg3imm = x & 0xFF
        ops_arit[opcode](reg1, reg2, reg3imm)

        pc += 3
    elif opcode in ops_comp:
        reg1 = (x >> 11) & 0x1F
        reg2imm = x & 0xFF
        ops_comp[opcode](reg1, reg2imm)

        pc += 3
    elif opcode in ops_ctrl:
        imm16 = x & 0xFFFF
        old_pc = pc
        ops_ctrl[opcode](imm16)
        if old_pc == pc:
            pc += 3
    elif opcode in ops_mem:
        reg1 = (x >> 13) & 0x1F
        reg2 = (x >> 8) & 0x1F
        reg3 = x & 0x1F
        ops_mem[opcode](reg1, reg2, reg3)

        pc += 3
    elif opcode in ops_io:
        reg1 = (x >> 11) & 0x1F
        imm3 = (x >> 8) & 7
        ops_io[opcode](reg1, imm3)

        pc += 2
    elif opcode == 23:
        halt = True
    else:
        print(opcode)
        print("OP NOT FOUND")
        halt = True


while not halt:
    if debug:
        print(f"{pc:04}: ", end="")

    parse(ram[pc : pc + 3])

    event = pygame.event.poll()
    if event.type == pygame.QUIT:
        halt = True
    elif event.type == pygame.KEYDOWN:
        if event.key in range(pygame.K_a, pygame.K_z + 1):
            print(chr(event.key))

            serial_input += chr(event.key)
```

Running the emulator draws the flag:

![](/images/yauzactf2021-arc6969p2.png)
