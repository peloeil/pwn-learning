import gdb

binpath = "../../../problems/stack/rop/medium"

gdb.execute(f"file {binpath}")
gdb.execute("b main")
gdb.execute("r")

vmmap = gdb.execute("vmmap libc", to_string=True)

def calc_libc_base():
    for line in vmmap.splitlines():
        if line.startswith("0x"):
            return int(line.split('\x01')[0], 16)
    return 0


def main():
    addr_libc_start = gdb.parse_and_eval("*(uintptr_t *)($rsp+8)") - 0x75
    libc_base = calc_libc_base()
    print(f"addr_libc_start                 : {hex(addr_libc_start)}")
    print(f"libc base                       : {hex(libc_base)}")
    print()
    print(f"offset of __libc_start_call_main: {hex(addr_libc_start - libc_base)}")
    return


if __name__ == "__main__":
    main()
