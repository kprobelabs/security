import gdb
import string


DEBUG = 1
POINTER_SIZE = 8
DATA_PREVIEW_SIZE = 50


def print(message):
    gdb.write("[SHOWMEM]: {}\n".format(message))


class StoreBlock:
    address = 0x0
    next = 0x0
    length = 0x0


class HeapChunk:
    address = 0x0
    in_use = False
    size = 0x0


def colorize(message):
    return "\033[1;36m{}\033[0;0m".format(message)


class ShowMem(gdb.Command):
    def __init__(self):
        super(ShowMem, self).__init__("smem", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        store_blocks = self._iterate_chain_bases()
        heap_chunks = self._iterate_heap_chunks(store_blocks)

        all_memory = heap_chunks + store_blocks

        for m in sorted(all_memory, key=lambda m: m.address):
            if isinstance(m, StoreBlock):
                print(
                    colorize(
                        "  0x{:x}: storeblock of size 0x{:08x}      / data: {}".format(
                            m.address, m.length, self._get_data_preview(m)
                        )
                    )
                )
            else:
                print(
                    "0x{:x}: heap chunk of size 0x{:08x} ({}) / data: {}".format(
                        m.address, m.size, "used" if m.in_use else "free", self._get_data_preview(m)
                    )
                )

    @staticmethod
    def _get_data_preview(store_block):
        printable = [c for c in string.printable if c not in [chr(x) for x in [0xA, 0xB, 0xC, 0xD]]]
        preview = []
        for offset in range(DATA_PREVIEW_SIZE):
            current_address = store_block.address + 16 + offset  # + 16: skip next and length fields

            try:
                char = chr(int(gdb.parse_and_eval("(int)*((char *){})".format(hex(current_address)))))
            except ValueError:
                char = None

            if char == "\0":
                break

            char = char if char and char in printable else "."

            preview.append(char)

        return "".join(preview)

    @staticmethod
    def _iterate_heap_chunks(storeblocks):
        heap_chunks = []

        # heap chunks that are stored in front of the first storeblock's heap chunk will not be displayed
        # storeblock's address is the return value of malloc(), thus address - 16 is where mchunkptr points to
        current_chunk_address = storeblocks[0].address - 16
        top_chunk_address = int(gdb.parse_and_eval("((struct malloc_state)main_arena).top"))
        break_next = False

        while True:
            size_with_amp_bits = int(
                gdb.parse_and_eval("((struct malloc_chunk)*{}).mchunk_size".format(hex(current_chunk_address)))
            )
            prev_in_use = bool(size_with_amp_bits & 1)
            # clear the last 3 bits AMP (https://sourceware.org/glibc/wiki/MallocInternals#What_is_a_Chunk.3F)
            size = size_with_amp_bits & ~7
            assert size % 8 == 0 and size >= 4 * POINTER_SIZE  # min size is 4 * sizeof(void *)

            if len(heap_chunks) >= 1:
                heap_chunks[-1].in_use = prev_in_use

            h = HeapChunk()
            h.address = current_chunk_address
            h.size = size

            heap_chunks.append(h)

            if break_next:
                break

            current_chunk_address += size

            if current_chunk_address == top_chunk_address:
                break_next = True

        return heap_chunks

    @staticmethod
    def _iterate_chain_bases():
        store_blocks = []

        for pool_idx in range(3):
            first_block = StoreBlock()
            first_block.address = int(gdb.parse_and_eval("chainbase[{}]".format(pool_idx)))

            if first_block.address == 0x0:
                break

            store_blocks.append(first_block)

            while True:
                current_block = store_blocks[-1]

                current_block.length = int(
                    gdb.parse_and_eval("((storeblock)*{}).length".format(hex(current_block.address)))
                )
                current_block.next = int(
                    gdb.parse_and_eval("((storeblock)*{}).next".format(hex(current_block.address)))
                )

                if current_block.next == 0x0:
                    break

                next_block = StoreBlock()
                next_block.address = current_block.next
                store_blocks.append(next_block)

        store_blocks = sorted(store_blocks, key=lambda s: s.address)

        return store_blocks


ShowMem()
gdb.execute("continue")
