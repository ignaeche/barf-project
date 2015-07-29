import time

from barf.core.dbg.event import CallIntel32


def open_handler(event, process, open_files):
    # Get parameters.
    pathname_ptr, _ = event.get_typed_parameters()[0]
    fd = event.return_value

    filename, truncated = process.readCString(pathname_ptr, 1024)
    assert(not truncated)

    open_files[fd] = {
        'filename' : filename,
        'offset' : 0
    }

    return False

def close_handler(event, process, open_files):
    # Get function parameters.
    fd, _ = event.get_typed_parameters()[0]

    if fd in open_files:
        del open_files[fd]

    return False

def read_handler(event, process, emulator, memory_taints, open_files):
    # Get function parameters.
    fd, _ = event.get_typed_parameters()[0]
    buf, _ = event.get_typed_parameters()[1]
    count = event.return_value

    if fd not in open_files:
        return False

    # Get current file offset.
    base_offset = open_files[fd]['offset']

    for i in xrange(0, count):
        addr = buf + i
        offset = base_offset + i

        # Keep track of taint information.
        memory_taints[addr] = (fd, offset)

        # Taint memory address.
        emulator.set_memory_taint(addr, 1, True)

    # Update file offset.
    open_files[fd]['offset'] += count

    return True

def process_event(process, event, emulator, memory_taints, open_files):
    if isinstance(event, CallIntel32):
        if event.name == "open":
            return open_handler(event, process, open_files)

        #if event.name == "close":
        #    return close_handler(event, process, open_files)

        if event.name == "read":
            return read_handler(event, process, emulator, memory_taints, open_files)
