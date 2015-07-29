import time

from barf.core.dbg.event import CallIntel32


def open_handler(event, process, open_files):
    # Get parameters.
    pathname_ptr, _ = event.get_typed_parameters()[0]
    file_desc = event.return_value

    filename, truncated = process.readCString(pathname_ptr, 1024)
    assert(not truncated)

    open_files[file_desc] = {
        'filename' : filename,
        'offset' : 0
    }

    return False

def close_handler(event, process, open_files):
    # Get parameters.
    file_ptr, _ = event.get_typed_parameters()[0]
    file_desc = event.return_value

    if file_desc in open_files:
        del open_files[file_desc]

    return False

def read_handler(event, process, emulator, memory_taints, open_files, addrs_to_files):
    # Get parameters.
    file_desc, _ = event.get_typed_parameters()[0]
    buf, _ = event.get_typed_parameters()[1]
    bytes_read = event.return_value

    if file_desc not in open_files:
        return False

    # Keep record of inital taints.
    offset = open_files[file_desc]['offset']

    timestamp = int(time.time())

    for i in xrange(0, bytes_read):
        # Keep track of inital taints.
        memory_taints.append((buf + i, timestamp))

        # Keep track of files and current file position.
        d_entry = addrs_to_files.get(buf + i, {})
        l_entry = d_entry.get(file_desc, [])
        l_entry.append(offset + i)

        d_entry[file_desc] = l_entry
        addrs_to_files[buf + i] = d_entry

        # Taint memory address.
        emulator.set_memory_taint(buf + i, 1, True)

    # Update file offset.
    open_files[file_desc]['offset'] += bytes_read

    return True

def process_event(process, event, emulator, memory_taints, open_files, addrs_to_files):
    if isinstance(event, CallIntel32):
        if event.name == "open":
            return open_handler(event, process, open_files)

        #if event.name == "close":
        #    return close_handler(event, process, open_files)

        if event.name == "read":
            return read_handler(event, process, emulator, memory_taints, open_files, addrs_to_files)
