from barf.core.dbg.event import CallIntel32

def open_handler(event, process, open_files):
    # Get parameters.
    pathname_ptr, _ = event.get_typed_parameters()[0]
    file_desc = event.return_value

    filename, truncated = process.readCString(pathname_ptr, 1024)
    assert(not truncated)

    open_files[file_desc] = {
        'filename' : filename,
        'f_pos' : 0
    }

def read_handler(event, process, ir_emulator, initial_taints, open_files, addrs_to_files):
    # Get parameters.
    file_desc, _ = event.get_typed_parameters()[0]
    buf, _ = event.get_typed_parameters()[1]
    bytes_read = event.return_value

    # Taint memory address.
    ir_emulator.set_memory_taint(buf, bytes_read * 8, True)

    # Keep record of inital taints.
    file_curr_pos = open_files[file_desc]['f_pos']

    for i in xrange(0, bytes_read):
        # Keep track of inital taints.
        initial_taints.append(buf + i)

        # Keep track of files and current file position.
        d_entry = addrs_to_files.get(buf + i, {})
        l_entry = d_entry.get(file_desc, [])
        l_entry.append(file_curr_pos + i)

        d_entry[file_desc] = l_entry
        addrs_to_files[buf + i] = d_entry

        # Set emulator memory
        data = ord(process.readBytes(buf + i, 1))
        ir_emulator.write_memory(buf + i, 8, data)

        # print("Read @ %x : %02x (%s)" % (buf + i, data, chr(data)))

    open_files[file_desc]['f_pos'] = bytes_read

def process_event(process, event, ir_emulator, initial_taints, open_files, addrs_to_files):
    if isinstance(event, CallIntel32):
        if event.name == "open":
            open_handler(event, process, open_files)

        if event.name == "fopen":
            raise NotImplementedError

        if event.name == "read":
            read_handler(event, process, ir_emulator, initial_taints, open_files, addrs_to_files)

        if event.name == "fwrite":
            raise NotImplementedError
