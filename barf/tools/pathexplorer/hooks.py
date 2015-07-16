from barf.core.dbg.event import CallIntel32

"""
#FIXME: move this function to another file
def pfileno_32(process, file_ptr):
    _fileno_offset_32 = 56
    _fileno_size_32 = 4

    bs = process.readBytes(file_ptr+_fileno_offset_32,  _fileno_size_32)

    if CPU_X86_64:
        bs = bs + (4*'\00')

    return bytes2word(bs)
"""


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
    return False

def close_handler(event, process, open_files):
    # Get parameters.
    file_ptr, _ = event.get_typed_parameters()[0]
    file_desc = event.return_value

    #print "closing:", file_desc
    if file_desc in open_files:
        del open_files[file_desc]

    return False


"""
def fopen_handler(event, process, open_files):

    # Get parameters.
    pathname_ptr, _ = event.get_typed_parameters()[0]
    file_ptr = event.return_value

    filename, truncated = process.readCString(pathname_ptr, 1024)
    assert(not truncated)
    #print filename, hex(file_ptr)
    file_desc = pfileno_32(process, file_ptr)

    open_files[file_desc] = {
        'filename' : filename,
        'f_pos' : 0
    }
"""

def read_handler(event, process, ir_emulator, initial_taints, open_files, addrs_to_files):
    # Get parameters.
    file_desc, _ = event.get_typed_parameters()[0]
    buf, _ = event.get_typed_parameters()[1]
    bytes_read = event.return_value

    finfo = open_files.get(file_desc, None)
    if finfo is None: #or not (finfo['filename'] == "input1"):
        return False

    # Taint memory address.
    ir_emulator.set_memory_taint(buf, bytes_read, True)

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
        ir_emulator.write_memory(buf + i, 1, data)

        # print("Read @ %x : %02x (%s)" % (buf + i, data, chr(data)))

    open_files[file_desc]['f_pos'] = bytes_read
    return True

"""
# fread

def fread_handler(event, process, ir_emulator, initial_taints, open_files, addrs_to_files):
    raise NotImplementedError
    # TODO: cache?
    # Get parameters.
    file_ptr, _ = event.get_typed_parameters()[0]
    file_desc = pfileno_32(process, file_ptr)
    buf, _ = event.get_typed_parameters()[1]
    bytes_read = event.return_value

    # Taint memory address.
    ir_emulator.set_memory_taint(buf, bytes_read, True)

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
        ir_emulator.write_memory(buf + i, 1, data)

        # print("Read @ %x : %02x (%s)" % (buf + i, data, chr(data)))

    open_files[file_desc]['f_pos'] = bytes_read
"""

"""
def fgetc_handler(event, process, ir_emulator, initial_taints, open_files, addrs_to_files):

    ret_operand = ReilRegisterOperand("eax", 32)
    # Get parameters.
    file_ptr, _ = event.get_typed_parameters()[0]
    file_desc = pfileno_32(process, file_ptr)
    #byte_read = event.return_value

    # Taint return register.
    ir_emulator.set_operand_taint(ret_operand, True)

    # Keep record of inital taints.
    file_curr_pos = open_files[file_desc]['f_pos']

    #FIXME: missing code

    open_files[file_desc]['f_pos'] = open_files[file_desc]['f_pos'] + 1
"""

def process_event(process, event, ir_emulator, initial_taints, open_files, addrs_to_files):
    if isinstance(event, CallIntel32):
        if event.name == "open":
            return open_handler(event, process, open_files)

        #if event.name == "__close":
        #    return close_handler(event, process, open_files)

        #if event.name == "fopen":
        #    fopen_handler(event, process, open_files)

        if event.name == "read":
            return read_handler(event, process, ir_emulator, initial_taints, open_files, addrs_to_files)

        #if event.name == "fread":
        #    fread_handler(event, process, ir_emulator, initial_taints, open_files, addrs_to_files)

        #if event.name == "fgetc" or event.name == "_IO_getc":
        #    fgetc_handler(event, process, ir_emulator, initial_taints, open_files, addrs_to_files)

