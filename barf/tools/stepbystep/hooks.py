from barf.core.dbg.event import CallIntel32

def taint_read(process, event, ir_emulator, initial_taints, open_files, file_mem_mapper, addrs_to_file):
    if isinstance(event, CallIntel32):
        if event.name == "open":
            pathname_ptr, _ = event.get_typed_parameters()[0]
            file_desc = event.return_value

            filename, truncated = process.readCString(pathname_ptr, 1024)
            assert(not truncated)

            open_files[file_desc] = {
                'filename' : filename,
                'f_pos' : 0
            }

        if event.name == "fopen":
            raise NotImplementedError

        if event.name == "read":
            file_desc, _ = event.get_typed_parameters()[0]
            buf, _ = event.get_typed_parameters()[1]
            bytes_read = event.return_value

            file_curr_pos = open_files[file_desc]['f_pos']
            fmapper = file_mem_mapper.get(file_desc, {})

            # Taint memory address.
            ir_emulator.set_memory_taint(buf, bytes_read * 8, True)

            # Keep record of inital taints.
            for i in xrange(0, bytes_read):
                fmapper[buf + i] = file_curr_pos + i
                initial_taints.append(buf + i)

                d_entry = addrs_to_file.get(buf + i, {})
                l_entry = d_entry.get(file_desc, [])
                l_entry.append(file_curr_pos + i)

                d_entry[file_desc] = l_entry
                addrs_to_file[buf + i] = d_entry

                data = ord(process.readBytes(buf + i, 1))
                print "read @ %s : %x (%s)" % (hex(buf + i), data, chr(data))

                ir_emulator.write_memory(buf + i, 8, data)

            open_files[file_desc]['f_pos'] = bytes_read
            file_mem_mapper[file_desc] = fmapper

        if event.name == "fwrite":
            raise NotImplementedError


