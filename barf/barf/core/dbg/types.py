
class Type(object):

    def __init__(self, name, size, index=None):
        self.name = str(name)
        self.size_in_bytes = size
        self.index = index

    def __str__(self):
        r = str(self.name)

        if (self.index != None):
            r = r +"("+str(self.index)+")"

        return r

    def getSize(self):
        return self.size_in_bytes

ptypes = [Type("Num32",   4, None),
          Type("Ptr32",   4, None), # Generic pointer
          Type("SPtr32",  4, None), # Stack pointer
          Type("HPtr32",  4, None), # Heap pointer
          Type("GxPtr32", 4, None), # Global eXecutable pointer
          Type("FPtr32",  4, None), # File pointer
          Type("NPtr32",  4, None), # NULL pointer
          Type("DPtr32",  4, None), # Dangling pointer
          Type("GPtr32",  4, None), # Global pointer
          Type("Top32",   4, None)
         ]

def isNum(ptype):
    return ptype in ["int", "ulong", "long", "char"]

def isPtr(ptype):
    return "addr" in ptype or "*" in ptype or "string" in ptype or "format" in ptype or "file" in ptype

def isVoid(ptype):
    return ptype == "void"

def isNull(val):
    return val == "0x0" or val == "0"

def get_type(ptype):
    if isPtr(ptype):
        return Type("Ptr32", 4)
    elif isNum(ptype):
        return Type("Num32", 4)
    elif isVoid(ptype):
        return Type("Top32", 4)
    else:
        return Type("Top32", 4)
