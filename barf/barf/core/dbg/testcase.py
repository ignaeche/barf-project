import os
import shutil

from barf.core.dbg.input import Arg
from barf.core.dbg.input import File

def prepare_inputs(inputs):
    r = []

    for input in inputs:
        arg = input.PrepareData()

        if not arg is None:
            r.append(arg)

    return r

def write_testcase(name, program, args, copy=False):
    try:
        os.mkdir(name)
    except:
        pass

    os.chdir(name)

    filename = "path.txt"

    open(filename, "w").write(program)

    try:
        os.mkdir("inputs")
    except:
        pass

    os.chdir("inputs")

    for i, arg in enumerate(args):
        if "file:" in arg:
            arg = arg.replace("file:", "")

            assert(arg[0] == '/')

            filename = os.path.split(arg)[-1]

            if copy:
                shutil.copyfile(os.path.realpath(arg), "file_"+filename)
            else:
                os.symlink(os.path.realpath(arg), "file_"+filename)

            arg = filename

        filename = "argv_"+str(i+1)+".symb"

        open(filename, "w").write(arg)

    os.chdir("../..")

def GetTestcase(dirf):
    testcase = dict()

    os.chdir(GetDir(dirf))

    testcase["filename"] = GetCmd(None)

    os.chdir("inputs")

    testcase["envs"] = dict()
    testcase["args"] = GetArgs()
    testcase["files"] = GetFiles()

    return testcase

def GetDir(filename):
    dirf = filename.replace(".tar.bz2", "")

    return dirf

def GetCmd(s):
    if os.path.exists("path.txt"):
        f = open("path.txt")
        x = f.readline()

        return x.replace("\n", "").strip(" ")
    else:
        return s

def GetArg(n, conc):
    if conc:
        filename = "cargv_"+str(n)+".symb"
        data = open(filename).read()
        x = Arg(n, data)
        x.SetConcrete()
    else:
        filename = "argv_"+str(n)+".symb"
        data = open(filename).read()
        x = Arg(n, data)
        x.SetSymbolic()

    return x

def GetArgs():
    r = []

    for _, _, files in os.walk('.'):
        for f in files:
            for i in range(10):
                if ("cargv_"+str(i)) in f:
                    x = GetArg(i, True)

                    if x.IsValid():
                        r.append(x)

                    break
                elif ("argv_"+str(i)) in f:
                    x = GetArg(i, False)

                    if x.IsValid():
                        r.append(x)

                    break

    r.sort()

    for i in range(len(r)):
        if r[i].i != i+1:
            r = r[0:i]
            break

    return r

def GetFile(filename, source):
    data = open(source).read()

    return File(filename, data)

def GetFiles():
    r = []
    stdinf = "file___dev__stdin.symb"

    for dir, _, files in os.walk('.'):
        if dir == '.':
            for f in files:
                if (stdinf == f):
                    r.append(GetFile("/dev/stdin",stdinf))
                elif ("file_" in f):
                    filename = f.split(".symb")[0]
                    filename = filename.split("file_")[1]
                    filename = filename.replace(".__", "")

                    x = GetFile(filename, f)

                    if x.IsValid():
                        r.append(x)

    return r
