from os import close
from os import devnull
from os import dup2
from os import execv
from os import execve
from os import fork
from ptrace import PtraceError
from ptrace.binding import ptrace_traceme
from resource import RLIMIT_AS
from resource import setrlimit


class ChildError(RuntimeError):
    pass

def _execChild(arguments, no_stdout, env):
    if no_stdout:
        try:
            null = open(devnull, 'wb')
            dup2(null.fileno(), 1)
            dup2(1, 2)
            null.close()
        except IOError, err:
            close(2)
            close(1)
    try:
        if env is not None:
            execve(arguments[0], arguments, env)
        else:
            execv(arguments[0], arguments)
    except Exception, err:
        raise ChildError(str(err))

def createChild(arguments, no_stdout, env=None):
    """
    Create a child process:
     - arguments: list of string where (eg. ['ls', '-la'])
     - no_stdout: if True, use null device for stdout/stderr
     - env: environment variables dictionary

    Use:
     - env={} to start with an empty environment
     - env=None (default) to copy the environment
    """

    # Fork process
    pid = fork()
    if pid:
        return pid
    else:
        setrlimit(RLIMIT_AS, (1024*1024*1024, -1))

        try:
            ptrace_traceme()
        except PtraceError, err:
            raise ChildError(str(err))

        _execChild(arguments, no_stdout, env)

        exit(255)
