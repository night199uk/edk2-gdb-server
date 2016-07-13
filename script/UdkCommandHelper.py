import gdb
from UdkMessage import *

def string_to_list(s, w = 1):
    """Turn a hex string into a byte list, e.g.: '3412' -> [0x34, 0x12]."""
    v = 0
    l = []
    for i in list(range(len(s)//2//w)):
        v = 0
        for j in list(range(w)):
            v += int(s[i*2*w + j*2 : i*2*w + j*2 + 2], 16) << (j * 8)
        l.append(v)
    return l

def list_to_string(l, w = 1):
    """Turn a byte list into a hex string, e.g.: [0x34, 0x12] -> '3412'."""
    s = ""
    for _l in l:
        if w == 1:
            s += "%02x" % _l
        elif w == 2:
            s += "%02x%02x" % (_l & 0xff, _l >> 8)
        elif w == 4:
            s += "%02x%02x%02x%02x" % (_l & 0xff, (_l >> 8) & 0xff, (_l >> 16) & 0xff, _l >> 24)
        elif w == 8:
            s += "%02x%02x%02x%02x%02x%02x%02x%02x" % (_l & 0xff, (_l >> 8) & 0xff, (_l >> 16) & 0xff, (_l >> 24) & 0xff,
                                               (_l >> 32) & 0xff, (_l >> 40) & 0xff, (_l >> 48) & 0xff, _l >> 56)
    return s

def string_to_long(s):
    """Turn a hex string into integer/long value, e.g.: '3412' -> 0x1234."""
    l = 0
    for i in list(range(len(s)//2)):
        l += (int(s[i*2:(i+1)*2], 16) << (8 * i))
    return l

def long_to_string(l, n):
    """Turn a integer/long value into a hex encoded string, e.g.: 0x1234 -> '3412'."""
    s = ""
    for i in list(range(n)):
        s += "%02x" % (l & 0xff)
        l >>= 8
    return s

def checkParameterEx(arg, count_min, count_max):
    try:
        args = gdb.string_to_argv(arg)
    except AttributeError:
        # GDB 7.0 doesn't have string_to_argv() interface
        args = []
        for _arg in arg.split(' '):
            if _arg != '':
                args.append(_arg)

    if len(args) >= count_min and len(args) <= count_max:
        return args
    if len(args) < count_min:
        print(ARGUMENT_TOO_FEW)
        return None
    else:
        print(ARGUMENT_TOO_MANY)
        return None

def checkParameter(arg, count):
    return checkParameterEx(arg, count, count)

_debugMode = False 
def executeCommand(cmd):
    try:
        if _debugMode:
            print("run: %s" % cmd)

        try:
            lines = gdb.execute(cmd, True, True).split("\n")
        except TypeError:
            # GDB 7.0 's execute() doesn't have the 3rd parameter to return all the return string
            FILE = "%s/.udk-script.temp" % os.getenv('HOME')
            gdb.execute("set logging file %s" % FILE)
            gdb.execute("set logging overwrite")
            gdb.execute("set logging redirect on")
            gdb.execute("set logging on")
            gdb.execute(cmd)
            gdb.execute("set logging off")
            gdb.execute("set logging redirect off")
            file = open(FILE)
            lines = [ line.rstrip('\n') for line in file.readlines() ]
            file.close()

        if _debugMode:
            for line in lines:
                print("result: %s" % line)
        return lines
    except Exception as e:
        print(e)

def sendPacket(cmd, prefix=None):
    if prefix != None:
        cmd = prefix + cmd
    for line in executeCommand("maint packet %s" % cmd):
        if line.startswith("received: "):
            return line[11:-1]
    return ""

def sendUdkExtensionPacket(cmd):
    return sendPacket(cmd, "qUdkExtension:")

def getTargetDebugInfo(pc):
    response = sendUdkExtensionPacket("symbol:0x%x" % pc)
    # /home/ray/a.dll;0x1000;.text=0x1234;.data=0x4567
    print(str(response))
    array = response.split(";")
    if (len(array) > 2):
        image_addr = int(array[1], 16)
        debug_info = (array[0], image_addr, {})
        for section in array[2:]:
            (section_name, section_addr) = section.split("=")
            debug_info[2][section_name] = int(section_addr, 16)
        return debug_info
    return None

_supportExpat = None

def supportExpat():
    global _supportExpat
    if _supportExpat != None:
        return _supportExpat

    _supportExpat = False
    if sendUdkExtensionPacket("checkexpat:start") == "OK":
        executeCommand("info sharedlibrary")
        if sendUdkExtensionPacket("checkexpat:end") == "OK":
            # if qXfer:libraries:read is received by gdb server between check:start and check:end
            _supportExpat = True
    return _supportExpat
