import gdb
import re
import UdkCommandHelper

def ReadMsr(Index):
    response = UdkCommandHelper.sendUdkExtensionPacket("msr%x" % Index)
    m = re.match('E([0-9A-Fa-f]+)', response)
    if m != None:
        return None
    else:
        return int(response, 16)

def WriteMsr(Index, Value):
    response = UdkCommandHelper.sendUdkExtensionPacket("MSR%x=%x" % (Index, Value))
    if response != "OK":
        return False
    else:
        return True

def ReadIo(Address, Size):
    return UdkCommandHelper.string_to_long(
             UdkCommandHelper.sendUdkExtensionPacket("io%x,%x" % (Address, Size))
             );

def WriteIo(Address, Size, Value):
    response = UdkCommandHelper.sendUdkExtensionPacket("IO%x,%x:%s" % (Address, Size, UdkCommandHelper.long_to_string(Value, Size)))
    if response != "OK":
        return False
    else:
        return True

def _RegisterIndex(Name):
    response = UdkCommandHelper.sendUdkExtensionPacket("arch")
    if response == "use64":
        regs = [
#0       1        2       3       4       5       6       7       8       9        A      B      C      D      E      F
 'rax',  'rbx',   'rcx',  'rdx',  'rsi',  'rdi',  'rbp',  'rsp',  'r8',   'r9',    'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
 'rip',  'eflags','cs',   'ss',   'ds',   'es',   'fs',   'gs',   'st0',  'st1',   'st2', 'st3', 'st4', 'st5', 'st6', 'st7',
 'fctrl','fstat', 'ftag', 'fiseg','fioff','foseg','fooff','fop',  'xmm0', 'xmm1',  'xmm2','xmm3','xmm4','xmm5','xmm6','xmm7',
 'xmm8', 'xmm9',  'xmm10','xmm11','xmm12','xmm13','xmm14','xmm15','mxcsr','orig_rax'];
    elif response == "use32":
        regs = [
 'eax',  'ecx',   'edx',  'ebx',  'esp',  'ebp',  'esi',  'edi',  'eip',  'eflags','cs',  'ss',   'ds',   'es',   'fs',   'gs',
 'st0',  'st1',   'st2',  'st3',  'st4',  'st5',  'st6',  'st7',  'fctrl','fstat', 'ftag','fiseg','fioff','foseg','fooff','fop',
 'xmm0', 'xmm1',  'xmm2', 'xmm3', 'xmm4', 'xmm5', 'xmm6', 'xmm7', 'mxcsr','orig_eax'];
    else:
        return None

    index = 0
    for r in regs:
        if r == Name:
            return index
        index += 1
    return None

def ReadRegister(Name):
    response = UdkCommandHelper.sendPacket("p%x" % _RegisterIndex(Name))
    return UdkCommandHelper.string_to_list(response)

def WriteRegister(Name, Value):
    response = UdkCommandHelper.sendPacket(
                 "P%x=%s" % (_RegisterIndex(Name), UdkCommandHelper.list_to_string(Value))
                 )
    if response == "OK":
        UdkCommandHelper.executeCommand("flushregs")
    return response == "OK"

def WriteMemory(Address, Width, Value):
    response = UdkCommandHelper.sendUdkExtensionPacket(
                 "MMIO%x,%x,%x:%s" % (Address, Width, len(Value), UdkCommandHelper.list_to_string(Value, Width))
                 )
    return response == "OK"

def ReadMemory(Address, Width, Count):
    response = UdkCommandHelper.sendUdkExtensionPacket(
                 "mmio%x,%x,%x" % (Address, Width, Count)
                 )
    return UdkCommandHelper.string_to_list(response, Width)

def SearchSignature(Address, Length, Alignment, Positive, Signature):
    response = UdkCommandHelper.sendUdkExtensionPacket(
                 "search,%x,%x,%x,%x,%s" % (
                   Address, Length, Alignment, Positive, UdkCommandHelper.list_to_string(Signature)
                   )
                 )
    if response == "":
        return None
    else:
        return int(response, 16)

def GetArch():
    response = UdkCommandHelper.sendUdkExtensionPacket("arch")
    if response == "use32":
        return 1
    else:
        return 2
