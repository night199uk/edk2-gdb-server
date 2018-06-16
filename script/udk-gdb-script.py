import sys
import os
import re
import gdb
import traceback
import datetime
import inspect

script_path = os.path.dirname(__file__)
if script_path not in sys.path:
	sys.path.insert(0, script_path)
	sys.path.insert(0, script_path + '/py')

#
# Avoid generating the .pyc file
#
sys.dont_write_bytecode = True

import UdkExtension
import UdkCommandHelper
from imp import reload
from UdkMessage import *

class Edk2Py(gdb.Command):
    """
    Execute the Python function: py [/h] [/t] Module[.Function] [Arguments].
    /h to show the help of the function.
    /t to show the execution time.
    Module is the Python module where Function can be located.
    Function is the Python function to be executed, Function is "invoke" if omitted.
    Arguments will be passed to Function as the parameter.
    """
    def __init__(self):
        super(Edk2Py, self).__init__("py", gdb.COMMAND_FILES, gdb.COMPLETE_NONE)

    def _import(self, name):
        need_reload = name in sys.modules
        module = __import__(name)
        if need_reload:
            return reload(module)
        else:
            return module

    def invoke(self, arg, from_tty):
        self.dont_repeat()
        args = UdkCommandHelper.checkParameterEx(arg, 1, 0xffffffff)
        if args == None:
            return

        Help = False
        Time = False
        if args[0] == '/h':
            Help = True
            del args[0]
        elif args[0] == '/t':
            Time = True
            del args[0]

        if '.' in args[0]:
            (module, function) = args[0].split('.')
        else:
            (module, function) = (args[0], "invoke")
        module = self._import(module)
        try:
            function = module.__dict__[function]
        except:
            print(FAILED_TO_LOCATE_FUNCTION % (function, module.__name__))
            return

        if Help:
            print(function.__doc__)
            return
        else:
            Start = datetime.datetime.now()
            try:
                function(" ".join(args[1:]))
            except:
                traceback.print_exc()
            if Time:
                print(EXECUTION_TIME % (str(datetime.datetime.now() - Start)))
Edk2Py()

class Edk2Cpuid(gdb.Command):
    """
    Retrieves CPUID information: cpuid [INDEX] [SUBINDEX].
    INDEX is the value of EAX priori to executing CPUID instruction (defaults to 1).
    SUBINDEX is the value of ECX priori to executing CPUID instruction (defaults to 0).
    """
    def __init__(self):
        super(Edk2Cpuid, self).__init__("cpuid", gdb.COMMAND_DATA, gdb.COMPLETE_NONE)

    def invoke(self, arg, from_tty):
        args = UdkCommandHelper.checkParameterEx(arg, 0, 2)
        if args == None:
            return

        if len(args) < 2:
            subindex = 0
        else:
            try:
                subindex = int(args[1], 16)
            except:
                print(ARGUMENT_INVALID_SUBINDEX)
                return
        if len(args) < 1:
            index = 1
        else:
            try:
                index = int(args[0], 16)
            except:
                print(ARGUMENT_INVALID_INDEX)
                return
        response = UdkCommandHelper.sendUdkExtensionPacket("cpuid,%08x,%08x" % (index, subindex))
        try:
            print(CPUID_INPUT % (index, subindex))
            (eax, ebx, ecx, edx) = [int(v, 16) for v in response.split(",")]
            print(CPUID_OUTPUT % (eax, ebx, ecx, edx))
        except Exception:
            print(FAILED_TO_EXECUTE_COMMAND % response)
Edk2Cpuid()

class Edk2Io(gdb.Command):
    """
    Access IO: io/SIZE PORT [VALUE].
    PORT is an expression for the IO address to Access.
    SIZE letters are b(byte), h(halfword), w(word).
    VALUE is an expression to write to the PORT.
    """
    def __init__(self, command_str = "io", command_class = gdb.COMMAND_DATA, complete_type = gdb.COMPLETE_NONE):
        super(Edk2Io, self).__init__(command_str, command_class, complete_type)

    def parse_port(self, args):
        size_dic = {"/b":1, "/h":2, "/w":4}
        try:
            size = size_dic[args[0]]
        except:
            print(ARGUMENT_INVALID_SIZE)
            raise

        try:
            port = int(args[1], 16)
        except:
            print(ARGUMENT_INVALID_PORT)
            raise

        return (port, size)

    def invoke(self, arg, from_tty):
        args = UdkCommandHelper.checkParameterEx(arg, 2, 3)
        if args == None:
            return

        try:
            (port, size) = self.parse_port(args)
        except:
            return

        if len(args) == 2:
            value = UdkExtension.ReadIo(port, size)
            print("%0*x" % (size * 2, value))
        else:
            value = int(args[2], 16)
            if not UdkExtension.WriteIo(port, size, value):
                print(FAILED_TO_EXECUTE_COMMAND % response)
Edk2Io()

class Edk2IoWatch(Edk2Io):
    """
    Set a watchpoint for an IO address.
    Usage: iowatch/SIZE PORT
    A watchpoint stops execution of your program whenever the
    IO address is either read or written.
    PORT is an expression for the IO address to Access.
    SIZE letters are b(byte), h(halfword), w(word).
    VALUE is an expression to write to the PORT.
    """
    def __init__(self):
        super(Edk2IoWatch, self).__init__("iowatch", gdb.COMMAND_DATA, gdb.COMPLETE_NONE)
        self._watchpoints = {}
        self._num_watchpoints = 0

    def invoke(self, arg, from_tty):
        args = UdkCommandHelper.checkParameter(arg, 2)
        if args == None:
            return

        try:
            (port, size) = self.parse_port(args)
        except:
            return

        response = UdkCommandHelper.sendUdkExtensionPacket("Z5,%x,%x" % (port, size))
        if response != "OK":
            print(FAILED_TO_EXECUTE_COMMAND % response)
        else:
            self._num_watchpoints += 1
            self._watchpoints[self._num_watchpoints] = (port, size)
            print(IO_WATCH_POINT_INFO % (self._num_watchpoints, port, size))

    def list(self, arg):
        args = UdkCommandHelper.checkParameterEx(arg, 0, 1)
        if args == None:
            return

        if len(args) == 1:
            try:
                args[0] = int(args[0], 10)
            except:
                args[0] = 0

            if args[0] == 0:
                print(ARGUMENT_MUST_BE_NUMBER_1_BASED)
                return

        print("Num\tPort\tSize")
        for index, (port, size) in list(self._watchpoints.items()):
            if len(args) == 0 or args[0] == index:
                print("%d\t0x%x\t%d" % (index, port, size))

    def delete(self, arg):
        args = UdkCommandHelper.checkParameterEx(arg, 0, 1)
        if args == None:
            return

        if len(args) == 1:
            try:
                args[0] = int(args[0], 10)
            except:
                args[0] = 0

            if args[0] == 0:
                print(ARGUMENT_MUST_BE_NUMBER_1_BASED)
                return

        for index, (port, size) in list(self._watchpoints.items()):
            if len(args) == 0 or args[0] == index:
                response = UdkCommandHelper.sendUdkExtensionPacket("z5,%x,%x" % (port, size))
                if response != "OK":
                    print(FAILED_TO_EXECUTE_COMMAND % response)
                else:
                    del self._watchpoints[index]
IoWatchpoints = Edk2IoWatch()

class Edk2InfoIoWatchpoints(gdb.Command):
    """Status of specified IO watchpoint (all watchpoints if no argument)."""

    def __init__(self):
        super(Edk2InfoIoWatchpoints, self).__init__("info iowatchpoints", gdb.COMMAND_DATA, gdb.COMPLETE_NONE)

    def invoke(self, arg, from_tty):
        IoWatchpoints.list(arg)
Edk2InfoIoWatchpoints()

class Edk2DelIoWatchpoints(gdb.Command):
    """Delete some IO watchpoints.
Argument is IO watchpoints number.
To delete all IO watchpoints, give no argument."""

    def __init__(self):
        super(Edk2DelIoWatchpoints, self).__init__("delete iowatchpoints", gdb.COMMAND_DATA, gdb.COMPLETE_NONE)

    def invoke(self, arg, from_tty):
        IoWatchpoints.delete(arg)
Edk2DelIoWatchpoints()

class Edk2Msr(gdb.Command):
    """Read/Write MSR."""

    def __init__(self):
        super(Edk2Msr, self).__init__("msr", gdb.COMMAND_DATA, gdb.COMPLETE_NONE)

    def invoke(self, arg, from_tty):
        args = UdkCommandHelper.checkParameterEx(arg, 1, 2)
        if args != None:
            if len(args) == 1:
                index = int(args[0], 16)
                value = UdkExtension.ReadMsr(index)
                if value == None:
                    print(FAILED_TO_EXECUTE_COMMAND % response)
                else:
                    print("%016x" % value)
            else:
                index = int(args[0], 16)
                value = int(args[1], 16)
                if not UdkExtension.WriteMsr(index, value):
                    print(FAILED_TO_EXECUTE_COMMAND % response)
Edk2Msr()

class Edk2InfoException(gdb.Command):
    """Show the exception information.
    """

    def __init__(self):
        super(Edk2InfoException, self).__init__("info exception", gdb.COMMAND_DATA, gdb.COMPLETE_NONE)

    def invoke(self, arg, from_tty):
        args = UdkCommandHelper.checkParameter(arg, 0)
        if args != None:
            response = UdkCommandHelper.sendUdkExtensionPacket("exception")
            if response != "":
                (vector, error_code) = response.split(";")
                vector = int(vector, 16)
                error_code = int(error_code, 16)
                print(EXCEPTION_INFO % (vector, error_code))
Edk2InfoException()

class Edk2RefreshArchitecture(gdb.Command):
    """Refresh target architecture.
    """

    def __init__(self):
        super(Edk2RefreshArchitecture, self).__init__("refresharch", gdb.COMMAND_STATUS, gdb.COMPLETE_NONE)

    def invoke(self, arg, from_tty):
        self.dont_repeat()
        args = UdkCommandHelper.checkParameter(arg, 0)
        if args == None:
            return

        response = UdkCommandHelper.sendUdkExtensionPacket("arch")

        if response == "use32":
            UdkCommandHelper.executeCommand("set architecture i386")
        elif response == "use64":
            UdkCommandHelper.executeCommand("set architecture i386:x86-64")
Edk2RefreshArchitecture()

class Edk2SmmEntryBreak(gdb.Command):
    """Configure whether the target stops when entering SMM.
Usage: set smmentrybreak on|off
  on:  Stop when entering SMM
  off: Don't stop when entering SMM"""

    def __init__(self):
        super(Edk2SmmEntryBreak, self).__init__("set smmentrybreak", gdb.COMMAND_RUNNING)

    def invoke(self, arg, from_tty):
        self.dont_repeat()
        args = UdkCommandHelper.checkParameter(arg, 1)
        if args != None:
            if args[0] not in ["on", "off"]:
                print(ARGUMENT_ON_OFF_EXPECTED)
                return
            UdkCommandHelper.sendUdkExtensionPacket("smmentrybreak:%s" % args[0])

    def complete(self, text, word):
        return ["on", "off"]
Edk2SmmEntryBreak()

class Edk2BootScriptEntryBreak(gdb.Command):
    """Configure whether the target stops before executing boot script.
Usage: set bootscriptentrybreak on|off
  on:  Stop before executing boot script
  off: Don't stop before executing boot script"""

    def __init__(self):
        super(Edk2BootScriptEntryBreak, self).__init__("set bootscriptentrybreak", gdb.COMMAND_RUNNING)

    def invoke(self, arg, from_tty):
        self.dont_repeat()
        args = UdkCommandHelper.checkParameter(arg, 1)
        if args != None:
            if args[0] not in ["on", "off"]:
                print(ARGUMENT_ON_OFF_EXPECTED)
                return
            UdkCommandHelper.sendUdkExtensionPacket("bootscriptentrybreak:%s" % args[0])

    def complete(self, text, word):
        return ["on", "off"]
Edk2BootScriptEntryBreak()

class Edk2ResetTarget(gdb.Command):
    """Reset the target.
    """

    def __init__(self):
        super(Edk2ResetTarget, self).__init__("resettarget", gdb.COMMAND_RUNNING, gdb.COMPLETE_NONE)

    def invoke(self, arg, from_tty):
        self.dont_repeat()
        args = UdkCommandHelper.checkParameter(arg, 0)
        if args == None:
            return

        for line in UdkCommandHelper.executeCommand("signal SIGKILL"):
            print(line)
Edk2ResetTarget()

class Edk2ImageLoader:
    def __init__(self):
        self._symtbl = []

    def loadsymbol(self, cur, force = False, display = True):
        if force and self._issymbolpresent(cur):
            self._removesymbol(cur)
        if not self._issymbolpresent(cur):
            debug_info = UdkCommandHelper.getTargetDebugInfo(cur)
            if (debug_info != None):
                (debug_link, image_addr, section_info) = debug_info
                if debug_link.endswith(".pdb"):
                    print(UNSUPPORTED_DEBUG_INFORMATION)
                    return False
                if debug_link == "" or \
                   ".text" not in section_info or ".data" not in section_info:
                    print(MISSING_DEBUG_INFORMATION)
                    return False

                # Mach-O uses segment loading
                cmd = "add-symbol-file %s 0x%x" % (debug_link, section_info['.text'])
#                for section_name, section_addr in list(section_info.items()):
#                    if section_name not in [".debug", ".gnu_deb", ".reloc", ".text"]:
#                        cmd += " -s %s 0x%x" % (section_name, section_addr)
#                try:
#                    if display:
#                        gdb.execute(cmd)
#                    else:
#                        UdkCommandHelper.executeCommand(cmd)
#               except RuntimeError as e:
#                   if str(e).find("No such file or directory") != -1:
#                       print(FAILED_TO_FIND_SYMBOL_FILE)
#                   return False
#               except Exception:
#                   print(FAILED_TO_LOAD_SYMBOL)
#                   return False
                self._addsymbol(section_info[".text"], section_info[".data"])
                return True
            else:
                print(FAILED_TO_FIND_DEBUG_INFORMATION)
                return False
        else:
            return True

    def _addsymbol(self, start, end):
        element = (start, end)
        self._symtbl.append(element)

    def _removesymbol(self, addr):
        removelist = []
        for sym in self._symtbl:
            if addr >= sym[0] and addr < sym[1]:
                removelist.append(sym)
        removelist.reverse()
        for sym in removelist:
            self._symtbl.remove(sym)

    def _issymbolpresent(self, addr):
        for sym in self._symtbl:
            if addr >= sym[0] and addr < sym[1]:
                return True
        return False
ImageLoader = Edk2ImageLoader()

class Edk2LoadThis(gdb.Command):
    """Load debug symbol for the given address: loadthis [Address].
Address is address you wish to load debug symbol for.
If no argument is given, the command loads debug symbol for the current instruction pointer."""

    def __init__(self, imageloader):
        super(Edk2LoadThis, self).__init__("loadthis", gdb.COMMAND_FILES, gdb.COMPLETE_NONE)
        self._imageloader = imageloader

    def invoke(self, arg, from_tty):
        args = UdkCommandHelper.checkParameterEx(arg, 0, 1)
        if args != None:
            self.dont_repeat()
            if len(args) == 0:
                cur = gdb.selected_frame().pc()
            else:
                try:
                    cur = int(args[0], 16)
                except:
                    print(ARGUMENT_HEX_EXPECTED)
                    return
            print(LOADING_SYMBOL % cur)
            self._imageloader.loadsymbol(cur, True)
Edk2LoadThis(ImageLoader) # loadthis

class Edk2LoadAll(gdb.Command):
    """Load symbols for all loaded modules.
    """
    def __init__(self, imageloader):
        super(Edk2LoadAll, self).__init__("loadall", gdb.COMMAND_FILES, gdb.COMPLETE_NONE)
        self._imageloader = imageloader

    def invoke(self, arg, from_tty):
        self.dont_repeat()
        args = UdkCommandHelper.checkParameter(arg, 0)
        if args == None:
            return

        response = UdkCommandHelper.sendUdkExtensionPacket("fmodules")
        while response != "l":
            (image_entry, image_base, image_name) = response.split(";")
            response = UdkCommandHelper.sendUdkExtensionPacket("smodules")
            pe_sig = UdkCommandHelper.executeCommand("x/hx %s" % image_base)[0].split()[1]
            if pe_sig in ["0x5a4d", "0x5a56"]:
                print(LOADING_SYMBOL_FOR_MODULE % (image_base, image_name))
                self._imageloader.loadsymbol(int(image_entry, 16), False, False)
            else:
                print(SKIPPING_SYMBOL_FOR_MODULE % (image_base, image_name))
Edk2LoadAll(ImageLoader) # loadall

class Edk2InfoModules(gdb.Command):
    """List information of the loaded modules or the specified module(s).
    """
    def __init__(self):
        super(Edk2InfoModules, self).__init__("info modules", gdb.COMMAND_DATA)

    def _query(self):
        image_info = []
        response = UdkCommandHelper.sendUdkExtensionPacket("fmodules")
        while response != "l":
            image_info.append(response.split(";"))
            response = UdkCommandHelper.sendUdkExtensionPacket("smodules")
        return image_info

    def invoke(self, arg, from_tty):
        self.dont_repeat()
        args = list(map(str.lower, UdkCommandHelper.checkParameterEx(arg, 0, 0xffffffff)))
        if args == None:
            return

        print("ENTRY\tBASE\tNAME")
        print("====================================")
        for (image_entry, image_base, image_name) in self._query():
            if len(args) == 0 or image_name.lower() in args:
                print("%s\t%s\t%s" % (image_entry, image_base, image_name))
        print("")

    def complete(self, text, word):
        suggestion = []
        for (image_entry, image_base, image_name) in self._query():
            if image_name.lower().startswith(word.lower()):
                suggestion.append(image_name)
        return suggestion
Edk2InfoModules()  # info module

def Edk2StopHandler2(event):
    gdb.execute("refresharch")
    if not UdkCommandHelper.supportExpat():
        gdb.execute("loadthis")
    gdb.execute("info exception")
#gdb.events.stop.connect(Edk2StopHandler2)

class Edk2StopHandler(gdb.Command):
    """Command to be run when target is stopped.
    """
    def __init__(self):
        super(Edk2StopHandler, self).__init__("stop-handler", gdb.COMMAND_RUNNING, gdb.COMPLETE_NONE)

    def invoke(self, arg, from_tty):
        self.dont_repeat()
        args = UdkCommandHelper.checkParameter(arg, 0)
        if args == None:
            return
        Edk2StopHandler2(None)
Edk2StopHandler()

class Edk2DebugScript(gdb.Command):
    """Command to turn on or off the script debugging.
    """
    def __init__(self):
        super(Edk2DebugScript, self).__init__("set debug udk-script", gdb.COMMAND_MAINTENANCE)

    def invoke(self, arg, from_tty):
        self.dont_repeat()
        args = UdkCommandHelper.checkParameter(arg, 1)
        if args == None:
            return
        if args[0] not in ["on", "off"]:
            print(ARGUMENT_ON_OFF_EXPECTED)
            return

        UdkCommandHelper._debugMode = (args[0] == "on")

    def complete(self, text, word):
        return ["on", "off"]
Edk2DebugScript()

try:
    gdb.execute("set remotetimeout 20")
    gdb.execute("set disassemble-next-line auto")
    gdb.execute("set step-mode on")
    gdb.execute("set disassembly-flavor intel")
    gdb.execute("set height 0")
    gdb.execute("set prompt (udb) ")
    print(SCRIPT_BANNER_BEGIN)
    # exception raised when GdbServer is not connected
    #print("select_frame")
    #gdb.selected_frame()

    # provide additional command when gdb doesn't support Expat
    if UdkCommandHelper.supportExpat():
       print(SUPPORT_PENDING_BREAKPOINTS)
    else:
       print(NOT_SUPPORT_PENDING_BREAKPOINTS)
    print(SCRIPT_BANNER_END)

    # Set loadimageat an alias to loadthis to keep backward compatibility
    #gdb.execute("alias loadimageat=loadthis")

    # Run the hook-stop script
    # gdb.execute("stop-handler")

    # force to load the shared library in the first time
    # gdb.execute("sharedlibrary")

except:
    print(GDBSERVER_NOT_CONNECTED)
    print(SCRIPT_BANNER_END)
