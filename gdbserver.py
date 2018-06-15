#!/usr/bin/env python
import logging
import collections
import struct
import binascii
import enum

logger = logging.getLogger('gdbserver')
logger.setLevel(logging.INFO)

#### This should be generated from the gdb signals.def
class Signals(enum.IntEnum):
    GDB_SIGNAL_0 = 0
    GDB_SIGNAL_HUP = 1
    GDB_SIGNAL_INT = 2
    GDB_SIGNAL_QUIT = 3
    GDB_SIGNAL_ILL = 4
    GDB_SIGNAL_TRAP = 5
    GDB_SIGNAL_ABRT = 6
    GDB_SIGNAL_EMT = 7
    GDB_SIGNAL_FPE = 8
    GDB_SIGNAL_KILL = 9
    GDB_SIGNAL_BUS = 10
    GDB_SIGNAL_SEGV = 11
    GDB_SIGNAL_SYS = 12
    GDB_SIGNAL_PIPE = 13

class BreakpointState(enum.IntEnum):
    BP_UNDEFINED    =    0x00
    BP_SET          =    0x01
    BP_ACTIVE       =    0x02
    BP_REMOVED      =    0x03

class Breakpoint(object):
    def __init__(self, address):
        self.state = BreakpointState.BP_UNDEFINED
        self.address = address
        self.first_byte = None

class Segment(object):
    def __init__(self, address):
        self.name = None
        self.address = None

class Section(object):
    def __init__(self, name, address, length):
        self.name = name
        self.address = address
        self.length = length

class SharedLibrary(object):
    def __init__(self, address):
        self.name = None
        self.segment = None
        self.sections = None

#### This should be generated from the packaged gdb xmls eventually
# can be viewed in a running gdb with maint remote-registers
architectures = {
    'i386': {
        'registers': [
            {'name': 'eax', 'size': 4 },
            {'name': 'ecx', 'size': 4 },
            {'name': 'edx', 'size': 4 },
            {'name': 'ebx', 'size': 4 },
            {'name': 'esp', 'size': 4 },
            {'name': 'ebp', 'size': 4 },
            {'name': 'esi', 'size': 4 },
            {'name': 'edi', 'size': 4 },
            {'name': 'eip', 'size': 4 },
            {'name': 'eflags', 'size': 4 },
            {'name': 'cs', 'size': 4 },
            {'name': 'ss', 'size': 4 },
            {'name': 'ds', 'size': 4 },
            {'name': 'es', 'size': 4 },
            {'name': 'fs', 'size': 4 },
            {'name': 'gs', 'size': 4 },
            {'name': 'st0', 'size': 10 },
            {'name': 'st1', 'size': 10 },
            {'name': 'st2', 'size': 10 },
            {'name': 'st3', 'size': 10 },
            {'name': 'st4', 'size': 10 },
            {'name': 'st5', 'size': 10 },
            {'name': 'st6', 'size': 10 },
            {'name': 'st7', 'size': 10 },
            {'name': 'fctrl', 'size': 4 },
            {'name': 'fstat', 'size': 4 },
            {'name': 'ftag', 'size': 4 },
            {'name': 'fiseg', 'size': 4 },
            {'name': 'fioff', 'size': 4 },
            {'name': 'foseg', 'size': 4 },
            {'name': 'fooff', 'size': 4 },
            {'name': 'fop', 'size': 4 },
            {'name': 'xmm0', 'size': 16 },
            {'name': 'xmm1', 'size': 16 },
            {'name': 'xmm2', 'size': 16 },
            {'name': 'xmm3', 'size': 16 },
            {'name': 'xmm4', 'size': 16 },
            {'name': 'xmm5', 'size': 16 },
            {'name': 'xmm6', 'size': 16 },
            {'name': 'xmm7', 'size': 16 },
            {'name': 'mxcsr', 'size': 4 },
        ]
    },
    'i386:x86-64': {
        'registers': [
            {'name': 'rax', 'size': 8 },
            {'name': 'rbx', 'size': 8 },
            {'name': 'rcx', 'size': 8 },
            {'name': 'rdx', 'size': 8 },
            {'name': 'rsi', 'size': 8 },
            {'name': 'rdi', 'size': 8 },
            {'name': 'rbp', 'size': 8 },
            {'name': 'rsp', 'size': 8 },

            {'name': 'r8',  'size': 8 },
            {'name': 'r9',  'size': 8 },
            {'name': 'r10', 'size': 8 },
            {'name': 'r11', 'size': 8 },
            {'name': 'r12', 'size': 8 },
            {'name': 'r13', 'size': 8 },
            {'name': 'r14', 'size': 8 },
            {'name': 'r15', 'size': 8 },

            {'name': 'rip', 'size': 8 },

            {'name': 'eflags', 'size': 4 },

            {'name': 'cs',  'size': 4 },
            {'name': 'ss',  'size': 4 },
            {'name': 'ds',  'size': 4 },
            {'name': 'es',  'size': 4 },
            {'name': 'fs',  'size': 4 },
            {'name': 'gs',  'size': 4 },

            {'name': 'st0', 'size': 10 },
            {'name': 'st1', 'size': 10 },
            {'name': 'st2', 'size': 10 },
            {'name': 'st3', 'size': 10 },
            {'name': 'st4', 'size': 10 },
            {'name': 'st5', 'size': 10 },
            {'name': 'st6', 'size': 10 },
            {'name': 'st7', 'size': 10 },

            {'name': 'fctrl', 'size': 4 },
            {'name': 'fstat', 'size': 4 },
            {'name': 'ftag', 'size': 4 },
            {'name': 'fiseg', 'size': 4 },
            {'name': 'fioff', 'size': 4 },
            {'name': 'foseg', 'size': 4 },
            {'name': 'fooff', 'size': 4 },
            {'name': 'fop', 'size': 4 },

            {'name': 'xmm0', 'size': 16 },
            {'name': 'xmm1', 'size': 16 },
            {'name': 'xmm2', 'size': 16 },
            {'name': 'xmm3', 'size': 16 },
            {'name': 'xmm4', 'size': 16 },
            {'name': 'xmm5', 'size': 16 },
            {'name': 'xmm6', 'size': 16 },
            {'name': 'xmm7', 'size': 16 },
            {'name': 'xmm8', 'size': 16 },
            {'name': 'xmm9', 'size': 16 },
            {'name': 'xmm10', 'size': 16 },
            {'name': 'xmm11', 'size': 16 },
            {'name': 'xmm12', 'size': 16 },
            {'name': 'xmm13', 'size': 16 },
            {'name': 'xmm14', 'size': 16 },
            {'name': 'xmm15', 'size': 16 }
        ]
    }
}

class RemoteException(Exception):
    pass

class GdbHostStub(object):
    def __init__(self, rsp):
        super(GdbHostStub, self).__init__()
        self.rsp = rsp
        self.initialized = False
        self.features = {
            b'multiprocess': False,
            b'xmlRegisters': True,
            b'qRelocInsn': False,
            b'swbreak': True,
            b'hwbreak': True,
        }
        self.architecture = 'i386'
        self.breakpoints = []
        self.packet_handlers = collections.defaultdict(int)
        self.general_query_xfer_handlers = collections.defaultdict(dict)

        #### Standard Packet Handlers
        self.add_packet_handler(b'!', self.extended_mode)
        self.add_packet_handler(b'\x03', self.send_break)
        self.add_packet_handler(b'c', self.continue_execution)
        self.add_packet_handler(b'C', self.continue_execution_with_signal)
        self.add_packet_handler(b'g', self.read_registers)
        self.add_packet_handler(b'k', self.disconnect)
        self.add_packet_handler(b'm', self.read_memory)
        self.add_packet_handler(b'M', self.write_memory)
        self.add_packet_handler(b'p', self.read_register)
        self.add_packet_handler(b'P', self.write_register)
        self.add_packet_handler(b's', self.step_instruction)
        self.add_packet_handler(b'S', self.step_instruction_with_signal)
        self.add_packet_handler(b'Z', self.insert_breakpoint)
        self.add_packet_handler(b'z', self.remove_breakpoint)
        self.add_packet_handler(b'?', self.halt_reason)

        #### General Query
        self.add_packet_handler(b'q', self.general_query)
        self.general_query_handlers = collections.defaultdict(int)

        #### General Set
        self.add_packet_handler(b'Q', self.general_set)
        self.general_set_handlers = collections.defaultdict(int)

        #### Verbose Packet Prefix
        self.add_packet_handler(b'v', self.verbose)
        self.verbose_handlers = collections.defaultdict(int)

        #### Standard General Queries
        self.add_general_query_handler(b'Supported', self.general_query_supported)
        self.add_general_query_handler(b'Attached', self.general_query_attached)

        #### No ACK mode handler
        self.add_feature(b'QStartNoAckMode')
        self.add_general_set_handler(b'StartNoAckMode', self.general_set_start_no_ack_mode)
        self.rsp.no_acknowledgement_mode = False

        #### qXfer:object:read:annex:offset,length features
        self.xmls = collections.defaultdict(dict)

        self.add_feature(b'qXfer:features:read', False)
        self.add_feature(b'qXfer:libraries:read', False)
        self.add_general_query_handler(b'Xfer', self.general_query_xfer)

        #### Thread Info
        self.add_packet_handler(b'H', self.set_thread)
#        self.add_general_query_handler(b'C', self.general_query_current_thread)
#        self.add_general_query_handler(b'fThreadInfo', self.general_query_thread_info_first)
#        self.add_general_query_handler(b'sThreadInfo', self.general_query_thread_info_subsequent)

        #### Tracepoint Support
#        self.add_general_query_handler(b'TStatus', self.general_query_trace_status)
#        self.add_general_query_handler(b'TfV', self.general_query_trace_var_first)
#        self.add_general_query_handler(b'TsV', self.general_query_trace_var_subsequent)
#        self.add_general_query_handler(b'TfP', self.general_query_tracepoint_first)
#        self.add_general_query_handler(b'TsP', self.general_query_tracepoint_subsequent)

        self.add_verbose_handler(b'Kill', self.vkill)


    def add_feature(self, feature, value = True):
        self.features[feature] = value

    def add_packet_handler(self, cmd, handler):
        self.packet_handlers[cmd] = handler

    def add_general_query_handler(self, cmd, handler):
        self.general_query_handlers[cmd] = handler

    def add_general_query_xfer_handler(self, obj, operation, handler):
        self.general_query_xfer_handlers[obj][operation] = handler

    def add_general_set_handler(self, cmd, handler):
        self.general_set_handlers[cmd] = handler

    def add_verbose_handler(self, cmd, handler):
        self.verbose_handlers[cmd] = handler

    def set_architecture(self, architecture):
        if not architecture in architectures.keys():
            raise TypeError("unknown architecture")
        self.architecture = architecture

    #### Top Level GDB Commands
    ###


    def find_breakpoint(self, addr):
        for i, d in enumerate(self.breakpoints):
            if d['addr'] == addr:
                return i
        raise ValueError('breakpoint not found with address')

    def insert_breakpoint_impl(self, index, addr, kind):
        raise NotImplementedError("implement GdbHostStub and override insert_breakpoint_impl")

    def insert_breakpoint(self, args):
        """‘z0,addr,kind’
           ‘Z0,addr,kind[;cond_list...][;cmds:persist,cmd_list...]’
        Insert (‘Z0’) or remove (‘z0’) a memory breakpoint at address addr of type kind.
        A memory breakpoint is implemented by replacing the instruction at addr with a software
        breakpoint or trap instruction. The kind is target-specific and typically indicates the
        size of the breakpoint in bytes that should be inserted. E.g., the arm and mips can
        insert either a 2 or 4 byte breakpoint. Some architectures have additional meanings
        for kind; cond_list is an optional list of conditional expressions in bytecode form
        that should be evaluated on the target's side. These are the conditions that should
        be taken into consideration when deciding if the breakpoint trigger should be
        reported back to GDBN.

        See also the ‘swbreak’ stop reason (see swbreak stop reason) for how to best report a
        breakpoint event to gdb.

        The cond_list parameter is comprised of a series of expressions, concatenated without
        separators. Each expression has the following form:

        ‘X len,expr’
        len is the length of the bytecode expression and expr is the actual conditional expression
        in bytecode form. The optional cmd_list parameter introduces commands that may be run on
        the target, rather than being reported back to gdb. The parameter starts with a numeric
        flag persist; if the flag is nonzero, then the breakpoint may remain active and the
        commands continue to be run even when gdb disconnects from the target.
        Following this flag is a series of expressions concatenated with no separators.
        Each expression has the following form:

        ‘X len,expr’
        len is the length of the bytecode expression and expr is the actual conditional expression in bytecode form.
        see Architecture-Specific Protocol Details.

        Implementation note: It is possible for a target to copy or move code that contains memory
        breakpoints (e.g., when implementing overlays). The behavior of this packet, in the presence
        of such a target, is not defined.

        Reply:
        ‘OK’
        success
        ‘’
        not supported
        ‘E NN’
        for an error"""
        params = args
        if b';' in args:
            params, cond_list, cmd_list = args.split(b';')

        index, addr, kind = params.split(b',')
        index = int(index, 10)
        addr = int(addr, 16)
        self.insert_breakpoint_impl(index, addr, kind)
        self.rsp.send_packet(b'OK')

    def remove_breakpoint_impl(self, index, addr, kind):
        raise NotImplementedError("implement GdbHostStub and override remove_breakpoint_impl")

    def remove_breakpoint(self, args):
        index, addr, kind = args.split(b',')
        index = int(index, 10)
        addr = int(addr, 16)
        self.remove_breakpoint_impl(index, addr, kind)
        self.rsp.send_packet(b'OK')

    def continue_execution_impl(self, args):
        raise NotImplementedError("implement GdbHostStub and override continue_execution")

    def continue_execution(self, args):
        """‘c [addr]’

        Continue at addr, which is the address to resume. If addr is omitted, resume at current address.
        This packet is deprecated for multi-threading support. See vCont packet.
        Reply: See Stop Reply Packets, for the reply specifications."""
        self.continue_execution_impl()

    def continue_execution_with_signal_impl(self, sig, addr):
        raise NotImplementedError("implement GdbHostStub and override continue_execution")

    def continue_execution_with_signal(self, args):
        """‘C sig[;addr]’

        Continue with signal sig (hex signal number). If ‘;addr’ is omitted, resume at same address.
        This packet is deprecated for multi-threading support. See vCont packet.

        Reply: See Stop Reply Packets, for the reply specifications."""
        sig = args
        addr = None
        if b';' in sig:
            sig, addr = args.split(b';')
            addr = int(addr, 16)

        sig = int(sig, 16)
        self.continue_execution_with_signal_impl(sig, addr)

    def disconnect_impl(self, sig, addr):
        raise NotImplementedError("implement GdbHostStub and override disconnect_impl")

    def disconnect(self, args):
        self.disconnect_impl()
        return False

    def extended_mode(self, args):
        """‘!’

        Enable extended mode. In extended mode, the remote server is made persistent. The ‘R’ packet is used to restart the program being debugged.
        Reply:
        ‘OK’
        The remote target both supports and has enabled extended mode."""
        self.rsp.send_packet(b'OK')

    def halt_reason_impl(self):
        raise NotImplementedError("implement GdbHostStub and override halt_reason_impl")

    def halt_reason(self, args):
        """‘?’

        Indicate the reason the target halted. The reply is the same as for step and continue. This packet has a special interpretation when the target is in non-stop mode; see Remote Non-Stop.
        Reply: See Stop Reply Packets, for the reply specifications."""
        (cause, nr) = self.halt_reason_impl()
        self.rsp.send_stop_reply_packet(cause, nr)

    def read_memory_impl(self, address, size):
        raise NotImplementedError("implement GdbHostStub and override read_memory_impl")

    def read_memory(self, args):
        addr, size = args.split(b',')
        addr = int(addr, 16)
        size = int(size, 16)

        try:
            data = self.read_memory_impl(addr, size)
            self.rsp.send_packet(binascii.hexlify(data))
        except:
            self.rsp.send_packet(b'E99')

    def read_register_impl(self, register_name):
        raise NotImplementedError('implement GdbHostStub and override read_registers_impl')

    def read_register(self, args):
        index = int(args, 16)
        if index is None:
            self.rsp.send_packet(b'E00')
            return

        archdef = architectures[self.architecture]

        register = archdef['registers'][index]
        register_name = register['name']
        register_size = register['size']

        value = self.read_register_impl(register_name)

        s = b''
        if register_size == 4:
            s = binascii.hexlify(struct.pack('<I', value))
        elif register_size == 8:
            s = binascii.hexlify(struct.pack('<Q', value))
        elif register_size == 10:
            s = binascii.hexlify(value)

        self.rsp.send_packet(s)

    def read_registers_impl(self):
        raise NotImplementedError('implement GdbHostStub and override read_registers_impl')

    def read_registers(self, args):
        archdef = architectures[self.architecture]

        defaults = {}
        for register in archdef['registers']:
            register_name = register['name']
            defaults[register_name] = 0

        values = self.read_registers_impl(defaults)

        s = b''
        for register in archdef['registers']:
            register_name = register['name']
            register_size = register['size']
            if register_size == 4:
                s += binascii.hexlify(struct.pack('<I', values[register_name]))
            elif register_size == 8:
                s += binascii.hexlify(struct.pack('<Q', values[register_name]))
            elif register_size == 10:
                s += binascii.hexlify(values[register_name])

        self.rsp.send_packet(s)

    def send_break_impl(self):
        raise NotImplementedError("implement GdbHostStub and override send_break")

    def send_break(self, args):
        (cause, nr) = self.send_break_impl()
        self.rsp.send_stop_reply_packet(cause, nr)

    def set_thread(self, args):
        self.rsp.send_packet(b'OK')

    def step_instruction_impl(self):
        raise NotImplementedError("implement GdbHostStub and override send_break")

    def step_instruction(self, args):
        """'s [addr]'

        Single step, resuming at addr. If addr is omitted, resume at same address.
        This packet is deprecated for multi-threading support. See vCont packet.
        Reply: See Stop Reply Packets, for the reply specifications."""
        (cause, nr) = self.step_instruction_impl()
        self.rsp.send_stop_reply_packet(cause, nr)

    def step_instruction_with_signal_impl(self):
        raise NotImplementedError("implement GdbHostStub and override send_break")

    def step_instruction_with_signal(self, args):
        """‘S sig[;addr]’
        Step with signal. This is analogous to the ‘C’ packet, but requests a single-step, rather than a normal resumption of execution.
        This packet is deprecated for multi-threading support. See vCont packet.

        Reply: See Stop Reply Packets, for the reply specifications."""
        self.step_instruction_with_signal_impl()
#        self.rsp.send_stop_reply_packet(cause, nr)

    def vkill(self, args):
        pass

    def write_memory_impl(self, address, size):
        raise NotImplementedError("implement GdbHostStub and override write_memory_impl")

    def write_memory(self, args):
        params, data = args.split(b':', 1)
        addr, size = params.split(b',', 1)
        addr = int(addr, 16)
        size = int(size, 16)
        data = binascii.unhexlify(data)

        self.write_memory_impl(addr, size, data)
        self.rsp.send_packet(b'OK')

    def write_register_impl(self, register_name, value):
        raise NotImplementedError("implement GdbHostStub and override write_memory_impl")

    def write_register(self, args):
        register, value = args.split(b'=', 2)
        index = int(register, 16)

        if index is None:
            self.rsp.send_packet(b'E00')
            return

        archdef = architectures[self.architecture]

        register = archdef['registers'][index]
        register_name = register['name']
        register_size = register['size']

        s = 0
        if register_size == 4:
            s, = struct.unpack('<I', binascii.unhexlify(value))
        elif register_size == 8:
            s, = struct.unpack('<Q', binascii.unhexlify(value))
        elif register_size == 16:
            s = struct.unpack('<QQ', binascii.unhexlify(value))
        elif register_size == 10:
            s = binascii.unhexlify(value)

        value = self.write_register_impl(register_name, s)
        self.rsp.send_packet(b'OK')

    #### Standard GDB Commands
    ###
    def general_query(self, query):
        cmd = query
        args = b''
        if b':' in cmd:
            cmd, args = query.split(b':', 1)

        if cmd not in self.general_query_handlers:
            logger.error('This subcommand %r is not implemented in q' % cmd)
            self.rsp.send_packet(b'')
            return

        self.general_query_handlers[cmd](args)

    def general_set(self, query):
        cmd = query
        args = b''
        if b':' in cmd:
            cmd, args = query.split(b':', 1)

        if cmd not in self.general_set_handlers:
            logger.error('This subcommand %r is not implemented in q' % cmd)
            self.rsp.send_packet(b'')
            return

        self.general_set_handlers[cmd](args)

    def verbose(self, query):
        cmd = query
        args = b''
        if b';' in cmd:
            cmd, args = query.split(b';', 1)

        if cmd not in self.verbose_handlers:
            logger.error('This subcommand %r is not implemented in v' % cmd)
            self.rsp.send_packet(b'')
            return

        self.verbose_handlers[cmd](args)

    #### General Query Handlers
    def general_query_attached(self, args):
        self.rsp.send_packet(b'1')

    def general_query_current_thread(self, args):
        self.rsp.send_packet(b'QC1')

    def general_query_supported(self, args):
        features = []
        for feature, value in self.features.items():
            if value == True:
                features.append(b'%s+' % feature)
            elif value == False:
                features.append(b'%s-' % feature)
            else:
                features.append(b'%s=%x' % (feature, value))

        self.rsp.send_packet(b';'.join(features))

    def general_query_thread_info_first(self, args):
        self.rsp.send_packet(b'l')

    def general_query_thread_info_subsequent(self, args):
        self.rsp.send_packet(b'')

    #### XML Object transfer support
    def set_xml(self, obj, annex, xml):
        self.xmls[obj][annex] = xml

    def general_query_xfer(self, args):
        obj, operation, annex, offsetlength = args.split(b':', 4)
        offset, length = offsetlength.split(b',', 2)
        offset = int(offset, 16)
        length = int(length, 16)

        if operation == b'read':
            xml = None
            try:
                xml = self.xmls[obj][annex]
            except KeyError:
                self.rsp.send_packet(b'E02')  # No such file or directory

            packet = b'm'       # More follows
            end = offset + length
            if offset > len(xml) or end > len(xml):
                packet = b'l'   # Last
            self.rsp.send_packet(packet + xml[offset:end])
        else:
            logger.error('requested xfer operation not supported: {}:{}'.format(obj, operation))
            self.rsp.send_packet(b'')


    #### Trace support
    ### Trace variables not currently used
    def general_query_trace_status(self, args):
        self.rsp.send_packet(b'T0;tnotrun:0')

    def general_query_trace_var_first(self, args):
        self.rsp.send_packet(b'')

    def general_query_trace_var_subsequent(self, args):
        self.rsp.send_packet(b'')

    def general_query_tracepoint_first(self, args):
        self.rsp.send_packet(b'')

    def general_query_tracepoint_subsequent(self, args):
        self.rsp.send_packet(b'')

    #### No Acknowledgement Mode Support
    ###
    def general_set_start_no_ack_mode(self, args):
        self.rsp.no_acknowledgement_mode = True
        self.rsp.send_packet(b'OK')
        self.rsp.expect_ack() ## Soak up last ACK

class GdbRemoteSerialProtocol(object):
    def __init__(self, connection, clazz, *args, **kwargs):
        super(GdbRemoteSerialProtocol, self).__init__()
        self.stub = clazz(self, *args, **kwargs)
        self.connection = connection
        self.initialized = False

    ####
    #### Packet handling routines below
    ####
    def command_communication(self):
        message = self.receive_packet()
        cmd, subcmd = message[0:1], message[1:]

        ### Ignore an initial Ack ('+') if one is sent (gdb)
        initialized = self.initialized
        self.initialized = True
        if cmd == b'+' and initialized == False:
            return True

        if cmd == b'\x03':
            logger.debug('break received'.format(message))

        if cmd == b'-':
            logger.debug('resend requested'.format(message))
            return True

        if cmd not in self.stub.packet_handlers:
            logger.warning('{} command not handled'.format(message))
            self.send_packet(b'')
            return True

        return self.stub.packet_handlers[cmd](subcmd)

    def receive_packet(self):
        c = self.connection.read(1)
        # Ack packet
        if c != b'+' and c != b'$' and c != b'-' and c != b'\x03':
            raise RemoteException('Expected "$" received: "{0!s}"'.format(c))

        message = b''
        if c == b'+' or c == b'-' or c == b'\x03':
            message = c

        # Start of message
        elif c == b'$':
            while True:
                c = self.connection.read(1)
                if c == b'#':
                    break

                message += c

            # Checksum
            checksum = self.connection.read(2)
            checksum = int(checksum, 16)

            # if not self.no_acknowledgement_mode and checksum != self.calculate_checksum(message):
            if checksum != self.calculate_checksum(message):
                raise RemoteException('Wrong checksum {}'.format(checksum))

            logger.debug('[GDB][RX] ${0!s}#{1:x}'.format(message.decode('utf-8'), checksum))
            self.send_ack()

        return message

    def send_stop_reply_packet(self, cause, nr = None):
        s = b'S'
        if nr:
            s = b'T'

        # Process the N:R pairs
        s += binascii.hexlify(struct.pack('<B', cause))
        if nr:
            for n, r in nr.items():
                s += b':'.join([n, r]) + b';'

        self.send_packet(s)

    def send_packet(self, message):
        checksum = self.calculate_checksum(message)
        self.send(b'$%s#%02x' % (message, checksum))
        if not self.no_acknowledgement_mode:
            logger.debug('waiting for acknowledgement'.format(message))
            self.expect_ack()

    def send(self, packet):
        logger.debug('[GDB][TX] {0!s}'.format(packet.decode('utf-8')))
        self.connection.write(packet)
        self.connection.flush()

    def send_ack(self):
        self.send(b'+')

    def expect_ack(self):
        message = self.receive_packet()
        if message != b'+':
            raise RemoteException('Wrong ack: "{}"'.format(str(message)))

    def calculate_checksum(self, pkt):
        sum = 0
        for c in pkt:
            sum += c
        return sum & 0xff

    def close(self):
        self.send_packet('k')
        self.connection.close()

    def __del__(self):
        try:
            self.close()
        except:
            # close() most likely already called
            pass


    #### Not used yet
    def expect_signal(self):
        msg = self.__recv_msg()
        assert len(msg) == 3 and msg[0] == 'S', 'Expected "S", received "%c" % msg[0]'
        return int(msg[1:], 16)
