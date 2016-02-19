#!/usr/bin/env python

"""
An echo server that uses threads to handle multiple clients at a time.
Entering any line of input at the terminal will exit the server.
"""

import logging
import struct
import enum

logger = logging.getLogger('udkserver')
logger.setLevel(logging.DEBUG)

PACKET_READ_TIMEOUT = 0.25

DEBUG_STARTING_SYMBOL_ATTACH = 0xfa
DEBUG_STARTING_SYMBOL_COMPRESS = 0xfc
DEBUG_STARTING_SYMBOL_NORMAL = 0xfe

DEBUG_COMMAND_REQUEST   = 0 << 7
DEBUG_COMMAND_RESPONSE  = 1 << 7

DEBUG_AGENT_SETTING_SMM_ENTRY_BREAK         = 1
DEBUG_AGENT_SETTING_PRINT_ERROR_LEVEL       = 2
DEBUG_AGENT_SETTING_BOOT_SCRIPT_ENTRY_BREAK = 3

DEBUG_DATA_UPPER_LIMIT              = 255
DEBUG_DATA_MAXIMUM_REAL_DATA        = DEBUG_DATA_UPPER_LIMIT - 6 # sizeof(DEBUG_PACKET_HEADER)

class DebugCommands(enum.IntEnum):
    #
    # HOST initiated commands
    #
    DEBUG_COMMAND_RESET                 = DEBUG_COMMAND_REQUEST | 0x00
    DEBUG_COMMAND_GO                    = DEBUG_COMMAND_REQUEST | 0x01
    DEBUG_COMMAND_BREAK_CAUSE           = DEBUG_COMMAND_REQUEST | 0x02
    DEBUG_COMMAND_SET_HW_BREAKPOINT     = DEBUG_COMMAND_REQUEST | 0x03
    DEBUG_COMMAND_CLEAR_HW_BREAKPOINT   = DEBUG_COMMAND_REQUEST | 0x04
    DEBUG_COMMAND_SINGLE_STEPPING       = DEBUG_COMMAND_REQUEST | 0x05
    DEBUG_COMMAND_SET_SW_BREAKPOINT     = DEBUG_COMMAND_REQUEST | 0x06
    DEBUG_COMMAND_READ_MEMORY           = DEBUG_COMMAND_REQUEST | 0x07
    DEBUG_COMMAND_WRITE_MEMORY          = DEBUG_COMMAND_REQUEST | 0x08
    DEBUG_COMMAND_READ_IO               = DEBUG_COMMAND_REQUEST | 0x09
    DEBUG_COMMAND_WRITE_IO              = DEBUG_COMMAND_REQUEST | 0x0a
    DEBUG_COMMAND_READ_REGISTER         = DEBUG_COMMAND_REQUEST | 0x0b
    DEBUG_COMMAND_WRITE_REGISTER        = DEBUG_COMMAND_REQUEST | 0x0c
    DEBUG_COMMAND_READ_ALL_REGISTERS    = DEBUG_COMMAND_REQUEST | 0x0d
    DEBUG_COMMAND_ARCH_MODE             = DEBUG_COMMAND_REQUEST | 0x0e
    DEBUG_COMMAND_READ_MSR              = DEBUG_COMMAND_REQUEST | 0x0f
    DEBUG_COMMAND_WRITE_MSR             = DEBUG_COMMAND_REQUEST | 0x10
    DEBUG_COMMAND_SET_DEBUG_SETTING     = DEBUG_COMMAND_REQUEST | 0x11
    DEBUG_COMMAND_GET_REVISION          = DEBUG_COMMAND_REQUEST | 0x12
    DEBUG_COMMAND_GET_EXCEPTION         = DEBUG_COMMAND_REQUEST | 0x13
    DEBUG_COMMAND_SET_VIEWPOINT         = DEBUG_COMMAND_REQUEST | 0x14
    DEBUG_COMMAND_GET_VIEWPOINT         = DEBUG_COMMAND_REQUEST | 0x15
    DEBUG_COMMAND_DETACH                = DEBUG_COMMAND_REQUEST | 0x16
    DEBUG_COMMAND_CPUID                 = DEBUG_COMMAND_REQUEST | 0x17
    DEBUG_COMMAND_SEARCH_SIGNATURE      = DEBUG_COMMAND_REQUEST | 0x18
    DEBUG_COMMAND_HALT                  = DEBUG_COMMAND_REQUEST | 0x19

    #
    # TARGET initiated commands
    #
    DEBUG_COMMAND_INIT_BREAK            = DEBUG_COMMAND_REQUEST | 0x3f
    DEBUG_COMMAND_BREAK_POINT           = DEBUG_COMMAND_REQUEST | 0x3e
    DEBUG_COMMAND_MEMORY_READY          = DEBUG_COMMAND_REQUEST | 0x3d
    DEBUG_COMMAND_PRINT_MESSAGE         = DEBUG_COMMAND_REQUEST | 0x3c
    DEBUG_COMMAND_ATTACH_BREAK          = DEBUG_COMMAND_REQUEST | 0x3b

    #
    # Response commands
    #
    DEBUG_COMMAND_OK                    = DEBUG_COMMAND_RESPONSE | 0x00
    DEBUG_COMMAND_RESEND                = DEBUG_COMMAND_RESPONSE | 0x01
    DEBUG_COMMAND_ABORT                 = DEBUG_COMMAND_RESPONSE | 0x02

    #
    # The below 2 commands are used when transferring big data (like > ~250 bytes).
    # The sequence is:
    # HOST                      TARGET
    # Request           =>
    #                   <=      IN PROGRESS with partial data
    # CONTINUE          =>
    # (could have multiple IN_PROGRESS and CONTINUE interactions)
    #                   <=      OK with the last part of data
    # OK (no data - ACK)=>
    #
    DEBUG_COMMAND_IN_PROGRESS           = DEBUG_COMMAND_RESPONSE | 0x03
    DEBUG_COMMAND_CONTINUE              = DEBUG_COMMAND_RESPONSE | 0x04

    #
    # The below 2 commands are used to support deferred halt:
    # TARGET returns HALT_DEFERRED when it receives a HALT request in inter-active mode.
    # TARGET returns HALT_PROCESSED when it receives a GO request and has a pending HALT request.
    DEBUG_COMMAND_HALT_DEFERRED         = DEBUG_COMMAND_RESPONSE | 0x05
    DEBUG_COMMAND_HALT_PROCESSED        = DEBUG_COMMAND_RESPONSE | 0x06

    DEBUG_COMMAND_TIMEOUT               = DEBUG_COMMAND_RESPONSE | 0x07
    DEBUG_COMMAND_NOT_SUPPORTED         = DEBUG_COMMAND_RESPONSE | 0x0f

class BreakCauses(enum.IntEnum):
    DEBUG_DATA_BREAK_CAUSE_UNKNOWN        = 0
    DEBUG_DATA_BREAK_CAUSE_HW_BREAKPOINT  = 1
    DEBUG_DATA_BREAK_CAUSE_STEPPING       = 2
    DEBUG_DATA_BREAK_CAUSE_SW_BREAKPOINT  = 3
    DEBUG_DATA_BREAK_CAUSE_USER_HALT      = 4
    DEBUG_DATA_BREAK_CAUSE_IMAGE_LOAD     = 5
    DEBUG_DATA_BREAK_CAUSE_IMAGE_UNLOAD   = 6
    DEBUG_DATA_BREAK_CAUSE_SYSTEM_RESET   = 7
    DEBUG_DATA_BREAK_CAUSE_EXCEPTION      = 8
    DEBUG_DATA_BREAK_CAUSE_MEMORY_READY   = 9

SOFT_DEBUGGER_REGISTER_FP_BASE         =    0x30


#
#  IA-32/x64 processor register index table
#
class Register(enum.IntEnum):
    SOFT_DEBUGGER_REGISTER_DR0     =    0x00
    SOFT_DEBUGGER_REGISTER_DR1     =    0x01
    SOFT_DEBUGGER_REGISTER_DR2     =    0x02
    SOFT_DEBUGGER_REGISTER_DR3     =    0x03
    SOFT_DEBUGGER_REGISTER_DR6     =    0x04
    SOFT_DEBUGGER_REGISTER_DR7     =    0x05
    SOFT_DEBUGGER_REGISTER_EFLAGS  =    0x06
    SOFT_DEBUGGER_REGISTER_LDTR    =    0x07
    SOFT_DEBUGGER_REGISTER_TR      =    0x08
    SOFT_DEBUGGER_REGISTER_GDTR0   =    0x09 # the low 32bit of GDTR
    SOFT_DEBUGGER_REGISTER_GDTR1   =    0x0A # the high 32bit of GDTR
    SOFT_DEBUGGER_REGISTER_IDTR0   =    0x0B # the low 32bit of IDTR
    SOFT_DEBUGGER_REGISTER_IDTR1   =    0x0C # the high 32bot of IDTR
    SOFT_DEBUGGER_REGISTER_EIP     =    0x0D
    SOFT_DEBUGGER_REGISTER_GS      =    0x0E
    SOFT_DEBUGGER_REGISTER_FS      =    0x0F
    SOFT_DEBUGGER_REGISTER_ES      =    0x10
    SOFT_DEBUGGER_REGISTER_DS      =    0x11
    SOFT_DEBUGGER_REGISTER_CS      =    0x12
    SOFT_DEBUGGER_REGISTER_SS      =    0x13
    SOFT_DEBUGGER_REGISTER_CR0     =    0x14
    SOFT_DEBUGGER_REGISTER_CR1     =    0x15
    SOFT_DEBUGGER_REGISTER_CR2     =    0x16
    SOFT_DEBUGGER_REGISTER_CR3     =    0x17
    SOFT_DEBUGGER_REGISTER_CR4     =    0x18

    SOFT_DEBUGGER_REGISTER_DI      =    0x19
    SOFT_DEBUGGER_REGISTER_SI      =    0x1A
    SOFT_DEBUGGER_REGISTER_BP      =    0x1B
    SOFT_DEBUGGER_REGISTER_SP      =    0x1C
    SOFT_DEBUGGER_REGISTER_DX      =    0x1D
    SOFT_DEBUGGER_REGISTER_CX      =    0x1E
    SOFT_DEBUGGER_REGISTER_BX      =    0x1F
    SOFT_DEBUGGER_REGISTER_AX      =    0x20

    #
    # This below registers are only available for x64 (not valid for Ia32 mode)
    #
    SOFT_DEBUGGER_REGISTER_CR8     =    0x21
    SOFT_DEBUGGER_REGISTER_R8      =    0x22
    SOFT_DEBUGGER_REGISTER_R9      =    0x23
    SOFT_DEBUGGER_REGISTER_R10     =    0x24
    SOFT_DEBUGGER_REGISTER_R11     =    0x25
    SOFT_DEBUGGER_REGISTER_R12     =    0x26
    SOFT_DEBUGGER_REGISTER_R13     =    0x27
    SOFT_DEBUGGER_REGISTER_R14     =    0x28
    SOFT_DEBUGGER_REGISTER_R15     =    0x29

    #
    # This below registers are FP / MMX / XMM registers
    #
    SOFT_DEBUGGER_REGISTER_FP_FCW          =    (SOFT_DEBUGGER_REGISTER_FP_BASE + 0x00)
    SOFT_DEBUGGER_REGISTER_FP_FSW          =    (SOFT_DEBUGGER_REGISTER_FP_BASE + 0x01)
    SOFT_DEBUGGER_REGISTER_FP_FTW          =    (SOFT_DEBUGGER_REGISTER_FP_BASE + 0x02)
    SOFT_DEBUGGER_REGISTER_FP_OPCODE       =    (SOFT_DEBUGGER_REGISTER_FP_BASE + 0x03)
    SOFT_DEBUGGER_REGISTER_FP_EIP          =    (SOFT_DEBUGGER_REGISTER_FP_BASE + 0x04)
    SOFT_DEBUGGER_REGISTER_FP_CS           =    (SOFT_DEBUGGER_REGISTER_FP_BASE + 0x05)
    SOFT_DEBUGGER_REGISTER_FP_DATAOFFSET   =    (SOFT_DEBUGGER_REGISTER_FP_BASE + 0x06)
    SOFT_DEBUGGER_REGISTER_FP_DS           =    (SOFT_DEBUGGER_REGISTER_FP_BASE + 0x07)
    SOFT_DEBUGGER_REGISTER_FP_MXCSR        =    (SOFT_DEBUGGER_REGISTER_FP_BASE + 0x08)
    SOFT_DEBUGGER_REGISTER_FP_MXCSR_MASK   =    (SOFT_DEBUGGER_REGISTER_FP_BASE + 0x09)
    SOFT_DEBUGGER_REGISTER_ST0             =    (SOFT_DEBUGGER_REGISTER_FP_BASE + 0x0A)
    SOFT_DEBUGGER_REGISTER_ST1             =    (SOFT_DEBUGGER_REGISTER_FP_BASE + 0x0B)
    SOFT_DEBUGGER_REGISTER_ST2             =    (SOFT_DEBUGGER_REGISTER_FP_BASE + 0x0C)
    SOFT_DEBUGGER_REGISTER_ST3             =    (SOFT_DEBUGGER_REGISTER_FP_BASE + 0x0D)
    SOFT_DEBUGGER_REGISTER_ST4             =    (SOFT_DEBUGGER_REGISTER_FP_BASE + 0x0E)
    SOFT_DEBUGGER_REGISTER_ST5             =    (SOFT_DEBUGGER_REGISTER_FP_BASE + 0x0F)
    SOFT_DEBUGGER_REGISTER_ST6             =    (SOFT_DEBUGGER_REGISTER_FP_BASE + 0x10)
    SOFT_DEBUGGER_REGISTER_ST7             =    (SOFT_DEBUGGER_REGISTER_FP_BASE + 0x11)
    SOFT_DEBUGGER_REGISTER_XMM0            =    (SOFT_DEBUGGER_REGISTER_FP_BASE + 0x12)
    SOFT_DEBUGGER_REGISTER_XMM1            =    (SOFT_DEBUGGER_REGISTER_FP_BASE + 0x13)
    SOFT_DEBUGGER_REGISTER_XMM2            =    (SOFT_DEBUGGER_REGISTER_FP_BASE + 0x14)
    SOFT_DEBUGGER_REGISTER_XMM3            =    (SOFT_DEBUGGER_REGISTER_FP_BASE + 0x15)
    SOFT_DEBUGGER_REGISTER_XMM4            =    (SOFT_DEBUGGER_REGISTER_FP_BASE + 0x16)
    SOFT_DEBUGGER_REGISTER_XMM5            =    (SOFT_DEBUGGER_REGISTER_FP_BASE + 0x17)
    SOFT_DEBUGGER_REGISTER_XMM6            =    (SOFT_DEBUGGER_REGISTER_FP_BASE + 0x18)
    SOFT_DEBUGGER_REGISTER_XMM7            =    (SOFT_DEBUGGER_REGISTER_FP_BASE + 0x19)
    SOFT_DEBUGGER_REGISTER_XMM8            =    (SOFT_DEBUGGER_REGISTER_FP_BASE + 0x1A)
    SOFT_DEBUGGER_REGISTER_XMM9            =    (SOFT_DEBUGGER_REGISTER_FP_BASE + 0x1B)
    SOFT_DEBUGGER_REGISTER_XMM10           =    (SOFT_DEBUGGER_REGISTER_FP_BASE + 0x1C)
    SOFT_DEBUGGER_REGISTER_XMM11           =    (SOFT_DEBUGGER_REGISTER_FP_BASE + 0x1D)
    SOFT_DEBUGGER_REGISTER_XMM12           =    (SOFT_DEBUGGER_REGISTER_FP_BASE + 0x1E)
    SOFT_DEBUGGER_REGISTER_XMM13           =    (SOFT_DEBUGGER_REGISTER_FP_BASE + 0x1F)
    SOFT_DEBUGGER_REGISTER_XMM14           =    (SOFT_DEBUGGER_REGISTER_FP_BASE + 0x20)
    SOFT_DEBUGGER_REGISTER_XMM15           =    (SOFT_DEBUGGER_REGISTER_FP_BASE + 0x21)
    SOFT_DEBUGGER_REGISTER_MM0             =    (SOFT_DEBUGGER_REGISTER_FP_BASE + 0x22)
    SOFT_DEBUGGER_REGISTER_MM1             =    (SOFT_DEBUGGER_REGISTER_FP_BASE + 0x23)
    SOFT_DEBUGGER_REGISTER_MM2             =    (SOFT_DEBUGGER_REGISTER_FP_BASE + 0x24)
    SOFT_DEBUGGER_REGISTER_MM3             =    (SOFT_DEBUGGER_REGISTER_FP_BASE + 0x25)
    SOFT_DEBUGGER_REGISTER_MM4             =    (SOFT_DEBUGGER_REGISTER_FP_BASE + 0x26)
    SOFT_DEBUGGER_REGISTER_MM5             =    (SOFT_DEBUGGER_REGISTER_FP_BASE + 0x27)
    SOFT_DEBUGGER_REGISTER_MM6             =    (SOFT_DEBUGGER_REGISTER_FP_BASE + 0x28)
    SOFT_DEBUGGER_REGISTER_MM7             =    (SOFT_DEBUGGER_REGISTER_FP_BASE + 0x29)

###
# Errors
#
class UdkError(Exception):
    """Base class for exceptions in this module."""
    pass

class TimeoutError(UdkError):
    """Raised when a timeout occurs waiting for a read on the serial.

    Attributes:
        None.
    """

    pass

class InvalidSymbolError(UdkError):
    """Raised when the target communicates a symbol that is not valid.

    Attributes:
        symbol -- symbol that was received
    """

    def __init__(self, symbol):
        self.symbol = symbol

class CrcError(UdkError):
    """Raised when the target communicates a packet with an invalid CRC.

    Attributes:
        crc_received -- crc that was received.
        crc_calculated -- crc that was calculated.
    """

    def __init__(self, crc_received):
        self.crc_received = crc_received

class AbortError(UdkError):
    """Raised when the target aborts a UDK command.

    """

class Packet(object):
    def __init__(self, starting_symbol, command, seqno, data = b''):
        self.starting_symbol = starting_symbol
        self.command = command
        self.seqno = seqno
        self.data = data

    @staticmethod
    def calculate_crc16(data, crc = 0):
        for byte in data:
            crc ^= byte
            for bitindex in range(0, 8):
                if crc & 0x8000:
                    crc = ((crc << 1) & 0xffff) ^ 0x1021
                else:
                    crc = (crc << 1) & 0xffff
        return crc

    @classmethod
    def from_bytes(cls, data):
        starting_symbol, command, length, seqno, crc = struct.unpack("<BBBBH", data[0:6])
        if crc != cls.calculate_crc16(data[0:4] + b'\x00\x00' + data[6:]):
            raise CrcError(crc)

        data = data[6:]
        if length != len(data) + 6:
            raise UdkError("lengths do not match: {} and {}".format(length, len(data)))

        return cls(starting_symbol, command, seqno, data)

    def to_bytes(self):
        length = 6 + len(self.data)
        data = struct.pack("<BBBBH", self.starting_symbol, self.command, length, self.seqno, 0x0000) + self.data
        crc = self.calculate_crc16(data)
        data = data[0:4] + struct.pack("<H", crc) + data[6:]
        return data

    def dump(self, issend):
        buf = None
        if issend:
            buf = "Sent data [ "
        else:
            buf = "Received data [ "

        buf += ' '.join('{:02x}'.format(x) for x in self.to_bytes())
        buf += " ]"
        logger.debug(buf)

    def is_request(self):
        return (self._command & 0x80) == 0

    def is_response(self):
        return (self._command & 0x80) == 0x80

    @property
    def command(self):
        return self._command

    @command.setter
    def command(self, command):
        self._command = command

    @property
    def seqno(self):
        return self._seqno

    @seqno.setter
    def seqno(self, seqno):
        self._seqno = seqno

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, data):
        self._data = data


class UdkTargetStub(object):
    def __init__(self, target):
        self.target = target
        self.handlers = {}
        self.add_handler(DebugCommands.DEBUG_COMMAND_INIT_BREAK, self.handle_init_break)
        self.add_handler(DebugCommands.DEBUG_COMMAND_MEMORY_READY, self.handle_memory_ready)

        ## Break point handling
        self.add_handler(DebugCommands.DEBUG_COMMAND_BREAK_POINT, self.handle_break_point)

        self.break_cause_handlers = {}
#        self.add_break_cause_handler(BreakCauses.DEBUG_DATA_BREAK_CAUSE_UNKNOWN, self.handle_break_cause_unknown)
        self.add_break_cause_handler(BreakCauses.DEBUG_DATA_BREAK_CAUSE_HW_BREAKPOINT, self.handle_break_cause_hw_breakpoint)
#        self.add_break_cause_handler(BreakCauses.DEBUG_DATA_BREAK_CAUSE_STEPPING, self.handle_break_cause_stepping)
        self.add_break_cause_handler(BreakCauses.DEBUG_DATA_BREAK_CAUSE_SW_BREAKPOINT, self.handle_break_cause_sw_breakpoint)
#        self.add_break_cause_handler(BreakCauses.DEBUG_DATA_BREAK_CAUSE_USER_HALT, self.handle_break_cause_user_halt)
        self.add_break_cause_handler(BreakCauses.DEBUG_DATA_BREAK_CAUSE_IMAGE_LOAD, self.handle_break_cause_image_load)
#        self.add_break_cause_handler(BreakCauses.DEBUG_DATA_BREAK_CAUSE_IMAGE_UNLOAD, self.handle_break_cause_image_unload)
#        self.add_break_cause_handler(BreakCauses.DEBUG_DATA_BREAK_SYSTEM_RESET, self.handle_break_cause_system_reset)
        self.add_break_cause_handler(BreakCauses.DEBUG_DATA_BREAK_CAUSE_EXCEPTION, self.handle_break_cause_exception)
#        self.add_break_cause_handler(BreakCauses.DEBUG_DATA_BREAK_CAUSE_MEMORY_READY, self.handle_break_cause_memory_ready)

    def add_handler(self, command, handler):
        self.handlers[command] = handler

    def add_break_cause_handler(self, command, handler):
        self.break_cause_handlers[command] = handler

    def handle_init_break(self, packet):
        self.get_revision()
        self.put_debugger_setting(DEBUG_AGENT_SETTING_PRINT_ERROR_LEVEL, 0x1f)  # Trace setting
        self.put_debugger_setting(DEBUG_AGENT_SETTING_SMM_ENTRY_BREAK, 0)  # Trace setting
        self.put_debugger_setting(DEBUG_AGENT_SETTING_BOOT_SCRIPT_ENTRY_BREAK, 0)  # Trace setting
        self.get_viewpoint()
        ready = self.memory_ready()
        if not ready:
            self.go()

    def handle_memory_ready_impl(self):
        raise NotImplementedError("implement UdkHostStub and override handle_memory_ready")

    def handle_memory_ready(self, packet):
        logger.debug("Target memory is ready!")
        self.handle_memory_ready_impl()
        self.go()

    def handle_break_point_impl(self):
        raise NotImplementedError("implement UdkHostStub and override handle_memory_ready")

    def handle_break_point(self, packet):
        logger.debug("Target meet a breakpoint!")
        self.handle_break_point_impl()

    def handle_break_cause(self):
        self.get_viewpoint()
        cause, stop_address = self.break_cause()
        return self.break_cause_handlers[cause](stop_address)

    def handle_break_cause_image_load_impl(self, pdb_name, image_context):
        raise NotImplementedError("implement UdkHostStub and override handle_break_cause_image_load")

    def handle_break_cause_image_load(self, stop_address):
        pdb_name_addr = self.read_register(Register.SOFT_DEBUGGER_REGISTER_DR1)  # ImageContext->PdbPointer *
        image_context_addr = self.read_register(Register.SOFT_DEBUGGER_REGISTER_DR2)  # ImageContext *
        return self.handle_break_cause_image_load_impl(pdb_name_addr, image_context_addr)

    def handle_break_cause_hw_breakpoint_impl(self, stop_address):
        raise NotImplementedError("implement UdkHostStub and override handle_break_cause_sw_breakpoint")

    def handle_break_cause_hw_breakpoint(self, stop_address):
        return self.handle_break_cause_hw_breakpoint_impl(stop_address)

    def handle_break_cause_sw_breakpoint_impl(self, stop_address):
        raise NotImplementedError("implement UdkHostStub and override handle_break_cause_sw_breakpoint")

    def handle_break_cause_sw_breakpoint(self, stop_address):
        return self.handle_break_cause_sw_breakpoint_impl(stop_address)

    def handle_break_cause_exception_impl(self, stop_address, vector, data):
        raise NotImplementedError("implement UdkHostStub and override handle_break_cause_image_load")

    def handle_break_cause_exception(self, stop_address):
        vector, data, = self.get_exception()
        return self.handle_break_cause_exception_impl(stop_address, vector, data)

    #### Commands which send no response data
    def halt(self):
        logger.debug("Halt() called")
        self.target.send_command_and_wait_for_ack_ok(DebugCommands.DEBUG_COMMAND_HALT, 0)
        logger.debug("Halt() returning")

    def reset(self):
        logger.debug("Halt() called")
        self.target.send_command_and_wait_for_ack_ok(DebugCommands.DEBUG_COMMAND_RESET, 0)
        logger.debug("Halt() returning")

    def go(self):
        logger.debug("IGo() called")
        self.target.send_command_and_wait_for_ack_ok(DebugCommands.DEBUG_COMMAND_GO, 0)
        logger.debug("IGo() returning")

    def single_stepping(self):
        logger.debug("SingleStepping() called")
        self.target.send_command_and_wait_for_ack_ok(DebugCommands.DEBUG_COMMAND_SINGLE_STEPPING, 0)
        logger.debug("SingleStepping() returning")

    #### Commands which send response data
    def break_cause(self):
        logger.debug("BreakCause() called")
        response = self.target.send_command_and_wait_for_ack_ok(DebugCommands.DEBUG_COMMAND_BREAK_CAUSE, 0)
        cause, stop_address = struct.unpack("<BQ", response.data)
        self.target.send_ack_packet(DebugCommands.DEBUG_COMMAND_OK, response.seqno)
        logger.debug("BreakCause() returning : Cause = {} StopAddress = 0x{:0>16x}".format(cause, stop_address))
        return (cause, stop_address)

    def get_revision(self):
        logger.debug("QueryRevision() called")
        response = self.target.send_command_and_wait_for_ack_ok(DebugCommands.DEBUG_COMMAND_GET_REVISION, 0)
        revision, capabilities = struct.unpack("<II", response.data)
        self.target.send_ack_packet(DebugCommands.DEBUG_COMMAND_OK, response.seqno)
        logger.debug("QueryRevision() returning : Revision = {} Capability = {}".format(revision, capabilities))

    def get_viewpoint(self):
        logger.debug("IGetViewpoint() called")
        response = self.target.send_command_and_wait_for_ack_ok(DebugCommands.DEBUG_COMMAND_GET_VIEWPOINT, 0)
        target_viewpoint, = struct.unpack("<I", response.data)
        self.target.send_ack_packet(DebugCommands.DEBUG_COMMAND_OK, response.seqno)
        logger.debug("IGetViewpoint() returning : TargetViewpoint = {}".format(target_viewpoint))
        return target_viewpoint

    def get_exception(self):
        logger.debug("GetException() called")
        response = self.target.send_command_and_wait_for_ack_ok(DebugCommands.DEBUG_COMMAND_GET_EXCEPTION, 0)
        vector, data, = struct.unpack("<BI", response.data)
        self.target.send_ack_packet(DebugCommands.DEBUG_COMMAND_OK, response.seqno)
        logger.debug("GetException() returning : Exception = {} Data = {!s}".format(vector, data))
        return (vector, data)

    def memory_ready(self):
        logger.debug("MemoryReady() called")
        response = self.target.send_command_and_wait_for_ack_ok(DebugCommands.DEBUG_COMMAND_MEMORY_READY, 0)
        ready, = struct.unpack("<B", response.data)
        self.target.send_ack_packet(DebugCommands.DEBUG_COMMAND_OK, response.seqno)
        logger.debug("MemoryReady() returning : Ready = {}".format(ready))
        return ready

    def cpuid(self, eax, ecx):
        request = struct.pack("<II", eax, ecx)
        response = self.target.send_command_and_wait_for_ack_ok(DebugCommands.DEBUG_COMMAND_CPUID, 0, request)
        (eax, ebx, ecx, edx) = struct.unpack("<IIII", response.data)
        return (eax, ebx, ecx, edx)

    def put_debugger_setting(self, key, value):
        logger.debug("PutDebuggerSetting() called: Key = {} Value = {}".format(key, value))
        data = struct.pack("<BB", key, value)
        self.target.send_command_and_wait_for_ack_ok(DebugCommands.DEBUG_COMMAND_SET_DEBUG_SETTING, 0, data)

    def read_memory(self, address, width, count):
        request = struct.pack('<QBH', address, width, count)
        response = self.target.send_command_and_wait_for_ack_ok(DebugCommands.DEBUG_COMMAND_READ_MEMORY, 0, request)
        self.target.send_ack_packet(DebugCommands.DEBUG_COMMAND_OK, response.seqno)
        return response.data

    def write_memory(self, address, width, count, data):
        request = struct.pack("<QBH", address, width, count)
        response = self.target.send_command_and_wait_for_ack_ok(DebugCommands.DEBUG_COMMAND_WRITE_MEMORY, 0, request + data)
        return response.data

    def register_size(self, register):
        if register < SOFT_DEBUGGER_REGISTER_FP_BASE:
            return 8
        elif register < Register.SOFT_DEBUGGER_REGISTER_ST0:
            if register == Register.SOFT_DEBUGGER_REGISTER_FP_FCW:
                return 2
            elif register == Register.SOFT_DEBUGGER_REGISTER_FP_FSW:
                return 2
            elif register == Register.SOFT_DEBUGGER_REGISTER_FP_FTW:
                return 2
            elif register == Register.SOFT_DEBUGGER_REGISTER_FP_OPCODE:
                return 2
            elif register == Register.SOFT_DEBUGGER_REGISTER_FP_EIP:
                return 4
            elif register == Register.SOFT_DEBUGGER_REGISTER_FP_CS:
                return 2
            elif register == Register.SOFT_DEBUGGER_REGISTER_FP_DATAOFFSET:
                return 4
            elif register == Register.SOFT_DEBUGGER_REGISTER_FP_DS:
                return 2
            elif register == Register.SOFT_DEBUGGER_REGISTER_FP_MXCSR:
                return 4
            elif register == Register.SOFT_DEBUGGER_REGISTER_FP_MXCSR_MASK:
                return 4

        elif register <= Register.SOFT_DEBUGGER_REGISTER_ST7:
            return 10
        elif register <= Register.SOFT_DEBUGGER_REGISTER_XMM15:
            return 16
        else:
            return 8

    def read_register(self, register):
        logger.debug("ReadRegister() called")
        request = struct.pack('<B', register.value)
        response = self.target.send_command_and_wait_for_ack_ok(DebugCommands.DEBUG_COMMAND_READ_REGISTER, 0, request)
        self.target.send_ack_packet(DebugCommands.DEBUG_COMMAND_OK, response.seqno)
        size = self.register_size(register)

        value = None
        if size == 2:
            value, = struct.unpack("<H", response.data)
        elif size == 4:
            value, = struct.unpack("<I", response.data)
        elif size == 8:
            value, = struct.unpack("<Q", response.data)
        elif size == 10:
            raise NotImplementedError
        elif size == 16:
            value1, value2, = struct.unpack("<QQ", response.data)
            value = (value1 << 64) | value2

        logger.debug("ReadRegister() returning : Register {} Value = {}".format(register.name, value))
        return value

    def read_registers(self):
        response = self.target.send_command_and_wait_for_ack_ok(DebugCommands.DEBUG_COMMAND_READ_ALL_REGISTERS, 0)
        values = struct.unpack("<Q HHHHIHHIHBBII10s6s10s6s10s6s10s6s10s6s10s6s10s6s10s6s16s16s16s16s16s16s16s16s16s16s16s16s16s16s16s16s96s QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ", response.data)
        keys = [
            ####### DEBUG_DATA_X64_SYSTEM_CONTEXT
            'exception_data',
            ### Nested DEBUG_DATA_X64_FX_SAVE_STATE
            'fcw', 'fsw', 'ftw',
            'fop',
            'fpu_ip',
            'fcs',
            'reserved1',
            'fpu_dp',
            'fds',
            'reserved2_0', 'reserved2_1',
            'mxcsr',
            'mxcsr_mask',
            'st0mm0', 'reserved3',
            'st1mm1', 'reserved4',
            'st2mm2', 'reserved5',
            'st3mm3', 'reserved6',
            'st4mm4', 'reserved7',
            'st5mm5', 'reserved8',
            'st6mm6', 'reserved9',
            'st7mm7', 'reserved10',
            'xmm0', 'xmm1', 'xmm2', 'xmm3',
            'xmm4', 'xmm5', 'xmm6', 'xmm7',
            'xmm8', 'xmm9', 'xmm10', 'xmm11',
            'xmm12', 'xmm13', 'xmm14', 'xmm15',
            'reserved11',
            #####
            'dr0', 'dr1', 'dr2', 'dr3', 'dr6', 'dr7',
            'eflags',
            'ldtr', 'tr',
            'gdtr_0', 'gdtr_1',
            'idtr_0', 'idtr_1',
            'eip',
            'gs', 'fs', 'es', 'ds', 'cs', 'ss',
            'cr0', 'cr1', 'cr2', 'cr3', 'cr4',
            'rdi', 'rsi', 'rbp', 'rsp',
            'rdx', 'rcx', 'rbx', 'rax',
            'cr8',
            'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'
        ]
        self.target.send_ack_packet(DebugCommands.DEBUG_COMMAND_OK, response.seqno)
        registers = dict(zip(keys, values))
        return registers

    def write_register(self, register, value):
        logger.debug("WriteRegister() returning : Register {} Value = {}".format(register.name, value))
        size = self.register_size(register)
        request = struct.pack('<BB', register.value, size)
        data = None
        if size == 2:
            data = struct.pack("<H", value)
        elif size == 4:
            data = struct.pack("<I", value)
        elif size == 8:
            data = struct.pack("<Q", value)
        elif size == 10:
            raise NotImplementedError
        elif size == 16:
            data = struct.pack("<QQ", *value)

        response = self.target.send_command_and_wait_for_ack_ok(DebugCommands.DEBUG_COMMAND_READ_REGISTER, 0, request + data)
        self.target.send_ack_packet(DebugCommands.DEBUG_COMMAND_OK, response.seqno)
        logger.debug("WriteRegister() called")

    #### Utilities
    def read_null_terminated_string(self, addr, max_size = 1024):
        value = b''
        while b'\x00' not in value:
            value += self.read_memory(addr, 1, 16)
            if len(value) > max_size:
                value[max_size] = b'\x00'
                break
            addr = addr + 16

        null = value.find(b'\x00')
        value = value[:null].decode('utf-8')
        return value

class UdkTarget(object):
    def __init__(self, connection, clazz, *args, **kwargs):
        self.seqno = 1
        self.target_seqno = -1
        self.last_ack = 0
        self.msg = bytearray()

        if connection is None:
            raise UdkError()
        self.connection = connection

        self.stub = clazz(self, *args, **kwargs)
        if not isinstance(self.stub, UdkTargetStub):
            raise UdkError()

    def command_communication(self):
        packet = self.receive_packet(wait = False)
        if packet is None:
            return

        if not packet.is_request():
            return

        logger.debug("Request {} sequence {}".format(packet.command, packet.seqno))
        if packet.command == DebugCommands.DEBUG_COMMAND_INIT_BREAK:
            self.seqno = 1
            self.target_seqno = 0
        elif packet.seqno == self.target_seqno:
            logger.warning("TARGET: received one old command [{}] against command [{}]".format(packet.command, packet.seqno))
            self.target.send_ack_packet(self.last_ack, packet.seqno)
            return
        elif packet.seqno == (self.target_seqno + 1) % 256:
            self.target_seqno = (self.target_seqno + 1) % 256
        else:
            logger.warning("Receive one invalid command [{}] against command[{}]".format(packet.seqno, self.target_seqno))
            return

        if packet.command in self.stub.handlers:
            self.send_ack_packet(DebugCommands.DEBUG_COMMAND_OK, packet.seqno)
            self.stub.handlers[packet.command](packet)

    def receive_packet(self, timeout = PACKET_READ_TIMEOUT, wait = True):
        incompatibility_flag = False
        running = True

        timeout_for_start_symbol = timeout
        if not wait:
            timeout_for_start_symbol = 0

        while running:
            running = wait

            self.connection.timeout = timeout_for_start_symbol
            data = self.connection.read(1)
            self.connection.timeout = timeout
            if not data:
                continue

            starting_symbol = data[0]
            if not starting_symbol & 0x80:
                self.msg.extend(data)
                continue

            if self.msg:
                logger.debug(self.msg.decode('utf-8'))
                self.msg = bytearray()

            starting_symbol = data[0]
            if starting_symbol != DEBUG_STARTING_SYMBOL_NORMAL and \
               starting_symbol != DEBUG_STARTING_SYMBOL_COMPRESS:
                logger.error("Invalid starting symbol received")
                continue

            data = data + self.connection.read(2)
            length = data[2]
            if length < 6:  # sizeof(DEBUG_PACKET_HEADER)
                if incompatibility_flag:
                   incompatibility_flag = True
                # Skip the bad small packet
                continue

            data = data + self.connection.read(length - 3)
            packet = Packet.from_bytes(data)

            ### Ergh, these can come anywhere in the flow - output them and carry on
            if packet.command == DebugCommands.DEBUG_COMMAND_PRINT_MESSAGE:
                logger.debug("target: {}".format(packet.data.decode('utf-8').strip()))
                continue

            packet.dump(False)
            return packet

    def send_ack_packet(self, ack_command, seqno):
        if ack_command != DebugCommands.DEBUG_COMMAND_OK:
            logger.error("Send ACK({})".format(ack_command))

        logger.debug("SendAckPacket: SequenceNo = {}".format(seqno))
        packet = Packet(DEBUG_STARTING_SYMBOL_NORMAL, ack_command, seqno)
        packet.dump(True)
        self.connection.write(packet.to_bytes())
        self.last_ack = ack_command

    def send_command_and_wait_for_ack_ok(self, command, timeout, data = b''):
        retries = 3
        while retries > 0:
            request = Packet(DEBUG_STARTING_SYMBOL_NORMAL, command.value, self.seqno, data)
            request.dump(True)
            self.connection.write(request.to_bytes())

            packet = self.receive_packet()
            if packet is None:
                if command == DebugCommands.DEBUG_COMMAND_INIT_BREAK:
                    retries = retries - 1
                else:
                    logger.warning("TARGET: Timeout waiting for ACK packet.")
                continue

            if (packet.command == DebugCommands.DEBUG_COMMAND_OK or \
                packet.command == DebugCommands.DEBUG_COMMAND_HALT_DEFERRED or \
                packet.command == DebugCommands.DEBUG_COMMAND_HALT_PROCESSED) and \
               packet.seqno == self.seqno:
                # Received Ack OK
                self.seqno = (self.seqno + 1) % 256
                return packet

            elif packet.command == DebugCommands.DEBUG_COMMAND_ABORT and packet.seqno == self.seqno:
                # Received Abort - due to error
                logger.error("TARGET: Abort.")
                self.seqno = (self.seqno + 1) % 256
                raise AbortError()

            elif packet.command == DebugCommands.DEBUG_COMMAND_INIT_BREAK:
                logger.error("TARGET: Rebooted.")
                raise AbortError()

            elif packet.command == DebugCommands.DEBUG_COMMAND_IN_PROGRESS and packet.seqno == self.seqno:
                self.seqno = (self.seqno + 1) % 256
                while True:
                    continue_packet = Packet(DEBUG_STARTING_SYMBOL_NORMAL, DebugCommands.DEBUG_COMMAND_CONTINUE, self.seqno)
                    continue_packet.dump(True)
                    self.connection.write(continue_packet.to_bytes())

                    additional = self.receive_packet()
                    if additional.command == DebugCommands.DEBUG_COMMAND_IN_PROGRESS and additional.seqno == self.seqno:
                        packet.data = packet.data + additional.data
                        self.seqno = (self.seqno + 1) % 256
                        continue
                    elif additional.command == DebugCommands.DEBUG_COMMAND_OK and additional.seqno == self.seqno:
                        packet.data = packet.data + additional.data
                        packet.seqno = additional.seqno
                        self.seqno = (self.seqno + 1) % 256
                        break
                    else:
                        raise UdkError("unknown packet type {} or unexpected sequence number {}".format(additional.command, additional.seqno))
                return packet


        return None

