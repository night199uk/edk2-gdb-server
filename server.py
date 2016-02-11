#!/usr/bin/env python

"""
"""

import udkserver
import gdbserver
import collections
import logging
import select
import serial
import socket
import struct

#logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger()

#### This should be generated from the packaged gdb xmls eventually
# can be viewed in a running gdb with maint remote-registers
registers = {
    'rax': udkserver.Register.SOFT_DEBUGGER_REGISTER_AX,
    'rbx': udkserver.Register.SOFT_DEBUGGER_REGISTER_BX,
    'rcx': udkserver.Register.SOFT_DEBUGGER_REGISTER_CX,
    'rdx': udkserver.Register.SOFT_DEBUGGER_REGISTER_DX,
    'rsi': udkserver.Register.SOFT_DEBUGGER_REGISTER_SI,
    'rdi': udkserver.Register.SOFT_DEBUGGER_REGISTER_DI,
    'rbp': udkserver.Register.SOFT_DEBUGGER_REGISTER_BP,
    'rsp': udkserver.Register.SOFT_DEBUGGER_REGISTER_SP,

    'r8':  udkserver.Register.SOFT_DEBUGGER_REGISTER_R8,
    'r9':  udkserver.Register.SOFT_DEBUGGER_REGISTER_R9,
    'r10': udkserver.Register.SOFT_DEBUGGER_REGISTER_R10,
    'r11': udkserver.Register.SOFT_DEBUGGER_REGISTER_R11,
    'r12': udkserver.Register.SOFT_DEBUGGER_REGISTER_R12,
    'r13': udkserver.Register.SOFT_DEBUGGER_REGISTER_R13,
    'r14': udkserver.Register.SOFT_DEBUGGER_REGISTER_R14,
    'r15': udkserver.Register.SOFT_DEBUGGER_REGISTER_R15,

    'rip': udkserver.Register.SOFT_DEBUGGER_REGISTER_EIP,
    'eflags': udkserver.Register.SOFT_DEBUGGER_REGISTER_EFLAGS,

    'cs': udkserver.Register.SOFT_DEBUGGER_REGISTER_CS,
    'ss': udkserver.Register.SOFT_DEBUGGER_REGISTER_SS,
    'ds': udkserver.Register.SOFT_DEBUGGER_REGISTER_DS,
    'es': udkserver.Register.SOFT_DEBUGGER_REGISTER_ES,
    'fs': udkserver.Register.SOFT_DEBUGGER_REGISTER_FS,
    'gs': udkserver.Register.SOFT_DEBUGGER_REGISTER_GS,

    'st0': udkserver.Register.SOFT_DEBUGGER_REGISTER_ST0,
    'st1': udkserver.Register.SOFT_DEBUGGER_REGISTER_ST1,
    'st2': udkserver.Register.SOFT_DEBUGGER_REGISTER_ST2,
    'st3': udkserver.Register.SOFT_DEBUGGER_REGISTER_ST3,
    'st4': udkserver.Register.SOFT_DEBUGGER_REGISTER_ST4,
    'st5': udkserver.Register.SOFT_DEBUGGER_REGISTER_ST5,
    'st6': udkserver.Register.SOFT_DEBUGGER_REGISTER_ST6,
    'st7': udkserver.Register.SOFT_DEBUGGER_REGISTER_ST7,

    'fctrl': udkserver.Register.SOFT_DEBUGGER_REGISTER_FP_FCW,
    'fstat': udkserver.Register.SOFT_DEBUGGER_REGISTER_FP_FSW,
    'ftag': udkserver.Register.SOFT_DEBUGGER_REGISTER_FP_FTW,
    'fiseg': udkserver.Register.SOFT_DEBUGGER_REGISTER_FP_CS,
    'fioff': udkserver.Register.SOFT_DEBUGGER_REGISTER_FP_EIP,
    'foseg': udkserver.Register.SOFT_DEBUGGER_REGISTER_FP_DS,
    'fooff': udkserver.Register.SOFT_DEBUGGER_REGISTER_FP_DATAOFFSET,
    'fop': udkserver.Register.SOFT_DEBUGGER_REGISTER_FP_OPCODE,

    'xmm0': udkserver.Register.SOFT_DEBUGGER_REGISTER_XMM0,
    'xmm1': udkserver.Register.SOFT_DEBUGGER_REGISTER_XMM1,
    'xmm2': udkserver.Register.SOFT_DEBUGGER_REGISTER_XMM2,
    'xmm3': udkserver.Register.SOFT_DEBUGGER_REGISTER_XMM3,
    'xmm4': udkserver.Register.SOFT_DEBUGGER_REGISTER_XMM4,
    'xmm5': udkserver.Register.SOFT_DEBUGGER_REGISTER_XMM5,
    'xmm6': udkserver.Register.SOFT_DEBUGGER_REGISTER_XMM6,
    'xmm7': udkserver.Register.SOFT_DEBUGGER_REGISTER_XMM7,
    'xmm8': udkserver.Register.SOFT_DEBUGGER_REGISTER_XMM8,
    'xmm9': udkserver.Register.SOFT_DEBUGGER_REGISTER_XMM9,
    'xmm10': udkserver.Register.SOFT_DEBUGGER_REGISTER_XMM10,
    'xmm11': udkserver.Register.SOFT_DEBUGGER_REGISTER_XMM11,
    'xmm12': udkserver.Register.SOFT_DEBUGGER_REGISTER_XMM12,
    'xmm13': udkserver.Register.SOFT_DEBUGGER_REGISTER_XMM13,
    'xmm14': udkserver.Register.SOFT_DEBUGGER_REGISTER_XMM14,
    'xmm15': udkserver.Register.SOFT_DEBUGGER_REGISTER_XMM15,
}

class UdkGdbServer(udkserver.UdkHostStub, gdbserver.GdbHostStub):
    def __init__(self, serial_name = '/dev/cu.usbmodem1a141', host = '0.0.0.0', port = 1234):
        self._serial_name = serial_name
        self._serial = None

        self._host = host
        self._port = port
        self._socket = None

        self._poll = select.poll()
        self._poll_handlers = {}

        self.udk = None
        self.udk_extension_handlers = collections.defaultdict(dict)

        self.gdb = None

        ### Below here are instance parameters
        self.fmodules = []

    def add_udk_extension_handlers(self, command, handler):
        self.udk_extension_handlers[command] = handler

    def add_poll_fd(self, fd, handler):
        self._poll.register(fd, select.POLLIN)
        self._poll_handlers[fd] = handler

    def remove_poll_fd(self, fd):
        self._poll.unregister(fd)
        del self._poll_handlers[fd]

    def start_serial(self):
        ### Initialize the Serial port
        self._serial = serial.Serial(self._serial_name)
        self._serial.reset_input_buffer()
        self._serial.reset_output_buffer()
        self.udk = udkserver.Server(self, self._serial)

        self.add_poll_fd(self._serial.fileno(), self.serial_handler)

    def start_socket(self):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind((self._host, self._port))
        self._socket.listen(0)
        self.add_poll_fd(self._socket.fileno(), self.socket_handler)
        logger.info("Listening on {}:{} for connections".format(self._host, self._port))

    def socket_handler(self):
        self.connection, self.remote_addr = self._socket.accept()
        self.gdb = gdbserver.GdbRemoteSerialProtocol(self.connection.makefile('rwb', buffering = 0), self)

        #### UDK Extensions
        self.gdb.add_general_query_handler(b'UdkExtension', self.udk_extension)
        self.add_udk_extension_handlers(b'arch', self.udk_extension_arch)
        self.add_udk_extension_handlers(b'checkexpat', self.udk_extension_checkexpat)
        self.add_udk_extension_handlers(b'exception', self.udk_extension_exception)
        self.add_udk_extension_handlers(b'symbol', self.udk_extension_symbol)

        #### Loaded Modules Extension
        self.add_udk_extension_handlers(b'fmodules', self.udk_extension_fmodules)
        self.add_udk_extension_handlers(b'smodules', self.udk_extension_smodules)

        self.add_poll_fd(self.connection.fileno(), self.connection_handler)
        logger.info("Received a connection from {}".format(self.remote_addr))

    def connection_handler(self):
        self.gdb.command_communication()

    def serial_handler(self):
        self.udk.command_communication()

    ##### GDB Target Stub Side
    ### Called by GDB to request the target continue execution
    def continue_execution(self, address = None):
        self.udk.go()

    ### Called by GDB to request the target architecture
    def get_architecture(self):
        return 'i386:x86-64'

    ### Called by GDB to request the break cause from the target
    def get_break_cause(self):
        cause, stop_address = self.udk.break_cause()
        nrs = {}
        if cause == udkserver.BreakCauses.DEBUG_DATA_BREAK_CAUSE_IMAGE_LOAD:
            nrs[b'library'] = b'0'
        return (cause, nrs)

    ### Called by GDB to request memory from the target
    def read_memory(self, address, size):
        return self.udk.read_memory(address, 1, size)


    def read_register(self, register):
        udk_register = registers[register].udk
        value = self.udk.read_register(udk_register)
        return value

    ### Called by GDB to read the register state from the target
    def read_registers(self, defaults):
        registers = self.udk.read_registers()
        registers['rip'] = registers['eip']
        registers['fctrl'] = registers['fcw']
        registers['fstat'] = registers['fcw']
        registers['ftag'] = registers['ftw']
        registers['fiseg'] = registers['fcs']
        registers['fioff'] = registers['fpu_ip']
        registers['foseg'] = registers['fds']
        registers['fooff'] = registers['fpu_dp']
        registers['st0'] = registers['st0mm0']
        registers['st1'] = registers['st1mm1']
        registers['st2'] = registers['st2mm2']
        registers['st3'] = registers['st3mm3']
        registers['st4'] = registers['st4mm4']
        registers['st5'] = registers['st5mm5']
        registers['st6'] = registers['st6mm6']
        registers['st7'] = registers['st7mm7']
        return registers

    ### Called by GDB to halt the target from running
    def send_break(self):
        self.udk.halt()
#        viewpoint = self.udk.get_viewpoint()
        cause, stop_address = self.udk.break_cause()
        nrs = {}
        return (cause, nrs)

    #### GDB Protocol Extensions for UDK
    ###
    def udk_extension(self, args):
        cmd = args
        args = None
        if b':' in cmd:
            cmd, args = cmd.split(b':', 2)


        if cmd in self.udk_extension_handlers:
            self.udk_extension_handlers[cmd](args)
        else:
            self.gdb.send_packet(b'')

    def udk_extension_arch(self, args):
        self.gdb.send_packet(b'use64')

    def udk_extension_exception(self, args):
        self.gdb.send_packet(b'')

    def udk_extension_next_module(self):
        try:
            first = next(self.fmodules_iter)
            print(str(first))
            msg = '{0:x};{1:x};{2}'.format(first['image_addr'], first['image_size'], first['pdb_name'])
            self.gdb.send_packet(msg.encode('utf-8'))
        except StopIteration:
            self.gdb.send_packet(b'l')
            del self.fmodules_iter

    def udk_extension_fmodules(self, args):
        self.fmodules_iter = iter(self.fmodules)
        self.udk_extension_next_module()

    def udk_extension_smodules(self, args):
        if not self.fmodules_iter:
            self.gdb.send_packet(b'E99')

        self.udk_extension_next_module()

    def udk_extension_symbol(self, args):
        self.gdb.send_packet(b'E91')

    def udk_extension_checkexpat(self, args):
        if args == b'start':
            self.gdb.send_packet(b'OK')
        else:
            self.gdb.send_packet(b'E91')

    ##### UDK Host Side
    ### Called by UDK Server when memory is ready on the target
    def handle_memory_ready(self):
        if self._socket:
            return
        self.start_socket()

    ### Called by UDK Server when a SW breakpoint occurs on the target
    def handle_break_cause_sw_breakpoint(self, stop_address):
        cause, stop_address = self.udk.break_cause()
        self.gdb.send_stop_reply_packet(5)

    ### Called by UDK Server when an image load event occurs on the target
    def handle_break_cause_image_load(self, pdb_name_addr, image_context_addr):
        image_context = self.read_memory(image_context_addr, 16)
        image_addr, image_size = struct.unpack("<QQ", image_context)

        pdb_name = b''
        while b'\x00' not in pdb_name:
            pdb_name += self.read_memory(pdb_name_addr, 16)
            pdb_name_addr = pdb_name_addr + 16

        null = pdb_name.find(b'\x00')
        pdb_name = pdb_name[0:null].decode('utf-8')

        logger.info('module {0} loaded at address {1:x} with size {2:x}'.format(pdb_name, image_addr, image_size))
        self.fmodules.append({
                "pdb_name": pdb_name,
                "image_addr": image_addr,
                "image_size": image_size
            })

        if self.gdb:
            nrs = {b'library': b'0'}
            self.gdb.send_stop_reply_packet(5, nrs)

    def run(self):
        self.start_serial()

        while True:
            for (fd, event) in self._poll.poll():
                if event & (select.POLLHUP | select.POLLERR | select.POLLNVAL):
                    self.remove_poll_fd(fd)
                    self.gdb = None
                    del self.connection
                    continue

                elif not event & select.POLLIN:
                    logger.error("unknown poll event occurred {}".format(str(event)))
                    raise Exception

                if fd not in self._poll_handlers:
                    raise Exception("unknown fd raised poll event")

                self._poll_handlers[fd]()

if __name__ == "__main__":
    udk_gdb_server = UdkGdbServer()
    udk_gdb_server.run()
