#!/usr/bin/env python
import logging
import collections
import struct
import binascii
import xml.etree.ElementTree

logger = logging.getLogger('gdbserver')

#### This should be generated from the gdb signals.def
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

#### This should be generated from the packaged gdb xmls eventually
# can be viewed in a running gdb with maint remote-registers
architectures = {
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
    def get_architecture(self):
        raise NotImplementedError("implement GdbHostStub and override get_architecture")

    def get_break_cause(self):
        raise NotImplementedError("implement GdbHostStub and override get_break_cause")

    def get_features_xml(self, annex, offset, length):
        logger.info(annex)
        if annex == b'target.xml':
            target = xml.etree.ElementTree.Element('target', version='1.0')
            architecture = xml.etree.ElementTree.SubElement(target, 'architecture')
            architecture.text = self.get_architecture()
            return xml.etree.ElementTree.tostring(target, encoding='utf-8', method='xml')

        raise NotImplementedError('annex not defined')

    def read_registers(self):
        raise NotImplementedError('implement GdbHostStub and override read_registers')

    def read_memory(self, address, size):
        raise NotImplementedError("implement GdbHostStub and override read_memory")

    def send_break(self):
        raise NotImplementedError("implement GdbHostStub and override send_break")

    def continue_execution(self, address = None):
        raise NotImplementedError("implement GdbHostStub and override continue_execution")


class GdbRemoteSerialProtocol(object):
    def __init__(self, connection, stub):
        super(GdbRemoteSerialProtocol, self).__init__()
        self.connection = connection

        self.stub = stub
        self.backlog = 1
        self.initialized = False

        self.features = {
            b'multiprocess': False,
            b'xmlRegisters': False,
            b'qXfer:libraries:read': False,
            b'qRelocInsn': False
        }

        self.packet_handlers = collections.defaultdict(int)
        self.general_query_xfer_handlers = collections.defaultdict(dict)

        #### Standard Packet Handlers
        self.add_packet_handler(b'\x03', self.brk)
        self.add_packet_handler(b'c', self.continue_execution)
        self.add_packet_handler(b'g', self.read_registers)
        self.add_packet_handler(b'm', self.read_memory)
        self.add_packet_handler(b'p', self.read_register)
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
        self.add_general_query_handler(b'Xfer', self.general_query_xfer)

        #### No ACK mode handler
        self.add_feature(b'QStartNoAckMode')
        self.add_general_set_handler(b'StartNoAckMode', self.general_set_start_no_ack_mode)
        self.no_acknowledgement_mode = False

        #### qXfer:features:read feature
        self.add_feature(b'qXfer:features:read')
        self.add_general_query_xfer_handler(b'features', b'read', self.general_query_xfer_features_read)

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

    def command_communication(self):
        message = self.receive_packet()
        cmd, subcmd = message[0:1], message[1:]

        ### Ignore an initial Ack ('+') if one is sent (gdb)
        initialized = self.initialized
        self.initialized = True
        if cmd == b'+' and initialized == False:
            return

#        if cmd == b'\x03':
#            logger.info('break received'.format(message))

        if cmd not in self.packet_handlers:
            logger.info('{} command not handled'.format(message))
            self.send_packet(b'')
            return

        self.packet_handlers[cmd](subcmd)

    def general_query(self, query):
        cmd = query
        args = b''
        if b':' in cmd:
            cmd, args = query.split(b':', 1)

        if cmd not in self.general_query_handlers:
            logger.error('This subcommand %r is not implemented in q' % cmd)
            self.send_packet(b'')
            return

        self.general_query_handlers[cmd](args)

    def general_set(self, query):
        cmd = query
        args = b''
        if b':' in cmd:
            cmd, args = query.split(b':', 1)

        if cmd not in self.general_set_handlers:
            logger.error('This subcommand %r is not implemented in q' % cmd)
            self.send_packet(b'')
            return

        self.general_set_handlers[cmd](args)

    def verbose(self, query):
        cmd = query
        args = b''
        if b';' in cmd:
            cmd, args = query.split(b';', 1)

        if cmd not in self.verbose_handlers:
            logger.error('This subcommand %r is not implemented in q' % cmd)
            self.send_packet(b'')
            return

        self.verbose_handlers[cmd](args)

    def general_query_supported(self, args):
        features = []
        for feature, value in self.features.items():
            if value == True:
                features.append(b'%s+' % feature)
            elif value == False:
                features.append(b'%s-' % feature)
            else:
                features.append(b'%s=%x' % (feature, value))

        self.send_packet(b';'.join(features))

    def general_query_xfer(self, args):
        obj, operation, remaining_args = args.split(b':', 2)
        try:
            function = self.general_query_xfer_handlers[obj][operation]
            function(remaining_args)
        except KeyError:
            logger.error('requested xfer operation not supported: {}:{}'.format(obj, operation))
            self.send_packet(b'')

    #### XML Object transfer support
    def general_query_xfer_features_read(self, args):
        annex, offsetlength = args.split(b':', 2)
        offset, length = offsetlength.split(b',', 2)
        xml = None
        try:
            xml = self.stub.get_features_xml(annex, offset, length)
        except NotImplementedError:
            self.send_packet(b'E00')
            return

        if xml is None:
            self.send_packet(b'')
        self.send_packet(b'l' + xml)

    def general_query_attached(self, args):
        self.send_packet(b'1')

    def general_query_current_thread(self, args):
        self.send_packet(b'QC1')

    def general_query_thread_info_first(self, args):
        self.send_packet(b'l')

    def general_query_thread_info_subsequent(self, args):
        self.send_packet(b'')

    #### Trace support
    ### Trace variables not currently used
    def general_query_trace_status(self, args):
        self.send_packet(b'T0;tnotrun:0')

    def general_query_trace_var_first(self, args):
        self.send_packet(b'')

    def general_query_trace_var_subsequent(self, args):
        self.send_packet(b'')

    def general_query_tracepoint_first(self, args):
        self.send_packet(b'')

    def general_query_tracepoint_subsequent(self, args):
        self.send_packet(b'')


    def general_set_start_no_ack_mode(self, args):
        self.no_acknowledgement_mode = True
        self.send_packet(b'OK')
        self.expect_ack() ## Soak up last ACK

    #### Standard GDB Commands
    ###
    def brk(self, args):
        (cause, nr) = self.stub.send_break()
        self.send_stop_reply_packet(cause, nr)

    def set_thread(self, args):
        self.send_packet(b'OK')

    def halt_reason(self, args):
        (cause, nr) = self.stub.get_break_cause()
        self.send_stop_reply_packet(cause, nr)

    def continue_execution(self, args):
        if not args:
            self.stub.continue_execution()

    def read_register(self, args):
        index = int(args, 16)
        if index is None:
            self.send_packet(b'E00')
            return

        arch = self.stub.get_architecture()
        archdef = architectures[arch]

        register = archdef['registers'][index]
        register_name = register['name']
        register_size = register['size']

        value = self.stub.read_register(register_name)

        s = b''
        if register_size == 4:
            s = binascii.hexlify(struct.pack('<I', value))
        elif register_size == 8:
            s = binascii.hexlify(struct.pack('<Q', value))
        elif register_size == 10:
            s = binascii.hexlify(value)

        self.send_packet(s)

    def read_registers(self, args):
        arch = self.stub.get_architecture()
        archdef = architectures[arch]

        defaults = {}
        for register in archdef['registers']:
            register_name = register['name']
            defaults[register_name] = 0

        values = self.stub.read_registers(defaults)

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

        self.send_packet(s)

    def read_memory(self, args):
        addr, size = args.split(b',')
        addr = int(addr, 16)
        size = int(size, 16)

        data = self.stub.read_memory(addr, size)
        self.send_packet(binascii.hexlify(data))

    def handle_k(self, cmd, subcmd):
        pass

    def handle_s(self, cmd, subcmd):
        self.log.info('Received a "single step" command')
#        StepInto()
        self.send('T%.2x' % GDB_SIGNAL_TRAP)


    ####
    #### Packet handling routines below
    ####
    def receive_packet(self):
        c = self.connection.read(1)
        # Ack packet
        if c != b'+' and c != b'$' and c != b'-' and c != b'\x03':
            raise RemoteException('Expected "$" received: "%s"' % str(c))

        message = b''
        if c == b'+' or c == b'-' or c == b'\x03':
            message += c

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

            logger.debug('[GDB][RX] $%s#%02x' % (message.decode('utf-8'), checksum))
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
            self.expect_ack()

    def send(self, packet):
        logger.debug('[GDB][TX] %s' % packet.decode('utf-8'))
        self.connection.write(packet)
        self.connection.flush()

    def send_ack(self):
        self.send(b'+')

    def expect_ack(self):
        message = self.receive_packet()
        if message != b'+':
            raise RemoteException('Wrong ack: "%s"' % str(message))

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
    def step(self, addr=None):
        pkt = 's'
        if addr != None:
            pkt += '%x' % (addr)
        self.__send_msg(pkt)

    def __z_packet(self, pkt):
        self.__send_msg(pkt)
        reply = self.__recv_msg()
        if reply == b'':
            info('Z packets are not supported by target.')
        else:
            if (reply != 'OK'):
                raise RemoteException('Unexpected reply: %s' % str(reply))

    def break_insert(self, addr, _len=0, _type=0):
        self.__z_packet('Z%d,%x,%x' % (_type, addr, _len))

    def break_remove(self, addr, _len=0, _type=0):
        self.__z_packet('z%d,%x,%x' % (_type, addr, _len))

    def expect_signal(self):
        msg = self.__recv_msg()
        assert len(msg) == 3 and msg[0] == 'S', 'Expected "S", received "%c" % msg[0]'

        return int(msg[1:], 16)
