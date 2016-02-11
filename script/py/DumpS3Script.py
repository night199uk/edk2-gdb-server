#++
#
#Copyright (c) 2012 - 2014 Intel Corporation. All rights reserved
#This software and associated documentation (if any) is furnished
#under a license and may only be used or copied in accordance
#with the terms of the license. Except as permitted by such
#license, no part of this software or documentation may be
#reproduced, stored in a retrieval system, or transmitted in any
#form or by any means without the express written consent of
#Intel Corporation.
#
#Module Name:
#
#  DumpS3Script.py
#
#Abstract:
#
#  Dump content of S3 boot script.
#
#--

from __future__ import print_function
import UdkExtension

#****************************************************************************
#  FUNCTION:    GetWidthString()
#
#  DESCRIPTION: This function returns the string of width.
#
#  PARAMETER:   argvector[1] - Width
#
#  RETURNS:     String
#
#*****************************************************************************
def GetWidthString(Width):
    if Width == 0x0:
        return "Width = 8bits "
    else:
        if Width == 0x1:
            return "Width = 16bits"
        else:
            if Width == 0x2:
                return "Width = 32bits"
            else:
                if Width == 0x3:
                    return "Width = 64bits"
                else:
                    return None

#****************************************************************************
#  FUNCTION:    PrintForWrite()
#
#  DESCRIPTION: This function print the content of buffer for write action
#               according to the width and the count.
#
#  PARAMETER:   argvector[0] - Pointer Address
#               argvector[1] - Width
#               argvector[2] - Count
#
#  RETURNS:     NULL
#
#*****************************************************************************
def PrintForWrite(Ptr, Width, Count):
    WidthString = GetWidthString(Width)
    if WidthString is None:
        print("ERROR: invalid width in this boot script entry")
        return()
    else:
        print(WidthString, end=' ')
    WidthInByte = 0x01 << (Width & 0x03);
    print("Data =", end=' ')
    while Count != 0x0:
        print("0x%x" % ReadUnalignedN(Ptr, WidthInByte), end=' ')
        Ptr = Ptr + WidthInByte
        if Count != 0x1:
            print("-", end=' ')
        Count -= 1
    print("")
    return()

#****************************************************************************
#  FUNCTION:    PrintForReadWritePoll()
#
#  DESCRIPTION: This function print the content of buffer for read&write action
#               according to the width.
#
#  PARAMETER:   argvector[0] - Pointer Address
#               argvector[1] - Width
#               argvector[2] - RW/Poll (RW = 0, Poll = 1)
#
#  RETURNS:     NULL
#
#*****************************************************************************
def PrintForReadWritePoll(Ptr, Width, Poll):
    WidthString = GetWidthString(Width)
    if WidthString is None:
        print("ERROR: invalid width in this boot script entry")
        return()
    else:
        print(WidthString, end=' ')
    WidthInByte = 0x01 << (Width & 0x03);
    if Poll == 0:
        print("Data = Data", end=' ')
        print("& 0x%x | 0x%x" % (ReadUnalignedN (Ptr + WidthInByte, WidthInByte), \
                                 ReadUnalignedN (Ptr, WidthInByte)))
    else:
        print("Expected Data = 0x%x DataMask = 0x%x" % (ReadUnalignedN (Ptr, WidthInByte),\
                                                 ReadUnalignedN (Ptr + WidthInByte, WidthInByte)))
    return()


#****************************************************************************
#  FUNCTION:    PrintString()
#
#  DESCRIPTION: This function print the content of buffer for information string.
#
#  PARAMETER:   argvector[0] - Pointer Address
#               argvector[1] - Length
#
#  RETURNS:     NULL
#
#*****************************************************************************
def PrintString(Addr, Len):
    name = list(map (chr, UdkExtension.ReadMemory(Addr, 1, Len - 1)))
    print(''.join(name))

#****************************************************************************
#  FUNCTION:    ReadUnalignedN()
#
#  DESCRIPTION: This function reads the integer value from a unaligned address.
#
#  PARAMETER:   argvector[0] - Pointer Address
#               argvector[1] - Length
#
#  RETURNS:     The integer value
#
#*****************************************************************************
def ReadUnalignedN(Addr, N):
    data = UdkExtension.ReadMemory(Addr, 1, N)
    value = 0
    for index in range(N):
        value = value + (data[index] << (8 * index))
    return value

#****************************************************************************
#  FUNCTION:    invoke(arg)
#
#  DESCRIPTION: This function dumps all the entries in the S3 Boot Script Table and
#               Runtime Script Table.
#
#  PARAMETER:   The base of S3 boot script table.
#
#*****************************************************************************
def invoke(arg):
    """
DumpS3Script - Dump content of S3 boot script.
Arguments:                S3ScriptTableAddress
  S3ScriptTableAddress    The base address of S3 boot script table.
"""
    gDebugOn = 0
    args = []
    for _arg in arg.split(' '):
        if _arg != '':
            args.append(_arg)
    if len(args) == 0:
        print("ERROR: DumpS3Script needs the base address of S3 script table.")
        return()
    #
    # Now input parameter is TableBase.
    #
    AcpiBootScriptTable = int(args[0], 0)

    print("\n***** ***** S3 BootScript Start ***** *****\n")
    TableEntry = AcpiBootScriptTable
    TableLength = ReadUnalignedN(TableEntry + 0x5, 4)
    print("***** BootScriptTable Start  = 0x%x *****\n" % AcpiBootScriptTable)
    print("***** BootScriptTable Length = 0x%x *****\n" % TableLength)

    #
    # Check if header is valid, header opcode should be 0xaa.
    #
    if ReadUnalignedN(TableEntry, 2) != 0xaa:
        print("ERROR: Invalid S3 boot script table, quit.")
        return()

    #
    # Go to next real entry.
    #
    TableEntry = TableEntry + ReadUnalignedN(TableEntry + 0x2, 1)
    if gDebugOn:
        print("DEBUG: TableEntry = %x" % TableEntry)
    #
    # Parse entry in Table one by one.
    #
    while TableEntry < (AcpiBootScriptTable + TableLength):
        #
        # Each S3 script entry has a generic header.
        # typedef struct {
        #   UINT16  OpCode;
        #   UINT8   Length;
        # } EFI_BOOT_SCRIPT_GENERIC_HEADER;
        #
        OpCode = ReadUnalignedN(TableEntry, 2)
        Length = ReadUnalignedN(TableEntry + 0x2, 1)
        if gDebugOn:
            print("DEBUG: Entry OpCode = 0x%x, Length = 0x%x" % (OpCode, Length))
        if OpCode == 0x0:
            #
            # EFI_BOOT_SCRIPT_IO_WRITE_OPCODE
            #
            Width = ReadUnalignedN(TableEntry + 0x3, 4)
            Count = ReadUnalignedN(TableEntry + 0x7, 4)
            Address = ReadUnalignedN(TableEntry + 11, 8)
            print("script @ %x  Io.Write       Address = 0x%08x            Count = %d" % (TableEntry,Address,Count), end=' ')
            PrintForWrite(TableEntry + 19, Width, Count)
        if OpCode == 0x1:
            #
            # EFI_BOOT_SCRIPT_IO_READ_WRITE_OPCODE
            #
            Width = ReadUnalignedN(TableEntry + 0x3, 4)
            Address = ReadUnalignedN(TableEntry + 0x7, 8)
            print("script @ %x  Io.Read&Write  Address = 0x%08x           " % (TableEntry,Address), end=' ')
            PrintForReadWritePoll(TableEntry + 15,Width,0)
        if OpCode == 0x2:
            #
            # EFI_BOOT_SCRIPT_MEM_WRITE_OPCODE
            #
            Width = ReadUnalignedN(TableEntry + 0x3, 4)
            Count = ReadUnalignedN(TableEntry + 0x7, 4)
            Address = ReadUnalignedN(TableEntry + 11, 8)
            print("script @ %x Mem.Write       Address = 0x%08x            Count = %d" % (TableEntry,Address,Count), end=' ')
            PrintForWrite(TableEntry + 19,Width,Count)
        if OpCode == 0x3:
            #
            # EFI_BOOT_SCRIPT_MEM_READ_WRITE_OPCODE
            #
            Width = ReadUnalignedN(TableEntry + 0x3, 4)
            Address = ReadUnalignedN(TableEntry + 0x7, 8)
            print("script @ %x Mem.Read&Write  Address = 0x%08x           " % (TableEntry,Address), end=' ')
            PrintForReadWritePoll(TableEntry + 15,Width,0)
        if OpCode == 0x4:
            #
            # EFI_BOOT_SCRIPT_PCI_CONFIG_WRITE_OPCODE
            #
            Width = ReadUnalignedN(TableEntry + 0x3, 4)
            Count = ReadUnalignedN(TableEntry + 0x7, 4)
            Address = ReadUnalignedN(TableEntry + 11, 8)
            print("script @ %x Pci.Write       PciAddr = [B%02x:D%02x:F%02x:R%02x]     Count = %d" % \
                                                              (TableEntry,(Address >> 24) & 0xff,(Address >> 16) & 0xff, (Address >> 8) & 0xff, Address & 0xff, Count), end=' ')
            PrintForWrite(TableEntry + 19,Width,Count)
        if OpCode == 0x5:
            #
            # EFI_BOOT_SCRIPT_PCI_CONFIG_READ_WRITE_OPCODE
            #
            Width = ReadUnalignedN(TableEntry + 0x3, 4)
            Address = ReadUnalignedN(TableEntry + 0x7, 8)
            print("script @ %x Pci.Read&Write  PciAddr = [B%02x:D%02x:F%02x:R%02x]    " % \
                                                                   (TableEntry,(Address >> 24) & 0xff,(Address >> 16) & 0xff, (Address >> 8) & 0xff, Address & 0xff), end=' ')
            PrintForReadWritePoll(TableEntry + 15,Width,0)
        if OpCode == 0x6:
            #
            # EFI_BOOT_SCRIPT_SMBUS_EXECUTE_OPCODE
            #
            SmBusAddress = ReadUnalignedN(TableEntry + 0x3, 8)
            Command = ((SmBusAddress) >> 0x8) & 0xff
            Operation = ReadUnalignedN(TableEntry + 11, 4)
            if (SmBusAddress & 0x00400000) != 0:
              PecCheck = 1
            else:
              PecCheck = 0
            DataSize = ReadUnalignedN(TableEntry + 15, 4)
            print("script @ %x Smb.Execute     SmbAddr = 0x%08x            Cmd = 0x%x Oper = 0x%x PecCheck = 0x%x DataSize = %d &Data = 0x%x" % \
                                              (TableEntry,SmBusAddress,Command,Operation,PecCheck,DataSize,TableEntry + 19))
        if OpCode == 0x7:
            #
            # EFI_BOOT_SCRIPT_STALL_OPCODE
            #
            Duration = ReadUnalignedN(TableEntry + 0x3, 8)
            print("script @ %x Stall           Duration=%d" % (TableEntry,Duration))
        if OpCode == 0x8:
            #
            # EFI_BOOT_SCRIPT_DISPATCH_OPCODE
            #
            EntryPoint = ReadUnalignedN(TableEntry + 0x3, 8)
            print("script @ %x EntryFunc       EntryPoint=0x%x" % (TableEntry,EntryPoint))
        if OpCode == 0x9:
            #
            # EFI_BOOT_SCRIPT_DISPATCH2_OPCODE
            #
            EntryPoint = ReadUnalignedN(TableEntry + 0x3, 8)
            Context = ReadUnalignedN(TableEntry + 11, 8)
            print("script @ %x EntryFunc2      EntryPoint=0x%x Context=0x%x" % (TableEntry,EntryPoint,Context))
        if OpCode == 0xa:
            #
            # EFI_BOOT_SCRIPT_INFORMATION_OPCODE
            #
            InfoLen = ReadUnalignedN(TableEntry + 0x3, 4)
            InfoAddr = TableEntry + 0x7
            print("script @ %x Information    " % TableEntry, end=' ')
            PrintString(InfoAddr,InfoLen)
        if OpCode == 0xb:
            #
            # EFI_BOOT_SCRIPT_PCI_CONFIG2_WRITE_OPCODE
            #
            Width = ReadUnalignedN(TableEntry + 0x3, 4)
            Count = ReadUnalignedN(TableEntry + 0x7, 4)
            Address = ReadUnalignedN(TableEntry + 11, 8)
            Segment = ReadUnalignedN(TableEntry + 19, 2)
            print("script @ %x Pci.Write       PciAddr = [S%02x:B%02x:D%02x:F%02x:R%02x] Count = %d" %\
                            (TableEntry,Segment,(Address >> 24) & 0xff,(Address >> 16) & 0xff, (Address >> 8) & 0xff, Address & 0xff ,Count), end=' ')
            PrintForWrite(TableEntry + 21,Width,Count)
        if OpCode == 0xc:
            #
            # EFI_BOOT_SCRIPT_PCI_CONFIG2_READ_WRITE_OPCODE
            #
            Width = ReadUnalignedN(TableEntry + 0x3, 4)
            Address = ReadUnalignedN(TableEntry + 0x7, 8)
            Segment = ReadUnalignedN(TableEntry + 15, 2)
            print("script @ %x Pci.Read&Write  PciAddr = [S%02x:B%02x:D%02x:F%02x:R%02x]" % \
                                         (TableEntry,Segment,(Address >> 24) & 0xff,(Address >> 16) & 0xff, (Address >> 8) & 0xff, Address & 0xff), end=' ')
            PrintForReadWritePoll(TableEntry + 17,Width,0)
        if OpCode == 0xd:
            #
            # EFI_BOOT_SCRIPT_IO_POLL_OPCODE
            #
            Width = ReadUnalignedN(TableEntry + 0x3, 4)
            Address = ReadUnalignedN(TableEntry + 0x7, 8)
            Delay = ReadUnalignedN(TableEntry + 15, 8)
            print("script @ %x  Io.Poll        Address = 0x%08x            Delay = %d" % (TableEntry,Address,Delay), end=' ')
            PrintForReadWritePoll(TableEntry + 23,Width,1)
        if OpCode == 0xe:
            #
            # EFI_BOOT_SCRIPT_MEM_POLL_OPCODE
            #
            Width = ReadUnalignedN(TableEntry + 0x3, 4)
            Address = ReadUnalignedN(TableEntry + 0x7, 8)
            Delay = ReadUnalignedN(TableEntry + 15, 8)
            LoopTimes = ReadUnalignedN(TableEntry + 23, 8)
            print("script @ %x Mem.Poll        Address = 0x%08x            Delay = %d LoopTimes = %d" % \
                                                        (TableEntry,Address,Delay,LoopTimes), end=' ')
            PrintForReadWritePoll(TableEntry + 31,Width,1)
        if OpCode == 0xf:
            #
            # EFI_BOOT_SCRIPT_PCI_CONFIG_POLL_OPCODE
            #
            Width = ReadUnalignedN(TableEntry + 0x3, 4)
            Address = ReadUnalignedN(TableEntry + 0x7, 8)
            Delay = ReadUnalignedN(TableEntry + 15, 8)
            print("script @ %x Pci.ConfigPoll  PciAddr = [B%02x:D%02x:F%02x:R%02x]     Delay = %d" % \
                        (TableEntry,(Address >> 24) & 0xff,(Address >> 16) & 0xff, (Address >> 8) & 0xff,Address & 0xff,Delay), end=' ')
            PrintForReadWritePoll(TableEntry + 23,Width,1)
        if OpCode == 0x10:
            #
            # EFI_BOOT_SCRIPT_PCI_CONFIG2_POLL_OPCODE
            #
            Width = ReadUnalignedN(TableEntry + 0x3, 4)
            Address = ReadUnalignedN(TableEntry + 0x7, 8)
            Segment = ReadUnalignedN(TableEntry + 15, 2)
            Delay = ReadUnalignedN(TableEntry + 17, 8)
            WidthString = GetWidthString(Width)
            print("script @ %x Pci.Config2Poll PciAddr = [S%02x:B%02x:D%02x:F%02x:R%02x] Delay = %d" % \
                            (TableEntry,Segment,(Address >> 24) & 0xff,(Address >> 16) & 0xff, \
                            (Address >> 8) & 0xff, Address & 0xff,Delay), end=' ')
            PrintForReadWritePoll(TableEntry + 25,Width,1)
        if OpCode == 0xff:
            print("\n***** ***** S3 BootScript End ***** *****\n\n")
            return()
        if OpCode > 0x10:
            #
            # Other OpCode is not valid.
            #
            print("ERROR: Invalid script entry at %x is found!" % TableEntry)
            return()
        #
        # Go to next entry.
        #
        TableEntry = TableEntry + Length
    return()
