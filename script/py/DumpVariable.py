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
#  DumpVariable.py
#
#Abstract:
#
#  Dump content of variable.
#--
from __future__ import print_function
import UdkExtension

def _GetAttributes(Address):
    Attributes = []
    Attribute = UdkExtension.ReadMemory(Address, 1, 1)[0]
    ##define EFI_VARIABLE_NON_VOLATILE       0x00000001
    ##define EFI_VARIABLE_BOOTSERVICE_ACCESS 0x00000002
    ##define EFI_VARIABLE_RUNTIME_ACCESS     0x00000004
    ##define EFI_VARIABLE_READ_ONLY          0x00000008
    if Attribute & 0x1:
        Attributes.append("NV")
    if Attribute & 0x2:
        Attributes.append("BS")
    if Attribute & 0x4:
        Attributes.append("RT")
    if Attribute & 0x8:
        Attributes.append("RO")

    return " + ".join(Attributes)

def _PrintVariableVendorGuid(Address):
    Guid32 = UdkExtension.ReadMemory(Address, 4, 1)[0];
    Guid16 = UdkExtension.ReadMemory(Address + 4, 2, 2);
    Guid8  = UdkExtension.ReadMemory(Address + 8, 1, 8);
    print("VendorGuid: %08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X" % \
            (Guid32, Guid16[0], Guid16[1], Guid8[0], Guid8[1], Guid8[2], Guid8[3], Guid8[4], Guid8[5], Guid8[6], Guid8[7]))

def _PrintVariableData(Address, Size):
    #  printf("Variable Data Addr: %x\n", Address);
    #  printf("Variable Data Value: \n");
    Data = UdkExtension.ReadMemory(Address, 1, Size)
    Line = Size / 0x10
    Tmpl = 0x0
    while Tmpl < Line:
        #printf("   %08x: ", Tmpl);
        print("   %08x: " % (Address + Tmpl * 0x10), end=' ')
        Idx = 0x0
        while Idx < 0x10:
            if Idx == 0x7:
                print("%02x -" % Data[Tmpl * 0x10 + Idx], end=' ')
            else:
                print("%02x" % Data[Tmpl * 0x10 + Idx], end=' ')
            Idx += 1
        print(" *", end=' ')
        Idx = 0x0
        while Idx < 0x10:
            if Data[Tmpl * 0x10 + Idx] <= 0x7f and Data[Tmpl * 0x10 + Idx] >= 0x20:
                print("%c" % Data[Tmpl * 0x10 + Idx], end=' ')
            else:
                print(".", end=' ')
            Idx += 1
        print("*")
        Tmpl += 1
    if Size % 0x10:
        #printf("   %08x: ", Tmpl);
        print("   %08x: " % (Address + Tmpl * 0x10), end=' ')
        Idx = 0x0
        while Idx < Size % 0x10:
            if Idx == 0x7:
                print("%02x -" % Data[Tmpl * 0x10 + Idx], end=' ')
            else:
                print("%02x" % Data[Tmpl * 0x10 + Idx], end=' ')
            Idx += 1
        Idx = 0x0
        while Idx < 0x10 - Size % 0x10:
            if Idx == 0x7:
                print("    ", end=' ')
            else:
                print("  ", end=' ')
            Idx += 1
        print(" *", end=' ')
        Idx = 0x0
        while Idx < Size % 0x10:
            if Data[Tmpl * 0x10 + Idx] <= 0x7f and Data[Tmpl * 0x10 + Idx] >= 0x20:
                print("%c" % Data[Tmpl * 0x10 + Idx], end=' ')
            else:
                print(".", end=' ')
            Idx += 1
        print("*")

def _Match(Name, Pattern):
    if len(Pattern) > 0:
        if Pattern[0] == '*':
            return _Match(Name, Pattern[1:]) or (len(Name) > 0 and _Match(Name[1:], Pattern))
        elif Pattern[0] == '?':
            return len(Name) > 0 and _Match(Name[1:], Pattern[1:])
        else:
            return len(Name) > 0 and Pattern[0] == Name[0] and _Match (Name[1:], Pattern[1:])
    else:
        return len(Name) == 0

def _GetNvStorageStart():
    DebugOn = 0x0
    #
    # User could specify a hardcoded NvStorage start address
    #
    #return 0xFFFC0000;
    #
    # Search for NV storage FV
    #
    Addr = 0xffff0000
    if DebugOn:
      print("Start to find NV base\n")
    while 0x1:
        if Addr == 0x0:
            break
        if DebugOn:
          print("Search flash address at %x" % (Addr + 0x28))
        if UdkExtension.ReadMemory(Addr + 0x28, 4, 1)[0] == 0x4856465f:
            # FV header signature '_FVH'
            #
            # Find FileSystemGuid of NV.
            #
            if DebugOn:
              print("Find _FVH\n")
            if (UdkExtension.ReadMemory(Addr + 0x10, 4, 4)) == [0xfff12b8d, 0x4c8b7696, 0x472785a9, 0x504f5b07]:
              if UdkExtension.ReadMemory(Addr + 0x48, 4, 4) in [[0xaaf32c78, 0x439a947b, 0x142e80a1, 0x9277c34e], [0xddcf3616, 0x41643275, 0x85feb698, 0x7dfe7f70]]:
                    #
                    # Finding supported variable format (Auth/Non-Auth)
                    #
                    if DebugOn:
                        print("NV base address = %x\n" % Addr)
                    return(Addr)
        Addr -= 0x10000
        # assume flash block size: 64K
    return(0x0)

#****************************************************************************
#  FUNCTION: invoke(arg)
#
#  DESCRIPTION: The entry point of command to dump content of NV variable.
#
#  ARGUMENTS:
#    arg - Variable Name
#*****************************************************************************
def invoke(arg):
    """
DumpVariable - Dump content of UEFI variable on flash.
Arguments: [VariableName]
  VariableName    The name of variable. If a variable name is specified, 
                  the contents of this variable will be dumped. 
                  If a variable name is not specified, the contents of all
                  UEFI variables on flash will be dumped.
"""
    Pattern = '*'
    args = []
    for _arg in arg.split(' '):
        if _arg != '':
            args.append(_arg)
    if len(args) > 0x1:
        print("Invalid parameter")
        return()
    if len(args) == 0x1:
        Pattern = args[0]
    pVariableStart = _GetNvStorageStart()
    if pVariableStart == 0x0:
        print("ERROR: Can't find NV storage FV\n")
        return()
    #
    # Skip the FV header by adding the HeaderLength
    # typedef struct {
    #	UINT8                     ZeroVector[16];
    #   EFI_GUID                  FileSystemGuid;
    #   UINT64                    FvLength;
    #   UINT32                    Signature;
    #   EFI_FVB_ATTRIBUTES_2      Attributes;
    #   UINT16                    HeaderLength;
    #   UINT16                    Checksum;
    #   UINT16                    ExtHeaderOffset;
    #   UINT8                     Reserved[1];
    #   UINT8                     Revision;
    #   EFI_FV_BLOCK_MAP_ENTRY    BlockMap[1];
    #  } EFI_FIRMWARE_VOLUME_HEADER;
    #
    pVariableStart = pVariableStart + UdkExtension.ReadMemory(pVariableStart + 0x30, 2, 1)[0]
    DebugOn = 0x0
    #
    # When meet auth variable format, we should follow auth variable header to search.
    # Check auth variable store hander guid.
    #
    HeaderSize = 0x20
    if ((UdkExtension.ReadMemory(pVariableStart, 4, 1))[0] == 0xaaf32c78) and ((UdkExtension.ReadMemory(pVariableStart + 0x4, 4, 1))[0] == 0x439a947b) and \
        ((UdkExtension.ReadMemory(pVariableStart + 0x8, 4, 1))[0] == 0x142e80a1) and ((UdkExtension.ReadMemory(pVariableStart + 0xc, 4, 1))[0] == 0x9277c34e):
        #
        # Auth variable is used.
        #
        print("Authenticated Variable.")
        HeaderSize = 0x3c
    if DebugOn:
        print("Ready to find variable start\n")

    #
    # Get the start address of first variable
    #
    # typedef struct {
    #  EFI_GUID  Signature;
    #  UINT32  Size;
    #  UINT8   Format;
    #  UINT8   State;
    #  UINT16  Reserved;
    #  UINT32  Reserved1;
    # } VARIABLE_STORE_HEADER;
    #
    pVariableStart = pVariableStart + 28; # Skip the VARIABLE_STORE_HEADER for Auth and non-Auth
    if DebugOn:
        print("DEBUG: pVariableStart = %x\n" % pVariableStart)

    while (UdkExtension.ReadMemory(pVariableStart, 2, 1)[0] == 0x55aa):
        (NameSize, DataSize) = UdkExtension.ReadMemory(pVariableStart + HeaderSize - 0x10 - 0x8, 4, 2)
        if (UdkExtension.ReadMemory(pVariableStart + 0x2, 1, 1)[0]) == 0x3f:
            # EDKII BIOS adds 0x3F as valid variable header and data.
            Name = list(map(chr, UdkExtension.ReadMemory(pVariableStart + HeaderSize, 2, NameSize/2 - 1)))
            Name = "".join(Name)
            if _Match(Name, Pattern):
                print("Variable  \"%s\"" % Name)
                print("  ", end=' ')
                _PrintVariableVendorGuid(pVariableStart + HeaderSize - 0x10)
                print("   Attribute : %s             DataSize = %d" % (_GetAttributes(pVariableStart + 4), DataSize))
                _PrintVariableData(pVariableStart + HeaderSize + NameSize, DataSize)
        pVariableStart = pVariableStart + NameSize + DataSize + HeaderSize
        pVariableStart = (pVariableStart + 0x3) & ~0x3
