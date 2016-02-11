#++
#
#Copyright (c) 2012 - 2013 Intel Corporation. All rights reserved
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
#  DumpHobs.py
#
#Abstract:
#
#  Dump the content of HOB list.
#
#--
from __future__ import print_function
import UdkExtension

gCpuArch            = 0
def GetEfiSystemTable():
    DebugOn = 0
    #
    #typedef struct {
    #  UINT64                Signature;          ///< A constant UINT64 that has the value EFI_SYSTEM_TABLE_SIGNATURE
    #  EFI_PHYSICAL_ADDRESS  EfiSystemTableBase; ///< The physical address of the EFI system table. 
    #  UINT32                Crc32;              ///< A 32-bit CRC value that is used to verify the EFI_SYSTEM_TABLE_POINTER structure is valid.
    #} EFI_SYSTEM_TABLE_POINTER;
    #
    Signature = [0x49, 0x42, 0x49, 0x20, 0x53, 0x59, 0x53, 0x54]
    SystemTablePointer = UdkExtension.SearchSignature (0x400000, 0xFFC00000, 0x400000, True, Signature)
    if SystemTablePointer is None:
      return None
    #
    # Check the signature for EFI system table
    #
    SystemTable = UdkExtension.ReadMemory (SystemTablePointer + 0x8, 8, 1)[0]
    if DebugOn:
        print("EFI System Table Addr: %x\n" % SystemTable)
    return SystemTable

#****************************************************************************
#  FUNCTION: GetConfigTableValue ()
#
#  USAGE:  GetConfigTableValue (Guid32, Guid16, Guid16, StartAddr)
#
#  DESCRIPTION: This function finds the EFI system configuration table and
#    looks for an entry with a matching GUID.
#
#  ARGUMENTS: 
#    Guidxx    - the first 8 bytes of the GUID entry
#    StartAddr - optional EFI system table address
#
#  RETURNS:
#    The value for the entry.
#
#  NOTE: We only check the first 8 bytes for a match.
#*****************************************************************************
def GetConfigTableValue(GuidV32, GuidV16_1, GuidV16_2, GuidV64):
    DebugOn = 0x0
    if gCpuArch == 2:
        if DebugOn:
            print("64-bit mode")
        SizeOfPointer = 0x8
    else:
        if DebugOn:
            print("32-bit mode")
        SizeOfPointer = 0x4
    #
    # Find system table address
    #
    SystemTable = GetEfiSystemTable()
    if SystemTable is None:
        print("ERROR: Fail to find EFI System Table in memory and can not dump hobs on EFI System Table.")
        print("       Try to pass HOB start address into this command.")
        return None
    if DebugOn:
        print("debug:        EFI_SYSTEM_TABLE         at 0x%08x" % SystemTable)
    #
    # Get the pointer to the system configuration table.
    # An EFI_TABLE_HEADER size is sizeof(UINT64) + 4 * sizeof(UINT32) = 0x18
    #
    (Count, Table) = UdkExtension.ReadMemory(SystemTable + 0x18 + (10 * SizeOfPointer), SizeOfPointer, 2)
    Found = False
    while Count > 0x0:
        #
        # Look for a matching GUID value
        #
        if UdkExtension.ReadMemory(Table, 4, 1)[0] == GuidV32 and \
           UdkExtension.ReadMemory(Table+0x4, 2, 2) == [GuidV16_1, GuidV16_2] and \
           UdkExtension.ReadMemory(Table+0x8, 8, 1)[0] == GuidV64:
            #
            # Check the rest of the GUID bytes as well
            #
            Found = True
            break
        #
        # Move to the next entry in the table (sizeof(EFI_GUID) + sizeof(char *))
        #
        Table = Table + 0x10 + SizeOfPointer
        Count -= 1
    if not Found:
        print("ERROR: failed to find HOB list in the configuration table. Try to pass HOB start address into this command.")
        return None
    if DebugOn:
        print("debug GetConfigTableValue(): Found matching config table entry at %x" % Table)
    #
    # Get the pointer to the data (it's after the GUID)
    #
    Addr = UdkExtension.ReadMemory(Table + 0x10, SizeOfPointer, 1)[0]
    if DebugOn:
        print("debug GetConfigTableValue(): Entry data found at %x" % Addr)
    return(Addr)

#****************************************************************************
#  FUNCTION:  DumHobs()
#
#  USAGE:  DumpHobs (pointer HobAddress)
#
#  DESCRIPTION: This function takes a pointer to a HOB list and dumps them.
#*****************************************************************************
def DumpHobs(Address):
    DebugOn = 0x0
    HobStart = Address
    HeaderSize = 0x8
    FirstHob = True
    HobType = 0x0
    while HobType != 0xffff:
        if DebugOn:
            print("debug DumpHobs(): Hob at %x" % HobStart)
        (HobType, HobLength) = UdkExtension.ReadMemory(HobStart, 2, 2)
        if FirstHob and (HobType != 0x1):
            print("ERROR : DumpHobs() : first HOB is not PHIT")
            return
        FirstHob = False
        Hob = HobStart + HeaderSize
        #***********************************************************************
        #
        # HANDOFF HOB -- type 1
        #
        #***********************************************************************
        if HobType == 0x1:
            print("HOB Handoff at 0x%08x\n" % HobStart)
            print("  Version                0x%x" % UdkExtension.ReadMemory(Hob, 2, 1)[0])
            Hob += 0x4
            BootMode = UdkExtension.ReadMemory(Hob, 4, 1)[0]
            print("  Boot mode              0x%x  " % BootMode, end=' ')
            if BootMode == 0x0:
                print("full configuration")
            if BootMode == 0x1:
                print("minimal configuration")
            if BootMode == 0x2:
                print("no config changes")
            if BootMode == 0x3:
                print("default settings")
            if BootMode == 0x5:
                print("S4 resume")
            if BootMode == 0x6:
                print("S5 resume")
            if BootMode == 0x10:
                print("S2 resume")
            if BootMode == 0x11:
                print("S3 resume")
            if BootMode == 0x12:
                print("flash update")
            if BootMode == 0x20:
                print("recovery")
            Hob += 0x4
            (MemoryTop, MemoryBottom, FreeMemoryTop, FreeMemoryBottom, EndOfHob) = UdkExtension.ReadMemory(Hob, 8, 5)
            print("  Memory top             0x%016x" % MemoryTop)
            print("  Memory bottom          0x%016x" % MemoryBottom)
            print("  Free memory top        0x%016x" % FreeMemoryTop)
            print("  Free memory bottom     0x%016x" % FreeMemoryBottom)
            print("  End of HOB list        0x%016x" % EndOfHob)
        #***********************************************************************
        #
        # MEMORY ALLOCATION HOB -- type 2
        #
        #***********************************************************************
        elif HobType == 0x2:
            print("HOB Memory allocation ", end=' ')
            #
            # Look at the first 32-bits of the GUID and if it matches, assume it
            # is a stack/BSP allocation
            #
            Guid32 = UdkExtension.ReadMemory(Hob, 4, 1)[0]
            if Guid32 == 0x564b33cd:
                print("(BSP store)", end=' ')
            if Guid32 == 0x4ed4bf27:
                print("(stack)", end=' ')
            if Guid32 == 0xf8e21975:
                print("(module)", end=' ')
            print(" at 0x%08x" % HobStart)
            #
            # Skip over the GUID, and print the physical address and
            # the size (both 64-bit values)
            #
            (Base, Length) = UdkExtension.ReadMemory(Hob + 0x10, 8, 2)
            print("  Base                   0x%016x" % Base)
            print("  Length                 0x%016x" % Length)
            print("  Memory type           ", end=' ')
            Type = UdkExtension.ReadMemory (Hob + 0x20, 4, 1)[0]
            if Type == 0x0:
                print("EfiReservedMemoryType")
            if Type == 0x1:
                print("EfiLoaderCode")
            if Type == 0x2:
                print("EfiLoaderData")
            if Type == 0x3:
                print("EfiBootServicesCode")
            if Type == 0x4:
                print("EfiBootServicesData")
            if Type == 0x5:
                print("EfiRuntimeServicesCode")
            if Type == 0x6:
                print("EfiRuntimeServicesData")
            if Type == 0x7:
                print("EfiConventionalMemory")
            if Type == 0x8:
                print("EfiUnusableMemory")
            if Type == 0x9:
                print("EfiACPIReclaimMemory")
            if Type == 0xa:
                print("EfiACPIMemoryNVS")
            if Type == 0xb:
                print("EfiMemoryMappedIO")
            if Type == 0xc:
                print("EfiMemoryMappedIOPortSpace")
            if Type == 0xd:
                print("EfiPalCode")
            if Type == 0xe:
                print("EfiMaxMemoryType")
            if Type > 0xe:
                print("INVALID MEMORY TYPE")
        #***********************************************************************
        #
        # RESOURCE DESCRIPTOR HOB -- type 3
        #
        #***********************************************************************
        elif HobType == 0x3:
            print("HOB Resource descriptor at 0x%08x" % HobStart)
            Hob += 0x10
            (Type, Attribute) = UdkExtension.ReadMemory (Hob, 4, 2)
            print("  Resource type          0x%X (" % Type, end=' ')
            if Type == 0x0:
                print("system memory", end=' ')
            if Type == 0x1:
                print("memory-mapped I/O", end=' ')
            if Type == 0x2:
                print("I/O", end=' ')
            if Type == 0x3:
                print("firmware device", end=' ')
            if Type == 0x4:
                print("memory-mapped port I/O", end=' ')
            if Type == 0x5:
                print("reserved memory", end=' ')
            if Type == 0x6:
                print("reserved I/O", end=' ')
            if Type > 0x6:
                print("INVALID TYPE", end=' ')
            print(")")
            #
            # Decode the attributes
            #
            print("  Attributes             0x%x" % Attribute)
            if Attribute & 0x1:
                print("                         Present")
            if Attribute & 0x2:
                print("                         Initialized")
            if Attribute & 0x4:
                print("                         Tested")
            if Attribute & 0x8:
                print("                         Single-bit ECC")
            if Attribute & 0x10:
                print("                         Multiple-bit ECC")
            if Attribute & 0x20:
                print("                         ECC reserved #1")
            if Attribute & 0x40:
                print("                         ECC reserved #2")
            if Attribute & 0x80:
                print("                         Read-protected")
            if Attribute & 0x100:
                print("                         Write-protected")
            if Attribute & 0x200:
                print("                         Execution-protected")
            if Attribute & 0x400:
                print("                         Uncacheable")
            if Attribute & 0x800:
                print("                         Write-combinable")
            if Attribute & 0x1000:
                print("                         Write-through cacheable")
            if Attribute & 0x2000:
                print("                         Write-back cacheable")
            if Attribute & 0x4000:
                print("                         16-bit I/O")
            if Attribute & 0x8000:
                print("                         32-bit I/O")
            if Attribute & 0x10000:
                print("                         64-bit I/O")
            if Attribute & 0x20000:
                print("                         Uncached Exported")
            if Attribute & 0x100000:
                print("                         Read Protectable")
            if Attribute & 0x200000:
                print("                         Write Protectable")
            if Attribute & 0x400000:
                print("                         Execution Protectable")
            (Base, Length) = UdkExtension.ReadMemory (Hob + 0x8, 8, 2)
            print("  Base address           0x%016x" % Base)
            print("  Length                 0x%016x" % Length)
        #***********************************************************************
        #
        # GUID EXTENSION HOB -- type 4
        #
        #***********************************************************************
        elif HobType == 0x4:
            print("HOB GUID extension at 0x%08x" % HobStart)
        #***********************************************************************
        #
        # FIRMWARE VOLUME HOB -- type 5
        #
        #***********************************************************************
        elif HobType == 0x5:
            print("HOB Firmware volume at 0x%08x" % HobStart)
            (Base, Length) = UdkExtension.ReadMemory (Hob, 8, 2)
            print("  Base                   0x%016x" % Base)
            print("  Length                 0x%016x" % Length)
        #***********************************************************************
        #
        # CPU HOB -- type 6
        #
        #***********************************************************************
        elif HobType == 0x6:
            print("HOB CPU at 0x%08x" % HobStart)
            (MemorySpaceSize, IoSpaceSize) = UdkExtension.ReadMemory (Hob, 1, 2)
            print("  SizeOfMemorySpace      0x%02x" % MemorySpaceSize)
            print("  SizeOfIoSpace          0x%02x" % IoSpaceSize)
        #***********************************************************************
        #
        # MEMORY POOL HOB -- type 7
        #
        #***********************************************************************
        elif HobType == 0x7:
            print("HOB Memory pool at 0x%08x" % HobStart)
        #***********************************************************************
        #
        # CAPSULE VOLUME HOB -- type 8
        #
        #***********************************************************************
        elif HobType == 0x8:
            print("HOB Capsule volume at 0x%08x" % HobStart)
            (Base, Length) = UdkExtension.ReadMemory (Hob, 8, 2)
            print("  Base                   0x%016x" % Base)
            print("  Length                 0x%016x" % Length)
            
        #***********************************************************************
        #
        # FIRMWARE VOLUME2 HOB -- type 9
        #
        #***********************************************************************
        elif HobType == 0x9:
            print("HOB Firmware volume2 at 0x%08x" %HobStart)
            (Base, Length) = UdkExtension.ReadMemory (Hob, 8, 2)
            print("  Base                   0x%016x" % Base)
            print("  Length                 0x%016x" % Length)
        #***********************************************************************
        #
        # Load PEIM HOB -- type A
        #
        #***********************************************************************
        elif HobType == 0xa:
            print("HOB LOAD PEIM at 0x%08x" % HobStart)
        #***********************************************************************
        elif HobType == 0xfffe:
            print("HOB Unused at 0x%08x" % HobStart)
        #***********************************************************************
        elif HobType == 0xffff:
            print("HOB End of HOB list at 0x%08x" % HobStart)
        #***********************************************************************
        else:
            print("HOB INVALID TYPE 0x%x at 0x%08x -- aborting" % (Type,HobStart))
            return
        if HobLength == 0x0:
            print("DumpHobs() ERROR: 0-length HOB found at 0x%08x" % HobStart)
            return
        HobStart += HobLength

#****************************************************************************
#  FUNCTION: invoke(arg)
#                  
#  DESCRIPTION: This command finds the hob pointer in the DXE configuration
#               table, or if user pass a hob start address into this command, 
#               the content of hob will be dumped.
#
#  ARGUMENTS:
#    address  - optional start address of hob.
#*****************************************************************************
def invoke(arg):
    """
DumpHobs - Dump the content of HOB list.
Arguments:          [HobStartAddress]
  HobStartAddress   The start address of HOB list. The first HOB in the HOB list 
                    must be the Phase Handoff Information Table (PHIT) HOB. When
                    HobStartAddress is not specified, HOB list will be got from
                    EFI Configuration Table and dumped.
"""
    global gCpuArch
    args = []
    for _arg in arg.split(' '):
        if _arg != '':
            args.append(_arg)
    gCpuArch = UdkExtension.GetArch()
    if gCpuArch is None:
        print("ERROR: can not determine whether CPU is 32-bit or 64-bit")
        return
    if len(args) == 0:
        Addr = GetConfigTableValue (0x7739F24C, 0x93D7, 0x11D4, 0x4DC13F2790003A9A)
        if Addr is not None:
            DumpHobs(Addr)
    else:
        Addr = int(args[0], 0)
        DumpHobs(Addr)
