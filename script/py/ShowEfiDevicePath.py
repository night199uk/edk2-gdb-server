#++
#
#Copyright (c) 2012 - 2015 Intel Corporation. All rights reserved
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
#  ShowEfiDevicePath.py
#
#Abstract:
#
#  Convert device path to text
#
#--
from __future__ import print_function
import UdkExtension

def ReadUnalignedN(Address, N):
    data = UdkExtension.ReadMemory(Address, 1, N)
    value = 0
    for i in range(N):
        value = value + (data[i] << (8 * i))
    return value

def Pci(Address):
    return "Pci(0x%x,0x%x)" % (ReadUnalignedN(Address + 0x5, 1), ReadUnalignedN(Address + 0x4, 1))

def PcCard(Address):
    return "PcCard(0x%x)" % ReadUnalignedN(Address + 0x4, 1)

def MemMap(Address):
    return "MemoryMapped(0x%x,0x%lx,0x%lx)" % (ReadUnalignedN(Address + 0x4, 4),
                                               ReadUnalignedN(Address + 0x8, 8),
                                               ReadUnalignedN(Address + 0x10, 8)
                                               )

def Controller(Address):
    return "Ctrl(0x%x)" % ReadUnalignedN(Address + 0x4, 4)

def AcpiIdToString(ID):
    return "%c%c%c%04X" % (
        chr(((ID >> 10) & 0x1f) + ord('A') - 1),
        chr(((ID >>  5) & 0x1f) + ord('A') - 1),
        chr(((ID >>  0) & 0x1f) + ord('A') - 1),
        (ID >> 16) & 0xFFFF
        )

def Acpi(Address):
    HID = ReadUnalignedN(Address + 0x4, 4)
    UID = ReadUnalignedN(Address + 0x8, 4)
    if (HID & 0xffff) == 0x41d0:
        String = "Acpi(%s,0x%x)" % (AcpiIdToString(HID), UID)
        if (HID >> 16) == 0x0a03:
            String = "PciRoot(0x%x)" % UID
        if (HID >> 16) == 0x0a08:
            String = "PcieRoot(0x%x)" % UID
        if (HID >> 16) == 0x0604:
            String = "Floppy(0x%x)" % UID
        if (HID >> 16) == 0x0301:
            String = "Keyboard(0x%x)" % UID
        if (HID >> 16) == 0x0501:
            String = "Serial(0x%x)" % UID
        if (HID >> 16) == 0x0401:
            String = "ParallelPort(0x%x)" % UID
    else:
        String = "Acpi(0x%08x,0x%x)" % (HID, UID)
    return String

def AsciiBytesToString(Bytes):
    Str = ""
    for I in range(len(Bytes)):
        if Bytes[I] == 0:
            return (Str, Bytes[I + 1 :])
        else:
            Str += chr(Bytes[I])
    return None

def AcpiEx(Address):
    Length = ReadUnalignedN(Address + 2, 2)
    HID = ReadUnalignedN(Address+4, 4)
    UID = ReadUnalignedN(Address+8, 4)
    CID = ReadUnalignedN(Address+12, 4)
    IdString = UdkExtension.ReadMemory(Address + 16, 1, Length - 16)

    (HIDStr, IdString) = AsciiBytesToString(IdString)
    (UIDStr, IdString) = AsciiBytesToString(IdString)
    (CIDStr, IdString) = AsciiBytesToString(IdString)

    HIDText = AcpiIdToString(HID)
    CIDText = AcpiIdToString(CID)

    if HIDStr == "" and CIDStr == "" and UID == 0:
        String = "AcpiExp(%s,%s,%s)" % (HIDText, CIDText, UIDStr)
    else:
        if HID == 0:
            String = "AcpiEx(%s," % HIDStr
        else:
            String = "AcpiEx(%s," % HIDText

        if UID == 0:
            String += "%s," % UIDStr
        else:
            String += "0x%x," % UID

        if CID == 0:
            String += "%s)" % CIDStr
        else:
            String += "%s)" % CIDText
    return String

def AcpiAdr(Address):
    Length = ReadUnalignedN(Address + 2, 2)
    String = "AcpiAdr(0x%x" % ReadUnalignedN(Address + 4, 4)
    for I in range((Length - 8) / 4):
        String += ",0x%x" % ReadUnalignedN(Address + 8 + I * 4, 4)
    String += ")"
    return String

def Atapi(Address):
    if ReadUnalignedN(Address + 4, 1) == 1:
        PrimarySecondary = "Secondary"
    else:
        PrimarySecondary = "Primary"
    if ReadUnalignedN(Address + 5, 1) == 1:
        SlaveMaster = "Slave"
    else:
        SlaveMaster = "Master"
    return "Ata(%s,%s,0x%x)" % (PrimarySecondary, SlaveMaster, ReadUnalignedN(Address + 6, 2))

def Scsi(Address):
    return "Scsi(0x%x,0x%x)" % (ReadUnalignedN(Address + 4, 2), ReadUnalignedN(Address + 6, 2))

def Fibre(Address):
    return "Fibre(0x%lx,0x%lx)" % (ReadUnalignedN(Address + 8, 8), ReadUnalignedN(Address + 16, 8))

def FibreEx(Address):
    String = "FibreEx(0x"
    for b in UdkExtension.ReadMemory(Address + 8, 1, 8):
        String += "%02x" % b
    String += ",0x"
    for b in UdkExtension.ReadMemory(Address + 16, 1, 8):
        String += "%02x" % b
    String += ")"
    return String

def SasEx(Address):
    String = "SasEx(0x"
    for b in UdkExtension.ReadMemory(Address + 4, 1, 8):
        String += "%02x" % b
    String += ",0x"
    for b in UdkExtension.ReadMemory(Address + 12, 1, 8):
        String += "%02x" % b
    String += ",0x%x," % ReadUnalignedN(Address + 0x16, 2)
    TopologyString = "0,0,0,0"
    Topology = ReadUnalignedN(Address + 0x14, 2)
    if Topology & 0xf == 0x0:
        TopologyString = "NoTopology,0,0,0"
    if Topology & 0xf == 0x1 or Topology == 0x2:
        if (Topology & (0x1 << 4)) != 0:
            SataSas = "SATA"
        else:
            SataSas = "SAS"
        if (Topology & (0x1 << 5)) != 0:
            ExternalInternal = "External"
        else:
            ExternalInternal = "Internal"
        if (Topology & (0x1 << 6)) != 0:
            ExpandedDirect = "Expanded"
        else:
            ExpandedDirect = "Direct"
        TopologyString = "%s,%s,%s," % (SataSas, ExternalInternal, ExpandedDirect)
        if Topology & 0xf == 0x1:
            TopologyString += "0"
        else:
            TopologyString += "0x%x" % (Topology >> 8) & 0xff
    String += TopologyString
    String += ")"
    return String

def NVMe(Address):
    Uuid = UdkExtension.ReadMemory(Address + 8, 1, 8)
    return "NVMe(0x%x,%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x)" % (
        ReadUnalignedN(Address + 4, 4),
        Uuid[7], Uuid[6], Uuid[5], Uuid[4],
        Uuid[3], Uuid[2], Uuid[1], Uuid[0]
        )

def Ufs(Address):
    return "UFS(0x%x,0x%x)" % (ReadUnalignedN(Address + 4, 1),
                               ReadUnalignedN(Address + 5, 1))

def Sd(Address):
    return "SD(0x%x)" % ReadUnalignedN(Address + 4, 1)

def I1394(Address):
    return "I1394(%016lx)" % ReadUnalignedN(Address + 8, 8)

def Usb(Address):
    return "USB(0x%x,0x%x)" % (ReadUnalignedN(Address + 4, 1),
                               ReadUnalignedN(Address + 5, 1))


def UnicodeBytesToString(Bytes):
    Str = ""
    for I in range(0, len(Bytes), 2):
        if Bytes[I] == 0:
            return (Str, Bytes[I + 2 :])
        else:
            Str += chr(Bytes[I])
    return None

def UsbWwid(Address):
    Length = ReadUnalignedN(Address + 2, 2)
    SerialNumber = UdkExtension.ReadMemory(Address + 10, 1, Length - 10)
    (SerialNumberStr, SerialNumber) = UnicodeBytesToString(SerialNumber)
    return "UsbWwid(0x%x,0x%x,0x%x,\"%s\")" % (
        ReadUnalignedN(Address + 6, 2),
        ReadUnalignedN(Address + 8, 2),
        ReadUnalignedN(Address + 4, 2),
        SerialNumberStr
        )

def Unit(Address):
    return "Unit(0x%x)" % ReadUnalignedN(Address + 4, 1)

def UsbClass(Address):
    Known = True
    Class = ReadUnalignedN(Address + 8, 1)
    SubClass = ReadUnalignedN(Address + 9, 1)
    if Class == 1:
        ClassStr = "UsbAudio"
    elif Class == 2:
        ClassStr = "UsbCDCControl"
    elif Class == 3:
        ClassStr = "UsbHID"
    elif Class == 6:
        ClassStr = "UsbImage"
    elif Class == 7:
        ClassStr = "UsbPrinter"
    elif Class == 8:
        ClassStr = "UsbMassStorage"
    elif Class == 9:
        ClassStr = "UsbHub"
    elif Class == 10:
        ClassStr = "UsbCDCData"
    elif Class == 11:
        ClassStr = "UsbSmartCard"
    elif Class == 14:
        ClassStr = "UsbVideo"
    elif Class == 220:
        ClassStr = "UsbDiagnostic"
    elif Class == 224:
        ClassStr = "UsbWireless"
    else:
        Known = False

    if Known:
        return "%s(0x%x,0x%x,0x%x,0x%x)" % (
            ClassStr,
            ReadUnalignedN(Address + 4, 2),
            ReadUnalignedN(Address + 6, 2),
            SubClass,
            ReadUnalignedN(Address + 10, 1)
            )

    if Class == 0xFE:
        Known = True
        if SubClass == 1:
            SubClassStr = "UsbDeviceFirmwareUpdate"
        elif SubClass == 2:
            SubClassStr = "UsbIrdaBridge"
        elif SubClass == 3:
            SubClassStr = "UsbTestAndMeasurement"
        else:
            Known = False
        if Known:
            return "%s(0x%x,0x%x,0x%x)" % (
                SubClassStr,
                ReadUnalignedN(Address + 4, 2),
                ReadUnalignedN(Address + 6, 2),
                ReadUnalignedN(Address + 10, 1)
                )

    return "UsbClass(0x%x,0x%x,0x%x,0x%x,0x%x)" % (
         ReadUnalignedN(Address + 4, 2),
         ReadUnalignedN(Address + 6, 2),
         Class,
         SubClass,
         ReadUnalignedN(Address + 10, 1)
         )

def Sata(Address):
    return "Sata(0x%x,0x%x,0x%x)" % (ReadUnalignedN(Address + 4, 2),
                                    ReadUnalignedN(Address + 6, 2),
                                    ReadUnalignedN(Address + 8, 2))

def I2o(Address):
    return "I2O(0x%x)" % ReadUnalignedN(Address + 4, 4)

def Guid2String(Address):
    Guid0 = ReadUnalignedN(Address, 4)
    Guid1 = ReadUnalignedN(Address + 4, 4)
    Guid2 = ReadUnalignedN(Address + 8, 4)
    Guid3 = ReadUnalignedN(Address + 12, 4)
    GuidString = "%08x-%04x-%04x-%04x-%02x%02x%02x%02x%02x%02x" % (
                 Guid0, Guid1 & 0xffff, Guid1 >> 16,
                 (Guid2 & 0xff) << 8 | (Guid2 & 0xff00) >> 8,
                 (Guid2 >> 16) & 0xff, (Guid2 >> 24) & 0xff,
                 (Guid3 >> 0) & 0xff, (Guid3 >> 8) & 0xff, (Guid3 >> 16) & 0xff, (Guid3 >> 24) & 0xff
                 )
    return GuidString

def Mac(Address):
    AddressSize = 32
    IfType = ReadUnalignedN(Address + 36, 1)
    if IfType == 1 or IfType == 0:
        AddressSize = 6
    String = "MAC("
    for b in UdkExtension.ReadMemory(Address + 4, 1, AddressSize):
        String += "%02x" % b
    String += ",0x%x)" % IfType
    return String

def Ipv4(Address):
    String = "IPv4(%d.%d.%d.%d," % (
        ReadUnalignedN(Address + 8, 1),
        ReadUnalignedN(Address + 9, 1),
        ReadUnalignedN(Address + 10, 1),
        ReadUnalignedN(Address + 11, 1))
    Protocol = ReadUnalignedN(Address + 0x10, 2)
    ProtocolString = "0x%x" % Protocol
    if Protocol == 0x6:
        ProtocolString = "TCP"
    if Protocol == 0x11:
        ProtocolString = "UDP"
    String += ProtocolString
    if ReadUnalignedN(Address + 0x12, 1) == 1:
        String += ",%s," % "Static"
    else:
        String += ",%s," % "DHCP"
    String += "%d.%d.%d.%d" % (
                                  ReadUnalignedN(Address + 0x4, 1),
                                  ReadUnalignedN(Address + 0x5, 1),
                                  ReadUnalignedN(Address + 0x6, 1),
                                  ReadUnalignedN(Address + 0x7, 1))
    if ReadUnalignedN(Address + 0x2, 2) == 0x1b:
        String += ",%d.%d.%d.%d,%d.%d.%d.%d" % (
                                   ReadUnalignedN(Address + 0x13, 1),
                                   ReadUnalignedN(Address + 0x14, 1),
                                   ReadUnalignedN(Address + 0x15, 1),
                                   ReadUnalignedN(Address + 0x16, 1),
                                   ReadUnalignedN(Address + 0x17, 1),
                                   ReadUnalignedN(Address + 0x18, 1),
                                   ReadUnalignedN(Address + 0x19, 1),
                                   ReadUnalignedN(Address + 0x1a, 1))
    String += ")"
    return String

def Ipv6(Address):
    String = "IPv6(%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x," % (
                                  ReadUnalignedN(Address + 0x14, 1),
                                  ReadUnalignedN(Address + 0x15, 1),
                                  ReadUnalignedN(Address + 0x16, 1),
                                  ReadUnalignedN(Address + 0x17, 1),
                                  ReadUnalignedN(Address + 0x18, 1),
                                  ReadUnalignedN(Address + 0x19, 1),
                                  ReadUnalignedN(Address + 0x1a, 1),
                                  ReadUnalignedN(Address + 0x1b, 1),
                                  ReadUnalignedN(Address + 0x1c, 1),
                                  ReadUnalignedN(Address + 0x1d, 1),
                                  ReadUnalignedN(Address + 0x1e, 1),
                                  ReadUnalignedN(Address + 0x1f, 1),
                                  ReadUnalignedN(Address + 0x20, 1),
                                  ReadUnalignedN(Address + 0x21, 1),
                                  ReadUnalignedN(Address + 0x22, 1),
                                  ReadUnalignedN(Address + 0x23, 1))
    Protocol = ReadUnalignedN(Address + 0x28, 2)
    ProtocolString = "0x%x" % Protocol
    if Protocol == 0x6:
        ProtocolString = "TCP"
    if Protocol == 0x11:
        ProtocolString = "UDP"
    String += ProtocolString
    Attribute = ",StatefulAutoConfigure"
    if ReadUnalignedN(Address + 0x2a, 1) == 0:
        Attribute = ",Static"
    if ReadUnalignedN(Address + 0x2a, 1) == 1:
        Attribute = ",StatelessAutoConfigure"
    String += Attribute
    String += ",%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x" % (
                                  ReadUnalignedN(Address + 0x4, 1),
                                  ReadUnalignedN(Address + 0x5, 1),
                                  ReadUnalignedN(Address + 0x6, 1),
                                  ReadUnalignedN(Address + 0x7, 1),
                                  ReadUnalignedN(Address + 0x8, 1),
                                  ReadUnalignedN(Address + 0x9, 1),
                                  ReadUnalignedN(Address + 0xa, 1),
                                  ReadUnalignedN(Address + 0xb, 1),
                                  ReadUnalignedN(Address + 0xc, 1),
                                  ReadUnalignedN(Address + 0xd, 1),
                                  ReadUnalignedN(Address + 0xe, 1),
                                  ReadUnalignedN(Address + 0xf, 1),
                                  ReadUnalignedN(Address + 0x10, 1),
                                  ReadUnalignedN(Address + 0x11, 1),
                                  ReadUnalignedN(Address + 0x12, 1),
                                  ReadUnalignedN(Address + 0x13, 1))
    if ReadUnalignedN(Address + 0x2, 2) == 0x3c:
        String += ",0x%x,%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x" % (
                                   ReadUnalignedN(Address + 0x2b, 1),
                                   ReadUnalignedN(Address + 0x2c, 1),
                                   ReadUnalignedN(Address + 0x2d, 1),
                                   ReadUnalignedN(Address + 0x2e, 1),
                                   ReadUnalignedN(Address + 0x2f, 1),
                                   ReadUnalignedN(Address + 0x30, 1),
                                   ReadUnalignedN(Address + 0x31, 1),
                                   ReadUnalignedN(Address + 0x32, 1),
                                   ReadUnalignedN(Address + 0x33, 1),
                                   ReadUnalignedN(Address + 0x34, 1),
                                   ReadUnalignedN(Address + 0x35, 1),
                                   ReadUnalignedN(Address + 0x36, 1),
                                   ReadUnalignedN(Address + 0x37, 1),
                                   ReadUnalignedN(Address + 0x38, 1),
                                   ReadUnalignedN(Address + 0x39, 1),
                                   ReadUnalignedN(Address + 0x3a, 1),
                                   ReadUnalignedN(Address + 0x3b, 1))
    String += ")"
    return String

def Infiniband(Address):
    String = "Infiniband(0x%x," % ReadUnalignedN(Address + 4, 4)
    String += Guid2String(Address + 8)
    String += ",0x%lx,0x%lx,0x%lx)" % (ReadUnalignedN(Address + 24, 8),
                                              ReadUnalignedN(Address + 32, 8),
                                              ReadUnalignedN(Address + 40, 8))
    return String

def Uart(Address):
    String = ""
    Parity = "x"
    if ReadUnalignedN(Address + 0x11, 1) == 0:
        Parity = "D"
    if ReadUnalignedN(Address + 0x11, 1) == 1:
        Parity = "N"
    if ReadUnalignedN(Address + 0x11, 1) == 2:
        Parity = "E"
    if ReadUnalignedN(Address + 0x11, 1) == 3:
        Parity = "O"
    if ReadUnalignedN(Address + 0x11, 1) == 4:
        Parity = "M"
    if ReadUnalignedN(Address + 0x11, 1) == 5:
        Parity = "S"
    if ReadUnalignedN(Address + 0x8, 8) == 0:
        String += "Uart(DEFAULT,"
    else:
        String += "Uart(%ld," % ReadUnalignedN(Address + 0x8, 8)
    if ReadUnalignedN(Address + 0x10, 1) == 0:
        String += "DEFAULT,"
    else:
        String += "%d," % ReadUnalignedN(Address + 0x10, 1)
    String += Parity + ","
    Parity = "x)"
    if ReadUnalignedN(Address + 0x12, 1) == 0:
        Parity = "D)"
    if ReadUnalignedN(Address + 0x12, 1) == 1:
        Parity = "1)"
    if ReadUnalignedN(Address + 0x12, 1) == 2:
        Parity = "1.5)"
    if ReadUnalignedN(Address + 0x12, 1) == 3:
        Parity = "2)"
    String += Parity
    return String

def Iscsi(Address):
    String = "iSCSI("
    #
    # Get iSCSI target name
    #
    TargetNameLen = ReadUnalignedN(Address + 0x2, 2) - 0x12
    idx = 0
    Tmp = Address + 0x12
    while idx < TargetNameLen - 1:
        String += chr(ReadUnalignedN(Tmp, 1))
        Tmp += 0x1
        idx += 0x1
    String += ",0x%x,0x%lx," % (
                       ReadUnalignedN(Address + 0x10, 2),
                       ReadUnalignedN(Address + 0x8, 8))
    Options = ReadUnalignedN(Address + 0x6, 8)
    if ((Options >> 1) & 0x0001) != 0:
        String += "CRC32C,"
    else:
        String += "None,"
    if ((Options >> 3) & 0x0001) != 0:
        String += "CRC32C,"
    else:
        String += "None,"
    Chap = "CHAP_BI,"
    if ((Options >> 11) & 0x0001) != 0:
        Chap = "None,"
    if ((Options >> 12) & 0x0001) != 0:
        Chap = "CHAP_UNI,"
    String += Chap
    if ReadUnalignedN(Address + 0x4, 2) == 0:
        String += "TCP)"
    else:
        String += "reserved)"
    return String

def Vlan(Address):
    return "Vlan(%d)" % ReadUnalignedN(Address + 0x4, 2)

def Bluetooth(Address):
    Address = UdkExtension.ReadMemory(Address + 4, 1, 6)
    return "Bluetooth(%02x:%02x:%02x:%02x:%02x:%02x)" % (
        Address[5], Address[4], Address[3], Address[2], Address[1], Address[0]
        )

def Wifi(Address):
    Ssid = UdkExtension.ReadMemory(Address + 4, 1, 32)
    (SsidStr, Ssid) = AsciiBytesToString(Ssid)
    return "Wifi(%s)" % SsidStr

def Uri(Address):
    Length = ReadUnalignedN(Address + 2, 2)
    UriBytes = UdkExtension.ReadMemory(Address + 4, 1, Length - 4)
    (UriStr, UriBytes) = AsciiBytesToString(UriBytes)
    return "Uri(%s)" % UriStr

def HardDrive(Address):
    String = "0x%lx,0x%lx)" % (ReadUnalignedN(Address + 0x4, 4),
                                    ReadUnalignedN(Address + 0x29, 1))
    if ReadUnalignedN(Address + 0x29, 1) == 1:
        String = "HD(%d,MBR,0x%08x," % (ReadUnalignedN(Address + 0x4, 4), ReadUnalignedN(Address + 0x18, 4))
    if ReadUnalignedN(Address + 0x29, 1) == 2:
        String = "HD(%d,GPT," % ReadUnalignedN(Address + 0x4, 4)
        String += Guid2String(Address + 0x18)
    String += ",0x%lx,0x%lx)" % (ReadUnalignedN(Address + 0x8, 8),
                                       ReadUnalignedN(Address + 0x10, 8))
    return String

def CdRom(Address):
    String = "CDROM(0x%x,0x%lx,0x%lx)" % (ReadUnalignedN(Address + 0x4, 4),
                                                 ReadUnalignedN(Address + 0x8, 8),
                                                 ReadUnalignedN(Address + 0x10, 8))
    return String

def Vendor(Address):
    Type = "?"
    if ReadUnalignedN(Address, 1) == 0x1:
        Type = "Hw"
    if ReadUnalignedN(Address, 1) == 0x3:
        Type = "Msg"
        Guid = UdkExtension.ReadMemory(Address + 0x4, 1, 0x10)
        if Guid == [0x53, 0x47, 0xc1, 0xe0, 0xbe, 0xf9, 0xd2, 0x11, 0x9a, 0x0c, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d]:
            return "VenPcAnsi()"
        if Guid == [0x65, 0x60, 0xa6, 0xdf, 0x19, 0xb4, 0xd3, 0x11, 0x9a, 0x2d, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d]:
            return "VenVt100()"
        if Guid == [0x0b, 0xc7, 0xae, 0x7b, 0xe0, 0x57, 0x76, 0x4c, 0x8e, 0x87, 0x2f, 0x9e, 0x28, 0x08, 0x83, 0x43]:
            return "VenVt100Plus()"
        if Guid == [0xd6, 0xa0, 0x15, 0xad, 0xec, 0x8b, 0xcf, 0x4a, 0xa0, 0x73, 0xd0, 0x1d, 0xe7, 0x7e, 0x2d, 0x88]:
            return "VenUtf8()"
        if Guid == [0x9d, 0x9a, 0x49, 0x37, 0x2f, 0x54, 0x89, 0x4c, 0xa0, 0x26, 0x35, 0xda, 0x14, 0x20, 0x94, 0xe4]:
            FlowControlMap = ReadUnalignedN(Address + 0x14, 4)
            if FlowControlMap & 0x3 == 0:
                FlowControl = "None"
            if FlowControlMap & 0x3 == 1:
                FlowControl = "Hardware"
            if FlowControlMap & 0x3 == 2:
                FlowControl = "XonXoff"
            return "UartFlowCtrl(%s)" % FlowControl
        if Guid == [0xb4, 0xdd, 0x87, 0xd4, 0x8b, 0x00, 0xd9, 0x00, 0xaf, 0xdc, 0x00, 0x10, 0x83, 0xff, 0xca, 0x4d]:
            String = "SAS(0x%x,0x%x,0x%x," % (
                                   ReadUnalignedN(Address + 0x18, 8),
                                   ReadUnalignedN(Address + 0x20, 8),
                                   ReadUnalignedN(Address + 0x2a, 2)
                                   )
            DeviceTopology = ReadUnalignedN(Address + 0x28, 2)
            if (DeviceTopology & 0xf) == 0 and (DeviceTopology & 0x80) == 0:
                String += "NoTopology,0,0,0,"
            elif (DeviceTopology & 0x0f) <= 2 and (DeviceTopology & 0x80) == 0:
                if (DeviceTopology & 0x10) != 0:
                    SasSata = "SATA"
                else:
                    SasSata = "SAS"
                if (DeviceTopology & 0x20) != 0:
                    Location = "External"
                else:
                    Location = "Internal"
                if (DeviceTopology & 0x40) != 0:
                    Connect = "Expanded"
                else:
                    Connect = "Direct"
                if (DeviceTopology & 0x0f) == 1:
                    DriveBay = "0"
                else:
                    DriveBay = "0x%x" % (((DeviceTopology >> 8) & 0xff) + 1)

                String += "%s,%s,%s,%s," % (SasSata, Location, Connect, DriveBay)
            else:
                String += "0x%x,0,0,0," % DeviceTopology
            String += "0x%x)" % ReadUnalignedN(Address + 0x14, 4)
            return String
        if Guid == [0xd2, 0xe8, 0xa4, 0xeb, 0x58, 0x38, 0xec, 0x41, 0xa2, 0x81, 0x26, 0x47, 0xBA, 0x96, 0x60, 0xD0]:
            return "DebugPort()"

    if ReadUnalignedN(Address, 1) == 0x4:
        Type = "Media"

    String = "Ven%s(%s" % (Type, Guid2String(Address + 0x4))
    DataLen = ReadUnalignedN(Address + 2, 2) - 20
    if DataLen != 0:
        String += ","
        for b in UdkExtension.ReadMemory(Address + 20, 1, DataLen):
            String += "%02x" % b
    String += ")"
    return String

def FilePath(Address):
    Length = ReadUnalignedN(Address + 2, 2)
    PathName = UdkExtension.ReadMemory(Address + 4, 1, Length - 4)
    (PathNameStr, PathName) = UnicodeBytesToString(PathName)
    return PathNameStr

def MediaProtocol(Address):
    String = "Media" + "(" + Guid2String(Address + 4) + ")"
    return String

def Fv(Address):
    String = "Fv" + "(" + Guid2String(Address + 4) + ")"
    return String

def FvFile(Address):
    String = "FvFile" + "(" + Guid2String(Address + 4) + ")"
    return String

def RelativeOffset(Address):
    return "Offset(0x%lx,0x%lx)" % (
        ReadUnalignedN(Address + 8, 8),
        ReadUnalignedN(Address + 16, 8))

def Bbs(Address):
    Type = ReadUnalignedN(Address + 4, 2)
    if Type == 1:
        TypeStr = "Floppy"
    elif Type == 2:
        TypeStr = "HD"
    elif Type == 3:
        TypeStr = "CDROM"
    elif Type == 4:
        TypeStr = "PCMCIA"
    elif Type == 5:
        TypeStr = "USB"
    elif Type == 6:
        TypeStr = "Network"
    else:
        TypeStr = ""

    if TypeStr != "":
        String = "BBS(%s," % TypeStr
    else:
        String = "BBS(0x%x," % Type

    Length = ReadUnalignedN(Address + 2, 2)
    Description = UdkExtension.ReadMemory(Address + 8, 1, Length - 8)
    (DescriptionStr, Description) = AsciiBytesToString(Description)
    String += "%s,0x%x)" % (DescriptionStr, ReadUnalignedN(Address + 6, 2))
    return String

ToText = {
    #
    # Hardware device path
    #
    (0x1, 0x1):Pci,            (0x1, 0x2):PcCard,
    (0x1, 0x3):MemMap,         (0x1, 0x4):Vendor,
    (0x1, 0x5):Controller,
    #
    # ACPI device path
    #
    (0x2, 0x1):Acpi,           (0x2,0x2):AcpiEx,
    (0x2, 0x3):AcpiAdr,
    #
    # Messaging device path
    #
    (0x3, 0x1):Atapi,          (0x3, 0x2):Scsi,
    (0x3, 0x3):Fibre,          (0x3, 0x4):I1394,
    (0x3, 0x5):Usb,            (0x3, 0x6):I2o,
    (0x3, 0x9):Infiniband,     (0x3, 0xa):Vendor,
    (0x3, 0xb):Mac,            (0x3, 0xc):Ipv4,
    (0x3, 0xd):Ipv6,           (0x3, 0xe):Uart,
    (0x3, 0xf):UsbClass,       (0x3, 0x10):UsbWwid,
    (0x3, 0x11):Unit,          (0x3, 0x12):Sata,
    (0x3, 0x13):Iscsi,         (0x3, 0x14):Vlan,
    (0x3, 0x15):FibreEx,       (0x3, 0x16):SasEx,
    (0x3, 0x17):NVMe,          (0x3, 0x18):Uri,
    (0x3, 0x19):Ufs,           (0x3, 0x1a):Sd,
    (0x3, 0x1b):Bluetooth,     (0x3, 0x1c):Wifi,
    #
    # Media device path
    #
    (0x4, 0x1):HardDrive,      (0x4, 0x2):CdRom,
    (0x4, 0x3):Vendor,         (0x4, 0x4):FilePath,
    (0x4, 0x5):MediaProtocol,  (0x4, 0x6):FvFile,
    (0x4, 0x7):Fv,             (0x4, 0x8):RelativeOffset,
    #
    # Bbs device path
    #
    (0x5, 0x1):Bbs,
    }

ToTextGeneric = { 0x1:"HardwarePath", 0x2:"AcpiPath", 0x3:"Msg", 0x4:"MediaPath", 0x5:"BbsPath" }

def Generic(Address):
    Header = ReadUnalignedN(Address, 4)
    Type = DevicePathType(Header)
    SubType = DevicePathSubType(Header)
    if Type in ToTextGeneric:
        String = "%s(%d," % (ToTextGeneric[Type], SubType)
    else:
        String = "Path(%d,%d," % (Type, SubType)
    for Data in UdkExtension.ReadMemory(Address + 4, 1, DevicePathNodeLength(Header) - 4):
        String += "%02x" % Data
    String += ")"
    return String

def DevicePathNodeLength(Header):
    return Header >> 0x10

def DevicePathType(Header):
    return Header & 0xff

def DevicePathSubType(Header):
    return (Header & 0xff00) >> 0x8

def invoke(arg):
    """
ShowEfiDevicePath - Convert device path to text.
Arguments:           DevicePath
  DevicePath  The start address of device path.
"""
    MaxNodeCount = 0x100
    gDebugOn = 0
    args = []
    for _arg in arg.split(' '):
        if _arg != '':
            args.append(_arg)
    if len(args) == 0:
        print("ERROR: Device path address is required.")
        return()

    Address = int(args[0], 0)
    Text = ""
    while True:
        Header = ReadUnalignedN(Address, 4)
        Type = DevicePathType(Header)
        SubType = DevicePathSubType(Header)
        Length = DevicePathNodeLength(Header)
        MaxNodeCount = MaxNodeCount - 1
        if Header == 0xffffffff or MaxNodeCount == 0 or Length < 4:
            print("ERROR: Device path address is invalid!")
            return
        if gDebugOn:
            print("Header(%x) = (%d,%d,%x)" % (Address, Type, SubType, Length))
        Key = (Type, SubType)
        if Key in ToText:
            Text += "%s/" % ToText[Key](Address)
        elif Key == (0x7f, 0x1) or Key == (0x7f, 0xff):
            Text = Text[:-1] + "\n"
            if Key[1] == 0xff:
                break
        else:
            Text += Generic(Address)
        Address += Length
    print(Text, end=' ')
