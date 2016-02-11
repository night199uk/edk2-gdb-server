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
#  pci.py
#
#Abstract:
#
#  Display PCI device list or PCI function configuration space.
#
#--
from __future__ import print_function
import UdkExtension

def __read_pci_conf(bus, dev, func, reg, size):
    if not (bus in range (256) and dev in range (32) and func in range (8)):
        return None
    if not size in [1, 2, 4]:
        return None
    if not (reg + size - 1) in range (256):
        return None
    if (reg & (size - 1)) != 0:
        return None

    cfg_addr = (1 << 31) + (bus << 16) + (dev << 11) + (func << 8) + (reg & ~3)
    UdkExtension.WriteIo (0xcf8, 4, cfg_addr)
    cfg_data = UdkExtension.ReadIo (0xcfc + (reg & 3), size)
    return cfg_data

def __get_device_class(base_class_code, sub_class_code, prog_interface):
    class_dic = {
        # list not complete. can be updated if needed.
        (0,    0,    0)   :"Backward compatible device",
        (0,    1,    0)   :"VGA-compatible device",

        (1,    0,    0)   :"SCSI bus controller",
        (1,    1,    0)   :"IDE controller",
        (1,    2,    0)   :"Floppy disk controller",
        (1,    3,    0)   :"IPI bus controller",
        (1,    4,    0)   :"RAID controller",
        (1,    5, 0x20)   :"ATA controller with ADMA interface - single stepping",
        (1,    5, 0x30)   :"ATA controller with ADMA interface - continuous operation",
        (1,    6,    0)   :"Serial ATA controller - vendor specific interface",
        (1,    6,    1)   :"Serial ATA controller - AHCI 1.0 interface",
        (1,    6,    2)   :"Serial Storage Bus Interface",
        (1,    7,    0)   :"Serial Attached SCSI (SAS) controller",
        (1,    7,    1)   :"Serial Storage Bus Interface",
        (1,    8,    0)   :"Solid State Storage Controller",
        (1,    8,    1)   :"Solid State Storage Controller - NVMHCI 1.0 interface",
        (1,    8,    2)   :"Solid State Storage Controller - Enterprise NVMHCI 1.0",
        (1,    0x80, 0)   :"Other mass storage controller",

        (2,    0,    0)   :"Ethernet controller",
        (2,    1,    0)   :"Token Ring controller",
        (2,    2,    0)   :"FDDI controller",
        (2,    3,    0)   :"ATM controller",
        (2,    4,    0)   :"ISDN controller",
        (2,    5,    0)   :"WorldFip controller",
        (2,    6,    0)   :"PICMG 2.14 Multi Computing",
        (2,    7,    0)   :"InfiniBand* Controller",
        (2,    0x80, 0)   :"Other network controller",

        (3,    0,    0)   :"VGA-compatible controller",
        (3,    0,    1)   :"8514-compatible controller",
        (3,    1,    0)   :"XGA controller",
        (3,    2,    0)   :"3D controller",
        (3,    0x80, 0)   :"Other display controller",

        (4,    0,    0)   :"Video device",
        (4,    1,    0)   :"Audio device",
        (4,    2,    0)   :"Computer telephony device",
        (4,    3,    0)   :"Mixed mode device",
        (4,    0x80, 0)   :"Other multimedia device",

        (5,    0,    0)   :"RAM",
        (5,    1,    0)   :"Flash",
        (5,    0x80, 0)   :"Other memory controller",

        (6,    0,    0)   :"Host bridge",
        (6,    1,    0)   :"ISA bridge",
        (6,    2,    0)   :"EISA bridge",
        (6,    3,    0)   :"MCA bridge",
        (6,    4,    0)   :"PCI-to-PCI bridge",
        (6,    4,    1)   :"Subtractive Decode PCI-to-PCI bridge",
        (6,    5,    0)   :"PCMCIA bridge",
        (6,    6,    0)   :"NuBus bridge",
        (6,    7,    0)   :"CardBus bridge",
        (6,    8,    0)   :"RACEway bridge",
        (6,    9, 0x40)   :"Semi-transparent PCI-to-PCI bridge with the primary PCI bus side facing the system host processor",
        (6,    9, 0x80)   :"Semi-transparent PCI-to-PCI bridge with the secondary PCI bus side facing the system host processor",
        (6,    0xA,  0)   :"InfiniBand-to-PCI host bridge",
        (6,    0xB,  0)   :"Advanced Switching to PCI host bridge - Custom Interface",
        (6,    0xB,  1)   :"Advanced Switching to PCI host bridge - ASI-SIG Defined Portal Interface",
        (6,    0x80, 0)   :"Other bridge device",

        (7,    0x80, 0)   :"Other communications device",

        (0xc,  3,    0)   :"UHCI controller",
        (0xc,  3,    0x10):"OHCI controller",
        (0xc,  3,    0x20):"EHCI controller",
        (0xc,  3,    0xFE):"USB device",
        (0xc,  4,    0)   :"Fibre Channel",
        (0xc,  5,    0)   :"SMBus (System Management Bus)",
        (0xc,  6,    0)   :"InfiniBand (deprecated)",
        (0xc,  7,    0)   :"IPMI SMIC Interface",
        (0xc,  7,    1)   :"IPMI Keyboard Controller Style Interface",
        (0xc,  7,    2)   :"IPMI Block Transfer Interface",
        (0xc,  8,    0)   :"SERCOS Interface Standard (IEC 61491)",
        (0xc,  9,    0)   :"CANbus",
        (0xc,  0x80, 0)   :"Other Serial Bus Controllers",

        (0xd,  0,    0)   :"iRDA compatible controller",
        (0xd,  1,    0)   :"Consumer IR controller",
        (0xd,  1, 0x10)   :"UWB Radio controller ",
        (0xd,  0x10, 0)   :"RF controller",
        (0xd,  0x11, 0)   :"Bluetooth",
        (0xd,  0x12, 0)   :"Broadband",
        (0xd,  0x20, 0)   :"Ethernet (802.11a - 5 GHz)",
        (0xd,  0x21, 0)   :"Ethernet (802.11b - 2.4 GHz)",
        (0xd,  0x80, 0)   :"Other type of wireless controller",

        (0x10, 0,    0)   :"Network and computing en/decryption",
        (0x10, 0x10, 0)   :"Entertainment en/decryption",
        (0x10, 0x80, 0)   :"Other en/decryption",

        (0x11, 0,    0)   :"DPIO modules",
        (0x11, 1,    0)   :"Performance counters",
        (0x11, 0x80, 0)   :"Other data acquisition/signal processing controllers",

        (0x12, 0,    0)   :"Processing Accelerator - vendor-specific interface"
        }

    if (base_class_code == 1 and sub_class_code == 1) or \
       (base_class_code == 2 and sub_class_code == 6) or \
       (base_class_code == 6 and sub_class_code == 8):
        prog_interface = 0
    if (base_class_code, sub_class_code, prog_interface) in class_dic:
        return class_dic[(base_class_code, sub_class_code, prog_interface)]
    else:
        return "Unkown device class (Base:%02x Sub:%02x PI:%02x)" % (base_class_code, sub_class_code, prog_interface)

def __enum_pci_bus(bus):
    for dev in range (32):
        for func in range (8):
            # Detect the presence of the PCI device
            vendor_id = __read_pci_conf(bus, dev, func, 0, 2)
            if vendor_id == 0xffff:
                if func == 0:
                    break
            else:
                device_id = __read_pci_conf(bus, dev, func, 2, 2)
                base_class_code = __read_pci_conf(bus, dev, func, 0xb, 1)
                sub_class_code = __read_pci_conf(bus, dev, func, 0xa, 1)
                prog_interface = __read_pci_conf(bus, dev, func, 9, 1)
                header_type = __read_pci_conf(bus, dev, func, 0xe, 1)

                print("%02x  %02x  %1x    %04x   %04x   %s" % (bus, dev, func, vendor_id, device_id, __get_device_class(base_class_code, sub_class_code, prog_interface)))

                # Enumerate the PCI bus recursively if the PCI device is P2P bridge
                if (header_type & 0x7f) == 1:
                    secondary_bus = __read_pci_conf(bus, dev, func, 0x19, 1)
                    if secondary_bus > bus:
                        __enum_pci_bus (secondary_bus)
                if func == 0 and (header_type & 0x80) == 0:
                    break

def __dump_pci_conf(bus, dev, func):
    print("Dump PCI configuration space for Bus %02x Device %02x Function %02x" % (bus, dev, func))
    print("     00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F")
    print("     -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --")

    reg = 0
    for line in range (0x10):
        print("%02x: " % (line * 0x10), end=' ')
        for index in range (0x10):
            value = __read_pci_conf(bus, dev, func, reg, 1)
            print("%02x" % value, end=' ')
            reg = reg + 1
        print()

def invoke(arg):
    """
pci - Display PCI device list or PCI function configuration space.
Arguments: [Bus [Dev [Func]]]
  Bus           When only Bus is specified, it is the starting bus number for
                enumeration. 0 by default if not specified.
                Otherwise the bus number of the PCI device whose configuration
                space is to be dumped.
  Dev           Device number of the PCI device whose configuration space is
                to be dumped.
  Func          Function number of the PCI device whose configuration space
                is to be dumped. 0 by default if not specified.
"""
    args = []
    for _arg in arg.split(' '):
        if _arg != '':
            args.append(_arg)

    if len(args) in range(2):
        # Display PCI device list
        if len(args) == 0:
            bus = 0
        else:
            bus = int(args[0], 0)

        if not bus in range(256):
            print("Invalid bus number")
            return
        print("Bus Dev Func Vendor Device Class")
        print("--- --- ---- ------ ------ -----")
        __enum_pci_bus(bus)
        return
    
    # Dump PCI function configuration space
    bus = int(args[0], 0)
    dev = int(args[1], 0)
    if len(args) == 2:
        func = 0
    else:
        func = int(args[2], 0)

    if not bus in range(256):
        print("Invalid bus number")
        return
    if not dev in range(32):
        print("Invalid device number")
        return
    if not func in range(8):
        print("Invalid function number")
        return

    __dump_pci_conf(bus, dev, func)

