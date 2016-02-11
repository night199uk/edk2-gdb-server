#++
#
#Copyright (c) 2013 - 2014 Intel Corporation. All rights reserved
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
#  mmio.py
#
#Abstract:
#
#  Access the memory mapped IO space.
#
#--
from __future__ import print_function
import UdkExtension

def invoke(arg):
    """
mmio - Access the memory mapped IO space.
Arguments: Address Width [Value]
  Address       MMIO address to access.
  Width         Access width: 1, 2, 4 or 8.
  Value         Content to write to the MMIO address.
"""
    args = []
    for _arg in arg.split(' '):
        if _arg != '':
            args.append(_arg)

    args = [int(v, 16) for v in args]
    if (len(args) not in [2, 3]) or (args[1] not in [1, 2, 4, 8]) or ((args[0] & (args[1] - 1)) != 0):
        print("ERROR: Invalid parameter")
        return
    Address = args[0]
    Width   = args[1]
    if len(args) == 2:
        Value = UdkExtension.ReadMemory(Address, Width, 1)
        if Value is not None:
            print("%0*x" % (2 * Width, Value[0]))
        else:
            print("ERROR: failed to read memory.")
    else:
        Value = args[2]
        if not UdkExtension.WriteMemory(Address, Width, [Value]):
            print("ERROR: failed to write memory.")
