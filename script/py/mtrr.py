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
#  mtrr.py
#
#Abstract:
#
#  dump the MTRR setting of current processor.
#
#--
from __future__ import print_function
import UdkExtension

def memory_type (MemType):
  # 
  #  Encoding in MTRR       Memory type and mnemonic
  #-------------------     --------------------------
  #      00h                     Uncacheable (UC)
  #      01h                     Write Combining (WC)
  #      02h                     Reserved
  #      03h                     Reserved
  #      04h                     Write-through (WT)
  #      05h                     Write-protected (WP)
  #      06h                     Writeback (WB)
  #      07h-FFh                 Reserved
  #
  memory_type_dict = {
      0: "UC",
      1: "WC",
      4: "WT",
      5: "WP",
      6: "WB"
      }
  try:
    return memory_type_dict[MemType]
  except:
    return "Reserved"

def dump_mtrr(start, end, base, step):
  Address = base
  for msr in range(start, end):
    msr_xxx = UdkExtension.ReadMsr(msr)
    for Index in range(8):
      print("  %05x - %05x: %s" % (Address, Address + step - 1, memory_type((msr_xxx >> (Index * 8)) & 0xff)))
      Address += step


def invoke(arg):
  """mtrr - dump the MTRR setting of current processor
"""
  msr_2ff = UdkExtension.ReadMsr(0x2ff)
  print("IA32_MTRR_DEF_TYPE (0x2ff) : %016x" % msr_2ff)
  if msr_2ff & (1 << 11):
    print("                     MTRR  : enabled")
  else:
    print("                     MTRR  : disabled")
  if msr_2ff & (1 << 10):
    print("         Fixed-range MTRRs : enabled")
  else:
    print("         Fixed-range MTRRs : disabled")
  print("       Default Memory Type : %s" % memory_type(msr_2ff & 0xff))

  if (msr_2ff & (1 << 11)) == 0:
    return
  
  if msr_2ff & (1 << 10):
    print("\n\nFixed range MTRR")
    print("---------------------")

    print("IA32_MTRR_FIX64K (0x250):")
    dump_mtrr(0x250, 0x251, 0, 0x10000)

    print("\nIA32_MTRR_FIX16K (0x258-0x259):")
    dump_mtrr(0x258, 0x25a, 0x80000, 0x4000)
    
    print("\nIA32_MTRR_FIX4K (0x268-0x26f):")
    dump_mtrr(0x268, 0x270, 0xC0000, 0x1000)

  print("\nVariable range MTRR")
  print("---------------------")
  for msr in range(0x200, 0x210, 2):
    print("  MTRR %04x:" % msr)

    msr_yyy = UdkExtension.ReadMsr(msr+1)
    if msr_yyy & (1 << 11):
      # 
      # This MTRR is valid
      #
      msr_xxx = UdkExtension.ReadMsr(msr)
      Base = msr_xxx >> 12
      Mask = msr_yyy >> 12
      Mask |= 0xff000000
      Mask = ~Mask
      Mask &= 0xffffffff
      Mask += 1

      print("  %08x - %08x: %s (%4d MB)" % (Base << 12, ((Base + Mask) << 12) - 1, memory_type(msr_xxx & 0xff), Mask >> 8))
    else:
      print("  Invalid")
    print("")
