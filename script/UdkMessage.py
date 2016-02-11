#
# This file contains an 'Intel Peripheral Driver' and is
# licensed for Intel CPUs and chipsets under the terms of your
# license agreement with Intel or your vendor.  This file may
# be modified by the user, subject to additional terms of the
# license agreement
#
# Copyright (c) 2012 - 2015, Intel Corporation. All rights reserved.<BR>
#
#   This software and associated documentation (if any) is furnished
#   under a license and may only be used or copied in accordance
#   with the terms of the license. Except as permitted by such
#   license, no part of this software or documentation may be
#   reproduced, stored in a retrieval system, or transmitted in any
#   form or by any means without the express written consent of
#   Intel Corporation.

SCRIPT_BANNER_BEGIN = "##############################################################\n# This GDB configuration file contains settings and scripts\n# for debugging UDK firmware."
SUPPORT_PENDING_BREAKPOINTS = "# Setting pending breakpoints is supported by the GDB."
NOT_SUPPORT_PENDING_BREAKPOINTS = "# WARNING: Setting pending breakpoints is NOT supported by the GDB!"
GDBSERVER_NOT_CONNECTED = "# ERROR: GdbServer is not connected\n# Load this file after connecting to GdbServer"
SCRIPT_BANNER_END = "##############################################################"

ARGUMENT_TOO_FEW = "Incorrect usage. There are too few arguments in command"
ARGUMENT_TOO_MANY = "Incorrect usage. There are too many arguments in command"
ARGUMENT_INVALID_SUBINDEX = "invalid subindex parameter"
ARGUMENT_INVALID_INDEX = "invalid index parameter"
ARGUMENT_INVALID_SIZE = "invalid size parameter"
ARGUMENT_INVALID_PORT = "invalid port parameter"
ARGUMENT_MUST_BE_NUMBER_1_BASED = "The argument must be a number (1-based)"
ARGUMENT_1_TO_20_EXPECTED = "an integer from 1 to 20 is expected."
ARGUMENT_ON_OFF_EXPECTED = 'either an "on" or "off" expected.'
ARGUMENT_HEX_EXPECTED = "a hex address is expected."
IO_FAILURE = "Unexpected IO port access error."

CPUID_INPUT = "INDEX: %08x  SUBINDEX: %08x"
CPUID_OUTPUT = "EAX: %08x  EBX: %08x  ECX: %08x  EDX: %08x"
FAILED_TO_EXECUTE_COMMAND = "Unable to execute command: %s"
IO_WATCH_POINT_INFO = "IO Watchpoint %d: %X(%x)"
SETTING_PATH_MAPPING = "Set path mapping: `%s' -> `%s'"
EXCEPTION_INFO = "Target encountered an exception: Vector = %d, Error Code = %08x"
TARGET_IS_RUNNING_AFTER_RESET = "TARGET is resetting, continue running..."
LOADING_SYMBOL = "Loading symbol for address: 0x%x"
LOADING_SYMBOL_FOR_MODULE = "Loading symbol at address %s for %s"
SKIPPING_SYMBOL_FOR_MODULE = "Skipping symbol at address %s for %s"
UNSUPPORTED_DEBUG_INFORMATION = "Unsupported debug information found: PDB format"
MISSING_DEBUG_INFORMATION = "Missing debug information"
FAILED_TO_FIND_SYMBOL_FILE = "Unable to find the debug symbol file."
FAILED_TO_LOAD_SYMBOL = "Unable to load symbol file"
FAILED_TO_FIND_DEBUG_INFORMATION = "Unable to find the debug information for source level debugging."
FAILED_TO_LOCATE_FUNCTION = "Unable to locate function '%s()' in module '%s'."
EXECUTION_TIME = "Execution time: %s."
