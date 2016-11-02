# edk2-gdb-server
License: Credit me if you use it.

This is a open code replacement for Intel's binary only GDB server that
comes as part of the 'Intel UEFI Development Kit Debugger Tool'. Since
that tool is Intel x86/64 Linux/Windows only this allows more flexibility.

E.g. you can run this on any ARM based SoC with python3 and a USB OTG
port connected directly to your target via a USB2.0 EHCI Debug port using
the Linux USB OTG Debug Port gadget. You can then connect to that target
remotely from your build box, etc.

This also allows you to tweak the debugger itself. I've already added some
additional functionality here to assist when using SourceLevelDebugPkg
on non-EDK2 (i.e. no source available) firmwares such as AMI Aptio IV.

Combined with the gdb-symbol-maker here:
https://github.com/night199uk/gdb-symbol-maker

This will allow you to do rudimentary Source Level Debugging on firmwares
you don't have the source code for.

Using this:
1) Modify SourceLevelDebugPkg/Include/TransferProtocol.h

    Change:
    #define DEBUG_AGENT_REVISION            DEBUG_AGENT_REVISION_04

    To:
    #define DEBUG_AGENT_REVISION            DEBUG_AGENT_REVISION_03

This is to disable Compression, which we don't support (yet).

You will also need to set up SourceLevelDebugPkg as you need for your
target.  I have successfully used SourceLevelDebugPkg using both USB2
and Serial.  USB2 (EHCI Debug) is a little complex, but unlike much FUD
on the internet, it does work fine.

2) Include SourceLevelDebugPkg in your build by including the .inf 
   in your .dsc and .fdf.
or
2) Build a DebugAgentDxe.ffs manually and use e.g. UEFITool or MMTool
   to inject it into your BIOS (e.g. AMI, Phoenix, etc).

3) Edit the serial port / PTS specified in server.py to point to your
   serial port, CDC ACM device (USB2 Debug Gadget/EHCI Dongle, etc) or
   PseudoTTY (OvmfPkg/qemu).

4) Run:
   ./server.py

5) Reboot your target. The gdb server only starts listening after it
   succesfully handshakes with the target.

6) Build a working GDB on your debug host EDK2 (build box, etc):
   You will need to use --target x86_64-w64-mingw32 when configuring GDB.

7) Connect remotely from your host (build box) using gdb:
   target remote x.x.x.x:1234


Enjoy debugging UEFI.


