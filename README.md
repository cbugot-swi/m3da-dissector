m3da-dissector
==============

Wireshark M3DA dissector


This is a very first shot at writing an M3DA dissector, partially in Lua, for Wireshark.
 

# Linux build isntructions

To use it you need to build it you need to have Lua headers files installed on your machine.
On Debian/Ubuntu you can run:
> sudo apt-get install build-essential liblua5.1-0-dev

Build the dissector:
> make

# Windows builds tips
These are just tips since there is not uniform way to build on Window. I did manage to build it
on a Widows7+MinGW.
Tips:
   - Use MinGW+MSYS.
   - Download Lua 5.1 sources and compile it with mingw target (I had to rename
     the ddl lua51.dll into lua5.1.dll as WireShark use that name)
   - Build the checks.dll and bysant.dll (need to change the makefile a bit)
   - Copy the dll into the WireShark directory
   - Then it worked (for me)
If anybody cares to provide cleaner/more detailed instructions for Windows I am happy to take
in the changes!




# Use the dissector
Once compiled you can run it by running:
> wireshark -X lua_script:dissector.lua test1.pcapng






It's licensed under the term of the Eclipse Public License - v 1.0. See the LICENSE file at the root of the repository.

The binary deserializer and a couple of Lua utilities where extraced from the Mihini project: http://www.eclipse.org/mihini
