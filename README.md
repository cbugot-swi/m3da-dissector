m3da-dissector
==============

Wireshark M3DA dissector

This is a very first shot at writing an M3DA dissector, partially in Lua, for Wireshark.
 

To use it you need to build it you need to have Lua headers files installed on your machine.

Once compiled you can run it by running:
> wireshark -X lua_script:m3da-dissector/dissector.lua m3da-dissector/test1.pcapng


It's licensed under the term of the Eclipse Public License - v 1.0. See the LICENSE-EPLv1.0.html at the root of the repository.

The binary deserializer and a couple of Lua utilities where extraced from the Mihini project: http://www.eclipse.org/mihini
