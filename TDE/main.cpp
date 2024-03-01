#include "oreans_entry.hpp"
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <allins.hpp>

int __stdcall IDAPInitialize() {
    if (inf.filetype != f_PE) {
        warning("Only supports PE binaries.");
        return PLUGIN_SKIP;
    } else if (strncmp(inf.procName, "metapc", 8) != 0) {
        warning("Only supports x86 (for now).");
        return PLUGIN_SKIP;
    }
    return PLUGIN_KEEP;
}

void __stdcall IDAPTerminate() {
    /* There's nothing to clean up here */
}

void __stdcall IDAPRun(int arg) {
    ea_t address = get_screen_ea();
    msg("rying to devirtualize at address %08X...\n", address);
    decode_insn(address);

    if (cmd.itype != NN_jmp && cmd.itype != NN_call)
        msg("Instruction not an immediate jump or call.\n", address);
    else if (!cmd.Operands[0].addr)
        msg("Instruction doesn't point to an address.\n", address);
    else if (!isCode(get_flags_novalue(cmd.Operands[0].addr)))
        msg("The selected function entry is not executable code.");
    else if (!oreans_entry::get().tryDevirtualize(address, cmd.Operands[0].addr))
        msg("Failed to devirtualize function at %08X.\n", address);
    else
        msg("Successfully devirtualized function at %08X.\n", address);
}

plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,     // IDA version plug-in is written for
    0,                          // Flags (see below)
    IDAPInitialize,             // Initialisation function
    IDAPTerminate,              // Clean-up function
    IDAPRun,                    // Main plug-in body
    "This is my test plug-in",  // Comment – unused
    "CodeDevirtualizer",        // Help – unused
    "CodeDevirtualizer",        // Plug-in name shown in Edit->Plugins menu
    "Alt-F"                     // Hot key to run the plug-in
};
