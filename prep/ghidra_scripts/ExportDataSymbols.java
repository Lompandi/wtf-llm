// Export global data symbols with their sizes and bounds (snapfuzz CP7).
//
// WHY THIS EXISTS. Decompiled pseudo-C states the bound of a loop over a global
// array as a *symbol*, not a count:
//
//     puVar11 = ChunkList;
//     pp_Var9 = &__dyn_tls_dtor_callback;
//     do { ... } while (puVar11 != pp_Var9);
//
// A human reverse-engineer reads the capacity straight off Ghidra's listing --
// two addresses, an element size, one division. An LLM given only the pseudo-C
// cannot, because the fact was dropped in decompilation. CP7 measured the
// consequence: seed generation correctly worked out that the branch needed the
// table exhausted, then guessed at how full "full" was -- ChunkList holds four
// pointers, the fifth write lands past the end, and only the sixth packet reads
// that value back, which is what the branch tests (D-047).
//
// This is CLAUDE.md Contribution 2 in miniature -- Ghidra supplying the static
// facts the LLM's reasoning needs -- and it is not the answer to any particular
// branch: it is the same table of addresses, names and sizes a human would look
// at, for every global the program has.
//
// Written in Java for the same reason as ExportBasicBlocks.java: analyzeHeadless
// cannot start PyGhidra on a stock Ghidra 12 install (D-025).
//
// Args: <output.json> [scope] [entry]
//   scope = module           -- every global data symbol (default)
//   scope = function-closure -- only globals REFERENCED from the call closure of
//                               <entry>, which is what a prompt should carry
//   entry = a symbol name, or an address as 0x...
//
//@category snapfuzz
import java.io.PrintWriter;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolType;

public class ExportDataSymbols extends GhidraScript {

    // One global's static facts.
    private static class Datum {
        String name;
        long staticAddr;
        long rva;
        long size;          // bytes, from Ghidra's applied data type; 0 if unknown
        String type;        // data type name, or null
        String block;       // memory block (.data, .bss, ...)
        boolean referencedFromScope;
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            throw new IllegalArgumentException(
                "usage: ExportDataSymbols <output.json> [module|function-closure] [entry]");
        }

        String outputPath = args[0];
        String scope = args.length > 1 ? args[1] : "module";
        String entryArg = args.length > 2 ? args[2] : null;

        long imageBase = currentProgram.getImageBase().getOffset();

        String moduleName = currentProgram.getName();
        int dot = moduleName.lastIndexOf('.');
        if (dot > 0) {
            moduleName = moduleName.substring(0, dot);
        }

        // Which globals the closure touches. Collected even in module scope, so a
        // consumer can rank "referenced by the code we care about" first without
        // a second run.
        Set<Long> referenced = new HashSet<>();
        String entryResolved = null;
        if (entryArg != null) {
            Function entry = resolveEntry(entryArg);
            if (entry == null) {
                throw new IllegalArgumentException("could not resolve entry: " + entryArg);
            }
            entryResolved = entry.getName();
            for (Function function : closureOf(entry)) {
                collectReferencedAddresses(function, referenced);
            }
        } else if (scope.equals("function-closure") || scope.equals("closure")) {
            throw new IllegalArgumentException("function-closure scope requires an entry");
        }

        boolean closureOnly = scope.equals("function-closure") || scope.equals("closure");

        List<Datum> data = new ArrayList<>();
        SymbolIterator symbols = currentProgram.getSymbolTable().getAllSymbols(true);
        while (symbols.hasNext()) {
            if (monitor.isCancelled()) {
                break;
            }
            Symbol symbol = symbols.next();
            SymbolType type = symbol.getSymbolType();
            if (type != SymbolType.LABEL && type != SymbolType.GLOBAL_VAR) {
                continue;
            }
            Address address = symbol.getAddress();
            if (address == null || !address.isMemoryAddress()) {
                continue;
            }

            // Data, not code. A LABEL inside a function body is a jump target.
            MemoryBlock block = currentProgram.getMemory().getBlock(address);
            if (block == null || block.isExecute()) {
                continue;
            }

            long offset = address.getOffset();
            boolean isReferenced = referenced.contains(offset);
            if (closureOnly && !isReferenced) {
                continue;
            }

            Datum datum = new Datum();
            datum.name = symbol.getName();
            datum.staticAddr = offset;
            datum.rva = offset - imageBase;
            datum.block = block.getName();
            datum.referencedFromScope = isReferenced;

            Data applied = getDataAt(address);
            if (applied != null) {
                datum.size = applied.getLength();
                DataType dt = applied.getDataType();
                datum.type = dt != null ? dt.getDisplayName() : null;
            } else {
                datum.size = 0;
                datum.type = null;
            }
            data.add(datum);
        }

        data.sort(Comparator.comparingLong(d -> d.staticAddr));

        // The span to the NEXT symbol. This is the number that answers "how many
        // elements does this table hold" when no array type was applied -- which
        // is the normal case in a stripped binary, and exactly the situation
        // where the pseudo-C shows the bound as some unrelated adjacent symbol.
        long[] spans = new long[data.size()];
        for (int i = 0; i < data.size(); i++) {
            spans[i] = i + 1 < data.size()
                ? data.get(i + 1).staticAddr - data.get(i).staticAddr
                : 0;
        }

        try (PrintWriter out = new PrintWriter(outputPath, "UTF-8")) {
            out.println("{");
            out.println("  \"module\": \"" + escape(moduleName) + "\",");
            out.println("  \"image_base\": " + imageBase + ",");
            out.println("  \"scope\": \"" + escape(scope) + "\",");
            out.println("  \"entry\": " + (entryResolved == null
                ? "null" : "\"" + escape(entryResolved) + "\"") + ",");
            out.println("  \"symbols\": [");
            for (int i = 0; i < data.size(); i++) {
                Datum d = data.get(i);
                out.print("    {");
                out.print("\"name\": \"" + escape(d.name) + "\", ");
                out.print("\"static_addr\": " + d.staticAddr + ", ");
                out.print("\"rva\": " + d.rva + ", ");
                out.print("\"size\": " + d.size + ", ");
                out.print("\"span_to_next\": " + spans[i] + ", ");
                out.print("\"type\": " + (d.type == null
                    ? "null" : "\"" + escape(d.type) + "\"") + ", ");
                out.print("\"block\": \"" + escape(d.block) + "\", ");
                out.print("\"referenced_from_scope\": " + d.referencedFromScope);
                out.println(i + 1 < data.size() ? "}," : "}");
            }
            out.println("  ]");
            out.println("}");
        }

        println("ExportDataSymbols: wrote " + data.size() + " symbols to " + outputPath);
    }

    // Every global address any instruction in the function refers to.
    private void collectReferencedAddresses(Function function, Set<Long> into) {
        for (Instruction instruction :
                currentProgram.getListing().getInstructions(function.getBody(), true)) {
            for (Reference reference : instruction.getReferencesFrom()) {
                Address to = reference.getToAddress();
                if (to != null && to.isMemoryAddress()) {
                    into.add(to.getOffset());
                }
            }
        }
    }

    private Set<Function> closureOf(Function entry) {
        Set<Function> seen = new LinkedHashSet<>();
        Deque<Function> queue = new ArrayDeque<>();
        queue.add(entry);
        while (!queue.isEmpty()) {
            Function function = queue.poll();
            if (function == null || function.isExternal() || !seen.add(function)) {
                continue;
            }
            for (Function callee : function.getCalledFunctions(monitor)) {
                if (!seen.contains(callee)) {
                    queue.add(callee);
                }
            }
        }
        return seen;
    }

    private Function resolveEntry(String arg) {
        if (arg.startsWith("0x") || arg.startsWith("0X")) {
            Address address = currentProgram.getAddressFactory()
                .getDefaultAddressSpace()
                .getAddress(Long.parseLong(arg.substring(2), 16));
            return getFunctionAt(address);
        }
        for (Symbol symbol : currentProgram.getSymbolTable().getGlobalSymbols(arg)) {
            Function function = getFunctionAt(symbol.getAddress());
            if (function != null) {
                return function;
            }
        }
        return null;
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
