// Enumerate basic blocks for wtf coverage breakpoints (snapfuzz CP2).
//
// Written in Java, not Python, deliberately. Ghidra 12 ships Jython only as an
// optional extension and routes .py scripts to PyGhidra, which analyzeHeadless
// cannot start -- a stock install fails with "Ghidra was not started with
// PyGhidra". Java scripts always work. See docs/DEVIATIONS.md D-025.
//
// Modelled on wtf's own scripts/gen_coveragefile_ghidra.py, which is the format
// oracle (D-006). What it adds is the thing CP2 actually needs: scoping, so we
// do not enumerate an entire module when only the parser's call closure matters.
//
// Args: <output.json> <scope> [entry]
//   scope = module           -- every basic block in the program
//   scope = function-closure -- only blocks in functions reachable from <entry>
//   entry = a symbol name, or an address as 0x...
//
//@category snapfuzz
import java.io.PrintWriter;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Symbol;

public class ExportBasicBlocks extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException(
                "usage: ExportBasicBlocks <output.json> <module|function-closure> [entry]");
        }

        String outputPath = args[0];
        String scope = args[1];
        String entryArg = args.length > 2 ? args[2] : null;

        long imageBase = currentProgram.getImageBase().getOffset();

        // wtf resolves the .cov "name" through GetModuleBase(), which wants the
        // debugger's module name -- "tlv_server", not "tlv_server.exe". wtf's
        // own Ghidra script strips the last extension; match it exactly.
        String programName = currentProgram.getName();
        String moduleName = programName;
        int dot = moduleName.lastIndexOf('.');
        if (dot > 0) {
            moduleName = moduleName.substring(0, dot);
        }

        Set<Function> inScope = null;
        String entryResolved = null;
        if (scope.equals("function-closure") || scope.equals("closure")) {
            if (entryArg == null) {
                throw new IllegalArgumentException("function-closure scope requires an entry");
            }
            Function entry = resolveEntry(entryArg);
            if (entry == null) {
                throw new IllegalArgumentException("could not resolve entry: " + entryArg);
            }
            entryResolved = entry.getName() + "@" + entry.getEntryPoint();
            inScope = callClosure(entry);
            println("[snapfuzz] closure from " + entryResolved + ": "
                + inScope.size() + " functions");
        }
        else if (!scope.equals("module")) {
            throw new IllegalArgumentException("unknown scope: " + scope);
        }

        List<String> blocks = new ArrayList<>();
        long emitted = 0;
        long skippedOutOfScope = 0;
        long skippedBelowBase = 0;

        BasicBlockModel model = new BasicBlockModel(currentProgram);
        CodeBlockIterator it = model.getCodeBlocks(monitor);
        while (it.hasNext()) {
            monitor.checkCancelled();
            CodeBlock block = it.next();
            Address min = block.getMinAddress();

            Function containing = getFunctionContaining(min);
            if (inScope != null && (containing == null || !inScope.contains(containing))) {
                skippedOutOfScope++;
                continue;
            }

            long staticAddr = min.getOffset();
            // wtf stores RVAs and adds GetModuleBase() at load time. An address
            // below the image base cannot be expressed as one.
            if (staticAddr < imageBase) {
                skippedBelowBase++;
                continue;
            }

            blocks.add(String.format(
                "{\"rva\":%d,\"static_addr\":%d,\"function\":%s}",
                staticAddr - imageBase, staticAddr,
                containing == null ? "null" : quote(containing.getName())));
            emitted++;
        }

        try (PrintWriter out = new PrintWriter(outputPath, "UTF-8")) {
            out.print("{");
            out.print("\"module\":" + quote(moduleName) + ",");
            out.print("\"program\":" + quote(programName) + ",");
            out.print("\"image_base\":" + imageBase + ",");
            out.print("\"scope\":" + quote(scope) + ",");
            out.print("\"entry\":" + (entryResolved == null ? "null" : quote(entryResolved)) + ",");
            out.print("\"skipped_out_of_scope\":" + skippedOutOfScope + ",");
            out.print("\"skipped_below_image_base\":" + skippedBelowBase + ",");
            out.print("\"blocks\":[");
            out.print(String.join(",", blocks));
            out.print("]}");
        }

        println("[snapfuzz] module=" + moduleName + " image_base=0x"
            + Long.toHexString(imageBase) + " blocks=" + emitted
            + " skipped_out_of_scope=" + skippedOutOfScope
            + " skipped_below_image_base=" + skippedBelowBase);
        println("[snapfuzz] wrote " + outputPath);
    }

    /** Resolve an entry given either a symbol name or a 0x-prefixed address. */
    private Function resolveEntry(String spec) {
        if (spec.startsWith("0x") || spec.startsWith("0X")) {
            Address addr = currentProgram.getAddressFactory()
                .getDefaultAddressSpace()
                .getAddress(Long.parseUnsignedLong(spec.substring(2), 16));
            Function fn = getFunctionAt(addr);
            return fn != null ? fn : getFunctionContaining(addr);
        }

        List<Symbol> symbols = currentProgram.getSymbolTable().getGlobalSymbols(spec);
        for (Symbol s : symbols) {
            Function fn = getFunctionAt(s.getAddress());
            if (fn != null) {
                return fn;
            }
        }

        // Fall back to a linear scan: PDB-derived names sometimes are not
        // global symbols but the function still carries the name.
        for (Function fn : currentProgram.getFunctionManager().getFunctions(true)) {
            if (fn.getName().equals(spec)) {
                return fn;
            }
        }
        return null;
    }

    /**
     * Functions reachable from the entry by static call edges.
     *
     * Deliberately does NOT follow indirect calls -- Ghidra cannot resolve most
     * of them, so the closure is a lower bound on what actually executes. That
     * matters for CP2: a block missing from the .cov is simply never counted as
     * coverage, silently. `--scope=module` is the escape hatch.
     */
    private Set<Function> callClosure(Function entry) throws Exception {
        Set<Function> seen = new LinkedHashSet<>();
        Deque<Function> queue = new ArrayDeque<>();
        queue.add(entry);
        seen.add(entry);

        while (!queue.isEmpty()) {
            monitor.checkCancelled();
            Function fn = queue.poll();
            for (Function callee : fn.getCalledFunctions(monitor)) {
                if (callee.isExternal() || callee.isThunk()) {
                    continue;
                }
                if (seen.add(callee)) {
                    queue.add(callee);
                }
            }
        }
        return new HashSet<>(seen);
    }

    private static String quote(String s) {
        StringBuilder sb = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n");  break;
                case '\r': sb.append("\\r");  break;
                case '\t': sb.append("\\t");  break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    }
                    else {
                        sb.append(c);
                    }
            }
        }
        return sb.append('"').toString();
    }
}
