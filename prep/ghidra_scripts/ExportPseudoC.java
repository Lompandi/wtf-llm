// Batch-decompile a function closure to pseudo-C for A2 (snapfuzz CP6).
//
// Java for the same reason as ExportBasicBlocks: Ghidra 12 ships Jython only as
// an optional extension and analyzeHeadless cannot start PyGhidra (D-025).
//
// This is the UNATTENDED path. GhidraMCP is a GUI plugin whose server exists
// only while Ghidra is open (D-039), so it cannot build A2 -- it serves only the
// interactive on-demand lookup for an address the cache does not have.
//
// Args: <output.json> <scope> [entry] [timeoutSeconds]
//   scope = module           -- every function in the program
//   scope = function-closure -- only functions reachable from <entry>
//
//@category snapfuzz
import java.io.PrintWriter;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Symbol;

public class ExportPseudoC extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException(
                "usage: ExportPseudoC <output.json> <module|function-closure> [entry] [timeoutSec]");
        }

        String outputPath = args[0];
        String scope = args[1];
        String entryArg = args.length > 2 ? args[2] : null;
        int timeoutSec = args.length > 3 ? Integer.parseInt(args[3]) : 60;

        long imageBase = currentProgram.getImageBase().getOffset();
        String programName = currentProgram.getName();
        String moduleName = programName;
        int dot = moduleName.lastIndexOf('.');
        if (dot > 0) {
            moduleName = moduleName.substring(0, dot);
        }

        List<Function> targets = new ArrayList<>();
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
            targets.addAll(callClosure(entry));
        }
        else if (scope.equals("module")) {
            for (Function fn : currentProgram.getFunctionManager().getFunctions(true)) {
                if (!fn.isExternal() && !fn.isThunk()) {
                    targets.add(fn);
                }
            }
        }
        else {
            throw new IllegalArgumentException("unknown scope: " + scope);
        }

        println("[snapfuzz] decompiling " + targets.size() + " function(s)");

        DecompInterface decomp = new DecompInterface();
        List<String> entries = new ArrayList<>();
        long ok = 0;
        long failed = 0;

        try {
            if (!decomp.openProgram(currentProgram)) {
                throw new IllegalStateException(
                    "DecompInterface.openProgram failed: " + decomp.getLastMessage());
            }

            for (Function fn : targets) {
                monitor.checkCancelled();
                DecompileResults results = decomp.decompileFunction(fn, timeoutSec, monitor);

                // A decompile failure is per-function and must not abort the run:
                // one stubborn function should not cost us the other 13.
                if (results == null || !results.decompileCompleted()
                    || results.getDecompiledFunction() == null) {
                    failed++;
                    println("[snapfuzz] decompile FAILED for " + fn.getName() + ": "
                        + (results == null ? "null" : results.getErrorMessage()));
                    continue;
                }

                String code = results.getDecompiledFunction().getC();
                long entryAddr = fn.getEntryPoint().getOffset();
                Address min = fn.getBody().getMinAddress();
                Address max = fn.getBody().getMaxAddress();

                entries.add(String.format(
                    "{\"function\":%s,\"entry_static\":%d,\"min_static\":%d,"
                        + "\"max_static\":%d,\"code\":%s}",
                    quote(fn.getName()), entryAddr,
                    min == null ? entryAddr : min.getOffset(),
                    max == null ? entryAddr : max.getOffset(),
                    quote(code)));
                ok++;
            }
        }
        finally {
            decomp.dispose();
        }

        try (PrintWriter out = new PrintWriter(outputPath, "UTF-8")) {
            out.print("{");
            out.print("\"module\":" + quote(moduleName) + ",");
            out.print("\"program\":" + quote(programName) + ",");
            out.print("\"image_base\":" + imageBase + ",");
            out.print("\"scope\":" + quote(scope) + ",");
            out.print("\"entry\":" + (entryResolved == null ? "null" : quote(entryResolved)) + ",");
            out.print("\"decompiled\":" + ok + ",");
            out.print("\"failed\":" + failed + ",");
            out.print("\"functions\":[");
            out.print(String.join(",", entries));
            out.print("]}");
        }

        println("[snapfuzz] module=" + moduleName + " decompiled=" + ok
            + " failed=" + failed);
        println("[snapfuzz] wrote " + outputPath);
    }

    private Function resolveEntry(String spec) {
        if (spec.startsWith("0x") || spec.startsWith("0X")) {
            Address addr = currentProgram.getAddressFactory()
                .getDefaultAddressSpace()
                .getAddress(Long.parseUnsignedLong(spec.substring(2), 16));
            Function fn = getFunctionAt(addr);
            return fn != null ? fn : getFunctionContaining(addr);
        }

        for (Symbol s : currentProgram.getSymbolTable().getGlobalSymbols(spec)) {
            Function fn = getFunctionAt(s.getAddress());
            if (fn != null) {
                return fn;
            }
        }
        for (Function fn : currentProgram.getFunctionManager().getFunctions(true)) {
            if (fn.getName().equals(spec)) {
                return fn;
            }
        }
        return null;
    }

    /**
     * Static call closure. Same lower-bound caveat as ExportBasicBlocks: Ghidra
     * resolves few indirect calls, so a target dispatching through function
     * pointers will be under-covered. --scope=module is the escape hatch.
     */
    private Set<Function> callClosure(Function entry) throws Exception {
        Set<Function> seen = new LinkedHashSet<>();
        Deque<Function> queue = new ArrayDeque<>();
        queue.add(entry);
        seen.add(entry);

        while (!queue.isEmpty()) {
            monitor.checkCancelled();
            for (Function callee : queue.poll().getCalledFunctions(monitor)) {
                if (callee.isExternal() || callee.isThunk()) {
                    continue;
                }
                if (seen.add(callee)) {
                    queue.add(callee);
                }
            }
        }
        return seen;
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
