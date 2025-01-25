# Basics
*   Enumeration
    *   [DIE Tool](https://github.com/horsicq/Detect-It-Easy) / `file [FILE]` → Metadata / Filetype / Packers
    *   Execute in Sandbox        → Check User Inputs
    *   String Analysis                  → `strings() [FILE]` / Versions / Sensitive Exposure / GUI & GDB Analysis
*   Disassembling
    *   .NET         → `dnspy`
    *   Binaries  → GEF / Ghidra / Radare2 + Cutter GUI
    *   Exploitation
        *   Conditional Bypass    → Set Breakpoint + Change Boolean Value
        *   Secret Comparison    → Set Breakpoint → Check Encoding / Encryption → Input Test Chars / Find Encryption Key & Scheme
        *   Python Scripting        → PWNTools / Decoders & Decryptors
*   GDB Sheet
    *   Run Binary         → `r`
    *   Registry Values → `i r`
    *   Breakpoints       → `b *[ADDRESS]` / `b [FUNCTION_NAME]`
    *   Strings                 → `x/s [ADDRESS]`
*   Thick Clients
    *   Procmon / PE-Bear / System Informer / Wireshark → Bookmark Resources
    *   Insecure Storage
    *   Network Traffic
    *   Insecure GUI Access