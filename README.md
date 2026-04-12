# project-csec476-group2
Malware analysis project including static and dynamic analysis of a real-world sample, with detailed findings, reverse engineering, and network behavior investigation.

# Malware Analysis Report - Group 2

## Team Members
- Konstantin Avetisian – 405006442
- Ayush Gowda – 393000595
- Nikita Astionov – 386004799
- Youssef Elgayar – 772003595

## Table of Contents
- Technical Summary
- Static Analysis
- Dynamic Analysis
- Advanced Analysis
- Conclusion

---

## Technical Summary
(1 page summary of what malware does)

---

## Static Analysis

Static analysis examines a malware sample without executing it, extracting
identifying characteristics, structural properties, and behavioral intent from
the binary itself. For `group2.exe`, static analysis proved sufficient to
completely identify the sample, map its command-and-control infrastructure,
enumerate every Windows API it would invoke at runtime, and attribute the
sample to a specific offensive-security framework with its exact build-time
options — all before a single instruction was emulated or executed.

This section is divided into Basic Static Analysis, which establishes file
type, structure, and surface-level indicators, and Advanced Static Analysis,
which reconstructs the malware's runtime behavior through disassembly,
control-flow analysis, and cross-referencing against known threat-actor
techniques. All screenshots include the group identifier and a system
timestamp.

### Basic Static Analysis

#### Initial sample identification

The sample assigned to Group 2 was delivered as a single file named
`group2.pdf`, totalling 295.04 KiB. PDF is an unusual container for malware
because the format itself is not executable — a PDF is rendered by a reader
application (Adobe Reader, Foxit, the built-in Windows viewer, or a browser)
rather than directly by the operating system. When malware is delivered as a
PDF, it is almost always for one of three reasons: to exploit a vulnerability
in the PDF reader itself, to invoke embedded JavaScript that triggers a
secondary download, or to act as a passive delivery container that holds a
payload for the user to extract manually. We therefore began by establishing
the PDF's true file type and surveying it for indicators of which of these
three categories the sample falls into.

Detect It Easy (DIE) version 3.10, a Windows GUI tool that combines PE
identification, packer detection, and entropy analysis, was used as the first
identification step. DIE confirmed the file was a genuine PDF version 1.7
(the "with binary data" annotation indicates the file contains non-textual
streams — a strong hint at embedded binary content such as fonts, images, or
attachments) and reported no packer, obfuscator, or signature-based anomalies
on the PDF layer itself.

![Detect It Easy identifying group2.pdf as PDF 1.7 with binary data](images/pdf_die.png)

*Figure 1: Detect It Easy identifies `group2.pdf` as a legitimate PDF file
(format `PDF(1.7)[with binary data]`).*

Establishing the true file type before proceeding is standard practice in static analysis 
because file extensions can be forged, the actual magic bytes at the start of the file (`%PDF-1.7`)
determine what tools to apply next.

#### Triaging the PDF structure

Didier Stevens' `pdfid.py` is the de-facto standard tool for rapid PDF triage.
It parses the raw PDF object stream and counts occurrences of every keyword
commonly abused to trigger malicious behavior — specifically the elements that
Adobe and third-party PDF readers have historically allowed to invoke code or
retrieve external resources. The presence of any non-zero count on
`/JavaScript`, `/JS`, `/OpenAction`, `/AA`, `/Launch`, `/RichMedia`,
`/JBIG2Decode`, or `/EmbeddedFile` is a flag requiring further investigation.
the absence of all of them typically indicates a benign PDF.

Running `pdfid.py` against `group2.pdf` produced a diagnostic profile that
narrowed the threat model considerably.

![pdfid output showing /EmbeddedFile = 1 and all other suspicious keywords at zero](images/pdfid.png)

*Figure 2: `pdfid.py` parses the PDF and counts abuse-prone keywords. In
`group2.pdf`, only one such keyword appears: `/EmbeddedFile = 1`. Every
script-execution and auto-action keyword — `/JavaScript`, `/JS`,
`/OpenAction`, `/AA`, `/Launch` — is zero.*

This tells us the PDF contains no embedded JavaScript, no auto-execution triggers, and no launch actions.
Its sole function is to carry a single embedded file as an attachment.

#### Locating the embedded file reference

With a single `/EmbeddedFile` confirmed, the next step was to identify which
PDF object carries the embedded payload and what filename is associated with
it. Embedded files in PDF follow a specific object structure. A `/Filespec`
dictionary describes the file (name, MIME type, relationships), and an `/EF`
(Embedded File) dictionary inside the Filespec references a separate stream
object containing the actual file bytes. Identifying the `/Filespec` object
is therefore the entry point for extraction.

`pdf-parser.py --search Filespec` walks the object graph and returns every
`/Filespec` dictionary in the document.

![pdf-parser --search Filespec showing object 4 references /F (group2.exe)](images/pdfparser_filespec.png)

*Figure 3: `pdf-parser.py` locates object `4 0` with `/Type /Filespec`. The
critical line is `/F (group2.exe)` — the filename of the embedded attachment,
stored as an ASCII literal. The parallel `/UF` field encodes the same filename
as UTF-16 for Unicode support (the escape sequence `\x00g\x00r\x00o\x00u\x00p
\x00 2\x002 \x00.\x00e\x00x\x00e` is UTF-16LE for `group2.exe` with a leading
byte-order mark). The `/EF /F 3 0 R` line references object `3 0` as the
container of the actual file content.*

#### Inspecting the embedded file object

Before extracting the payload we inspected object `3 0` directly to verify its
structural properties, in particular what compression or filtering the PDF
specification applies to the stream. A PDF stream can declare any combination
of `/Filter` values — common ones are `/FlateDecode` (zlib deflate, the same
compression used in ZIP), `/ASCIIHexDecode`, `/ASCII85Decode`,
`/LZWDecode`, and `/Crypt`. To recover the original file we must inverse-apply
each filter in order.

![pdf-parser --object 3 showing /Type /EmbeddedFile, /Subtype /application/octet-stream, /Filter /FlateDecode](images/pdfparser_object3.png)

*Figure 4: Object `3 0` is confirmed as `/Type /EmbeddedFile` with
`/Subtype /application/octet-stream` and `/Filter /FlateDecode`. The subtype
`application/octet-stream` is the MIME type for "arbitrary binary data" —
PDF is deliberately not committing to whether the payload is an executable, a
document, or anything else. The `/FlateDecode` filter means the stream bytes
on disk are zlib-compressed; they must be inflated to recover the original
file.*

#### Extracting the payload

With the object identified and its compression understood, extraction was
straightforward. `pdf-parser.py --object 3 --filter --dump <outpath>` applies
every declared stream filter in order and writes the resulting bytes to the
specified file. We wrote the recovered bytes to `group2.exe` in the downloads
directory of the FLARE-VM analysis system.

#### Hashing and identifying the recovered binary

Once the PE was on disk as a standalone file, standard identification
procedures were applied.

![PowerShell Get-FileHash computing SHA-256 of the extracted group2.exe](images/pefile_hash.png)

*Figure 5: SHA-256 of the extracted binary*

The hash serves two purposes. First, it is the canonical identifier for the sample —
every subsequent finding in this report is attributable to this specific
SHA-256, which any reader can independently verify by recomputing the hash on
their own copy of the extracted file. Second, the hash can be searched against
public threat intelligence databases such as VirusTotal, MalwareBazaar, and
Hybrid Analysis to determine whether the sample has been previously observed
in the wild.

The complete metadata for the extracted binary is:

| Property  | Value |
|---|---|
| File type | PE32+ executable for MS Windows, x86-64 |
| File size | 7.50 KiB (7680 bytes) |
| MD5       | `0ce70f0f07c21bf4290a1c0308fc4f46` |
| SHA-1     | `1562f662214044749c1fa5601f52332ed347e011` |
| SHA-256   | `89dfbfeda4ec1d4f6d28ab376cc28468f42f98ccc694cd8e9a5033a34c2f7a7b` |
| ssdeep    | `24:eFGSGj30pFLknehtht6dp506WcNYKan2DOIRwQa/FlGVKbuqiksvckOp:iGb0onehthEdc2GJCO1Qa9QQqilk` |

The binary's small size (under 8 KB) is itself a behavioral indicator. A
fully-featured malicious application — a banking trojan, ransomware, or
backdoor — typically spans hundreds of kilobytes to several megabytes once
its functionality, configuration, and (often) statically-linked dependencies
are accounted for. A 7.5 KB Windows PE can contain only a small amount of
actual code. This size is characteristic of a **stager**: a minimal first-
stage payload whose sole purpose is to download a larger second-stage payload
from the attacker's infrastructure and execute it in memory. This hypothesis
is tested and confirmed by the Advanced Static Analysis below.

#### Threat intelligence lookup

![VirusTotal search returns no matching results for the extracted SHA-256](images/virustotal_nohits.png)

*Figure 6: VirusTotal returns no matching results for the extracted SHA-256
as of the analysis date.* 

The sample has not been previously observed by any
of the antivirus engines that contribute to VirusTotal, nor by the community
comment system. This negative result is itself a finding: whatever this
sample is, it is either genuinely novel or it has been generated fresh specifically 
for this deliverable and therefore has no prior fingerprint. Either way, we cannot rely
on external classification and must identify the family through our own analysis.

#### Binary identification with Detect It Easy

DIE was then applied to the extracted executable to determine compiler, linker,
architecture, and any high-level indicators such as packers or protectors.

![Detect It Easy on group2.exe reporting PE64 AMD64 GUI, MSVC 19.36.35207, Visual Studio 2022 v17.6, and a packer heuristic](images/die_exe.png)

*Figure 7: DIE reports `group2.exe` as a 64-bit GUI-subsystem PE (`PE64`,
`AMD64`, `GUI`), built with Microsoft Visual C/C++ version 19.36.35207 and
linked with Microsoft Linker 14.36.35207 (Visual Studio 2022, v17.6). The
heuristic line `(Heur)Packer: Compressed or packed data [Last section EP]` is
the most interesting single finding from this step* 

DIE's packer heuristic has flagged that the PE's entry point does not sit in the first section of
the binary (`.text`) but in the **last** section. Normal MSVC output places executable code in `.text`,
which is always the first code section. An entry
point in a trailing section is diagnostic of either a packer (which decompresses
the original code at runtime and transfers control to it) or a custom loader
(which prepares the environment and jumps to embedded shellcode). Combined
with the small file size, the latter interpretation is more likely.

#### PE structure analysis

The Portable Executable (PE) structure of the extracted binary was examined
using two complementary tools: PE-bear for interactive exploration and section-
level visualization, and CFF Explorer for detailed section-characteristic
inspection.

![PE-bear tree view showing DOS Header, NT Headers, Section Headers, and five sections ending with .glav containing the entry point](images/pebear_sections.png)

*Figure 8: PE-bear's tree view of `group2.exe`.*

The section tree shows five sections: `.text`, `.rdata`, `.data`, `.pdata`, and `.glav`. The first four
are standard outputs of the Microsoft linker for a 64-bit PE (`.text` for
executable code, `.rdata` for read-only data, `.data` for mutable data, and
`.pdata` for exception-handling metadata required by the x64 calling
convention). The fifth, `.glav`, is **non-standard**. The Microsoft linker
does not emit sections with this name under any default configuration. The
entry point annotation `EP = 1A00` further confirms that the binary's
execution begins inside `.glav` — the last-loaded section. This is the
structural signature of a hand-crafted PE loader with embedded shellcode,
not a normal compiled application.

![CFF Explorer section table showing .glav with virtual size 0x375, characteristics 0xE0000020](images/cff_sections.png)

*Figure 9: CFF Explorer VIII section characteristics table. The `.glav`
section has virtual size `0x375`, virtual address `0x5000`, raw size `0x400`,
and **Characteristics `0xE0000020`**. This value decodes to the bitwise OR
of four PE section flags: `IMAGE_SCN_CNT_CODE (0x00000020)`,
`IMAGE_SCN_MEM_EXECUTE (0x20000000)`, `IMAGE_SCN_MEM_READ (0x40000000)`, and
`IMAGE_SCN_MEM_WRITE (0x80000000)`.* 

The combination `MEM_EXECUTE | MEM_READ | MEM_WRITE` — commonly abbreviated RWX — is
extraordinarily unusual in legitimate software. Modern compilers and operating
systems enforce the W^X principle (a page should be writable or executable,
not both), both through build-time section flags and through runtime enforcement
via the Data Execution Prevention feature. A PE section flagged as RWX at
build time bypasses the first layer of this defense and strongly indicates a
shellcode container: code that must be writable because it modifies itself
during execution, and executable because it is ultimately control-transferred
to.

The combination of the `.glav` naming, RWX permissions, entry point in the
trailing section, and minimal `.text` content establishes that `group2.exe`
is structurally a loader rather than a conventional application. The
remaining sections (`.text`, `.rdata`, `.data`, `.pdata`) are present mainly
to satisfy the Windows loader's expectations of a well-formed PE; the actual
malicious payload resides in `.glav`.

#### Entropy analysis

A standard follow-up to identifying an unusual section is to examine the
entropy of its content. Shannon entropy, measured in bits per byte on a scale
from 0 to 8, indicates how uniformly distributed the byte values in a region
are. Entropy values correspond meaningfully to content categories: near-zero
for repetitive data (long runs of the same byte), roughly 4–5 for ASCII text,
5.5–6.5 for x86/x64 machine code, and above 7.5 for compressed or encrypted
data.

![DIE entropy analysis of group2.exe showing per-section entropy values and overall profile](images/pebear_entropy.png)

*Figure 10: Detect It Easy's entropy analysis of `group2.exe`.*

Although DIE's heuristic scanner flagged the binary as possibly packed in Figure 7, the
entropy analyzer reports a final verdict of "not packed (21%)". The two
subsystems are measuring different things — the heuristic flag is
**structural** (EP location, section layout, IAT shape), while the entropy
analysis is **statistical** (byte-value distribution). A genuine packer
would trigger both signals: structural anomaly plus high entropy (typically
7.5+ bits/byte) in the section containing the compressed payload. Here, the
per-section entropies are `.rdata` = 2.87, `.data` = 0.03, `.pdata` = 0.10,
and `.glav` = 5.76, with overall file entropy of 1.72. The 5.76 value in
`.glav` is elevated relative to the rest of the file and consistent with a
local peak of approximately 6.6 visible in the graph, but this falls
squarely within the range expected for dense hand-written x64 machine code
(5.5–6.5 bits/byte) and well below the ~7.5 threshold that would indicate
compression or the ~7.9 threshold that would indicate encryption. The
reconciliation of the two DIE findings is therefore clear: `group2.exe` has
the **structure** of a packed binary (entry point in a trailing custom
section) without the **content** of one (no compressed or encrypted blob
in that section). This is the structural signature of a shellcode loader
rather than a true packer — the bytes in `.glav` are ready-to-execute x64
instructions, not a decompress-then-run stub. The practical implication
for reverse engineering is confirmed by the Advanced Static Analysis
section below: the shellcode in `.glav` can be disassembled directly
without peeling off any encryption or compression wrapper.

#### Import Address Table

The Import Address Table (IAT) of a PE is the list of external DLL functions
the binary declares it will need at load time. The Windows loader resolves
each entry in the IAT to a function pointer before handing control to the
program's entry point. For a static analyst, the IAT is normally one of the
richest sources of behavioral information: an application that imports
`CreateFileA`, `WriteFile`, and `CloseHandle` is obviously doing file I/O;
one that imports `InternetOpenUrlA` and `HttpSendRequestA` is doing HTTP;
one that imports `CryptAcquireContextA`, `CryptHashData`, and `CryptEncrypt`
is doing cryptography. A binary's IAT is often a complete table of contents
of its functionality.

![PE-bear imports tab showing a single entry: KERNEL32.dll!VirtualProtect](images/pebear_imports.png)

*Figure 11: The complete Import Address Table of `group2.exe`.*

There is exactly **one** imported function across all DLLs: `KERNEL32.dll!VirtualProtect`.
This is extraordinary. A Windows GUI application — which the PE header declares
this binary to be — typically imports at minimum the window-creation,
message-pump, and GDI functions from `user32.dll` and `gdi32.dll`, plus dozens
of utility functions from `kernel32.dll`. A 1-function IAT is not just small,
it is the smallest possible useful IAT.

The interpretation is clear and follows a well-documented malware technique:
**the binary does not declare its dependencies statically because it resolves
them dynamically at runtime**. Rather than letting the Windows loader
populate pointers to WinINet, kernel, and network functions into the IAT, the
malware performs its own resolution by walking the Process Environment Block
(PEB) at runtime, enumerating loaded modules, hashing exported function
names with a lightweight hash function, and comparing the result against
pre-computed hash constants baked into the shellcode. This technique, known
as **API hashing**, was popularized in the mid-2000s by security researcher
Stephen Fewer in his publicly-released `block_api` shellcode. It serves two
defensive purposes for the attacker. First, the malware's intentions are
not visible to static analysts who inspect only the IAT — the actual API
surface is hidden behind opaque 32-bit hash values. Second, the absence of
an IAT reference to, for example, `InternetConnectA` means the malware evades
simple signature rules that flag "any binary importing WinINet functions as
suspicious".

The single import that is present, `VirtualProtect`, is consistent with
this interpretation: a runtime loader needs to make code pages executable
after writing them, and `VirtualProtect` is the standard Windows API for
changing memory-protection flags on an allocated region. Since the loader
can obtain a `VirtualProtect` function pointer legitimately through the IAT
and there is no signature-level suspicion attached to this single function,
the attacker has bootstrapped the remainder of API resolution from this one
starting point.

#### Static string extraction

The extracted strings of a binary often reveal hardcoded URLs, filenames,
error messages, and configuration data. FLOSS (FireEye Labs Obfuscated String
Solver) was used in addition to the simpler `strings` utility because FLOSS
applies control-flow analysis to the binary's code and can recover strings
that are assembled or decoded at runtime rather than stored as static data.

![FLOSS static strings output showing section names, PAYLOAD marker, shellcode fragments, wininet, User-Agent, 212.22.1.3, and a 120-character URI](images/floss_strings_1.png)

*Figure 12: FLOSS static strings output — the richer half.*

Notable extracted strings include: the PE section and directory labels (`.text$mn`, `.rdata`,
`.idata$5`, `.xdata`, `.idata$2`, `.idata$3`, `.idata$4`, `.idata$6`,
`.data`, `.pdata`, `.glav`); import table entries (`VirtualProtect`,
`KERNEL32.dll`); a `PAYLOAD:` literal (likely a marker string embedded in the
shellcode); short ASCII fragments (`AQAPRH1`, `rPM1`, `JJH1`, `R AQ`,
`AX^YZAXAYAZH`, `XAYZH`, `YSZM1`, `SZAXM1`, `PSSI`, `SYj@ZI`); the string
`wininet`; a full Mozilla/Chrome HTTP User-Agent
(`Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like
Gecko) Chrome/131.0.0.0 Safari/537.36`); an IPv4 address `212.22.1.3`; and a
120-character URI-like blob beginning with `/DoSaKUGGHJcVXRRffO9-...`.

The short ASCII fragments (`AQAPRH1`, `AX^YZAXAYAZH`, `SZAXM1`, etc.) are
not meaningful text. They are **x64 instruction opcode bytes that happen to
fall within the printable ASCII range** and were therefore caught by the
string extractor. For example, `A` is `0x41` which is the REX.B prefix
commonly used in x64; `Q` is `0x51` which is `push rcx`; `P` is `0x50` which
is `push rax`; `R` is `0x52` which is `push rdx`; `Z` is `0x5A` which is
`pop rdx`; `H` is `0x48` which is the REX.W prefix that makes an instruction
64-bit; `1` is `0x31` which is the opcode for `xor r/m, r` when combined
with a ModR/M byte. A sequence such as `AX^YZAXAYAZH` decodes as a cascade
of push/pop/xor instructions shuffling register values — the kind of
register-juggling that occurs at function epilogues and prologues in hand-
written shellcode. These fragments are therefore not "strings" in the usual
sense but fingerprints of the shellcode instruction stream being swept up by
a text extractor.

The remaining notable strings each correspond to a specific malware
behavior:

- `wininet` is the name of the Windows HTTP client library. Its presence as
  a string, combined with the complete absence of `wininet.dll` functions
  from the IAT, implies the library is loaded at runtime via `LoadLibraryA`
  rather than being declared as a static dependency.
- The Mozilla/Chrome User-Agent is the string value the malware will present
  to the C2 server in the `User-Agent` header of its HTTP requests.
  Impersonating a mainstream browser is a standard evasion technique against
  network-layer detection systems that flag unusual User-Agents.
- `212.22.1.3` is a hardcoded IPv4 address, very likely the command-and-
  control server. Hardcoded IPs are fragile for attackers (the address
  becomes an immutable IOC the moment any network defender observes it) but
  are the default msfvenom behavior and are consistent with a training
  sample.
- The 120-character `/DoSaKU…MZra` blob is the most distinctive string. Its
  character set (`A–Z`, `a–z`, `0–9`, `-`, `/`) resembles a URL-safe base64
  encoding with the `+` symbol replaced by `-`. This string became a central
  focus of the Advanced Static Analysis below.

![FLOSS stack and decoded strings output showing only wininet recovered](images/floss_strings_2.png)

*Figure 13: FLOSS stack strings and decoded strings output.*

Beyond the static strings already shown, FLOSS reports exactly one stack string (`wininet`)
and exactly one decoded string (also `wininet`). Stack strings are built up
byte-by-byte on the stack at runtime — an obfuscation technique where the
string never exists in the binary as contiguous data. Decoded strings are
those FLOSS has determined are produced by a runtime decoding routine. The
fact that FLOSS recovered `wininet` from both sources means the binary
assembles this particular string on the stack at runtime rather than loading
it from `.rdata`. Everything else — the User-Agent, the IP address, the URI,
the section names — appears to be present statically. This is exactly what
we would expect if the shellcode is using the string `wininet` once, to
invoke `LoadLibraryA`, early in its execution.

#### Automated capability extraction

Mandiant's `capa` tool automates the detection of malware capabilities by
matching a library of thousands of rules against a binary's disassembly,
imports, and strings. It produces output in natural language ("resolves
function by hash", "connects to HTTP server", "contains obfuscated stack
strings", etc.) and is one of the fastest ways to sanity-check a manual
analysis. For `group2.exe`, however, the result was unusual.

![capa output reporting "no capabilities found" for group2.exe](images/capa_nocaps.png)

*Figure 14: `capa` reports "no capabilities found" for `group2.exe`.*

This is the null result: capa's rule engine did not match any of its thousands of
capability rules against the binary. The result is not an error — it is a
direct consequence of the binary's structure. capa's rules rely heavily on
characteristic IAT imports and standard disassembly patterns. Because the
malware resolves every API at runtime, there are no conventional import
references for capa's rules to match on. Paradoxically, capa's failure here
is itself strong evidence of API hashing: in an ecosystem where 99.9% of
real-world malware triggers at least a handful of capa rules, a zero-
capability result is diagnostic of advanced evasion and points the analyst
toward the manual techniques used in the Advanced Static Analysis section.

#### Authenticode signature check

Windows executables can be digitally signed by their publisher using
Microsoft's Authenticode scheme. A valid signature chains to a trusted
certificate authority and confirms the identity of the publisher. Malware
is usually unsigned, though higher-effort threats sometimes employ stolen
signing certificates or certificates obtained under false pretenses. The
open-source utility `osslsigncode` was used to check for any signature.

![osslsigncode verify output reporting "No signature found" and an invalid PE checksum warning](images/osslsigncode.png)

*Figure 15: `osslsigncode verify group2.exe` reports "No signature found".*

The binary is unsigned — expected for a Metasploit-generated sample. The
additional warning `invalid PE checksum` is interesting: `osslsigncode`
reports the PE's declared checksum (`0x000098A5`) does not match the value
it computes from the binary's content (`0x00009A0D`). A mismatch indicates that either 
the linker's `/RELEASE` option was not used (in which case no checksum is
written at all, and the field defaults to zero — but this binary's checksum
is non-zero), or the binary was post-processed after linking. For a
Metasploit sample, the second explanation is likely: `msfvenom` takes the
compiled PE template and patches in the stager shellcode, which invalidates
any previously-computed checksum. The mismatch is therefore an additional
structural fingerprint pointing toward an msfvenom-produced binary.

#### Secondary PE survey with rabin2

As a final Basic Static Analysis step, `rabin2` (the radare2 suite's
binary-information tool) was used to independently confirm the findings of
the Windows-native tools.

![rabin2 -I, -S, -i, -zz output showing file properties, sections, imports, and strings](images/rabin2_sections.png)

*Figure 16: `rabin2` cross-verification.*
`rabin2 -I` confirms the PE-level properties (machine `AMD64`, subsystem `Windows GUI`, `nx: true`,
`signed: false`, `stripped: false`). `rabin2 -S` prints the five-section
layout, explicitly showing the permission strings: `.text` as `-r-x`,
`.rdata` as `-r--`, `.data` as `-rw-`, `.pdata` as `-r--`, and `.glav` as
`-rwx`. `rabin2 -i` confirms the single-entry IAT
(`KERNEL32.dll / VirtualProtect`). `rabin2 -zz` prints all strings including
the `!This program cannot be run in DOS mode.` DOS stub message. Every
finding from the Windows-side tools is corroborated by the Linux-side
tools, giving high confidence in the Basic Static Analysis conclusions.

#### Summary of Basic Static Analysis findings

At the conclusion of Basic Static Analysis we had established the following:
the sample was a small (7.5 KiB) 64-bit Windows PE extracted from a PDF
attachment; the PE was built with MSVC 2022 but post-processed in a way that
invalidated its checksum; the entry point resides in a non-standard,
read+write+execute section named `.glav`; the import table declares only a
single function (`VirtualProtect`); runtime behavior therefore relies on
API resolution by some alternative mechanism; strings extracted from the
binary include a hardcoded C2 IPv4 address (`212.22.1.3`), a Chrome
User-Agent, a reference to the `wininet` HTTP library, and a distinctive
120-character ASCII blob beginning with `/DoSaKU`; `capa` detects no
conventional capabilities because API references are all resolved dynamically;
the binary is unsigned and has not been previously sighted on VirusTotal.

These findings collectively pointed toward a minimalist HTTP(S)-based
downloader built as a shellcode loader. The Advanced Static Analysis below
confirms this hypothesis and identifies the specific framework, variant, and
build-time options used to produce the sample.

**Tools used in Basic Static Analysis:** Detect It Easy (DIE), Didier Stevens
Suite (`pdfid.py`, `pdf-parser.py`), PowerShell `Get-FileHash`, VirusTotal,
PE-bear, CFF Explorer VIII, FLOSS, capa, osslsigncode, rabin2 (radare2
suite).

---

### Advanced Static Analysis

Basic Static Analysis established that `group2.exe` is a shellcode loader
with a custom RWX section, dynamic API resolution, and several hardcoded
runtime parameters. Advanced Static Analysis seeks to complete the picture
by disassembling the shellcode itself, identifying the API resolution
algorithm, enumerating every Windows function the malware will invoke at
runtime, recovering the meaning of the 120-character `/DoSaKU…` blob, and
attributing the sample to a specific malware family or toolkit.

#### Ghidra disassembly — first approach to the stager

Ghidra was used as the primary static disassembler. Having identified the
120-character URI-like string in Basic Static Analysis as a distinctive
artifact, we searched for it in Ghidra's defined strings and followed its
cross-references into the code. The string is referenced inline in a
function labeled `FUN_140005191`, immediately after a `call` instruction.

![Ghidra listing at FUN_140005191 showing argument-preparation instructions and the call FUN_14000522E followed by the inline /DoSaKU... URI](images/ghidra_FUN_140005191.png)

*Figure 17: Ghidra's disassembly of `FUN_140005191`.*

The function prepares arguments for a WinINet call — `mov r8, 0x1f92` sets up a 4-byte immediate
(later identified as a port number), `xor r9, r9` clears a register for use
as a NULL argument, `push rbx` and `push 0x3` place stack arguments for
the call (service `0x3` = `INTERNET_SERVICE_HTTP`), and `mov r10, 0xc69f8957`
loads a 32-bit constant that will turn out to be the ROR13 hash of
`InternetConnectA`. The `call rbp` at `0x1400051ae` dispatches this API
call. Immediately after, `call FUN_14000522E` at `0x1400051b0` transfers
control to the next function in the stager chain — and the very next byte
at `0x1400051b5` is `0x2F` (`/`), the first character of the `/DoSaKU…`
URI, which Ghidra's auto-analyzer correctly leaves as undefined (`??`)
because the bytes sit in the middle of the code section rather than in a
data region.

The fact that the ASCII string is placed **immediately after a `call`
instruction** is the key structural observation. The x86-64 `call`
instruction pushes the address of the next instruction onto the stack as the
return address before transferring control to the callee. If the callee
begins with a `pop` of a register from the stack, it receives a pointer to
whatever bytes happened to follow the `call`. This idiom is known as the
**CALL/POP technique** and is a standard way for position-independent
shellcode to reference string data embedded in its own code stream without
requiring a data section or any knowledge of its own load address.

![Ghidra listing at FUN_14000522E showing the pop rdx consuming the URI pointer and subsequent argument setup](images/ghidra_FUN_14000522E.png)

*Figure 18: Ghidra's disassembly of `FUN_14000522E`.*

The function begins with `mov rcx, rax` (loading the connection handle returned by the previous
`InternetConnectA` call), followed by `push rbx / pop rdx` — a stack
alignment shuffle — and then `pop r8`, which consumes the return address
that the preceding `call` pushed onto the stack. Since the address pushed
by `call FUN_14000522E` at `0x1400051b0` was `0x1400051b5` (the first
character of the inline `/DoSaKU…` URI), `r8` now holds a pointer to that
URI string. The subsequent `xor r9, r9`, stack pushes, and `mov rax,
0x84a83200` set up the remaining arguments for the next call — the constant
`0x84A83200` is a bitmask of WinINet request flags including
`INTERNET_FLAG_SECURE (0x00800000)`, identifying the request as HTTPS rather
than plain HTTP.

This resolved the mystery of the `/DoSaKU…` string. It is not encoded. It
is not compressed. It is plaintext ASCII data, stored in the middle of the
code section rather than in `.rdata`, and accessed via the x86-64 calling
convention's automatic return-address push. The malware reads the URI out
of its own instruction stream the first time execution flows past the
associated `call`.

#### The URI checksum — a Metasploit-specific indicator

Having identified the URI as a plaintext argument to a WinINet call, the
next question is whether the URI itself encodes any meaningful information.
Brief entropy analysis ruled out the possibility of a base64-encoded payload
inside the URI — the 5.43 bits-per-character measurement is essentially
random, and no alphabet permutation produces readable text.

A different line of investigation proved more productive. In Metasploit's
reverse-HTTP staged payload architecture, the handler distinguishes
legitimate stager connections from random HTTP traffic by applying a
checksum to the requested URI. Specifically, the Metasploit framework
computes `sum(ASCII bytes of URI) mod 256` and compares the result against
a small table of magic constants. If the checksum matches, the request is
treated as a stager handshake and the appropriate second-stage payload is
served in reply. The constants are defined in the Metasploit source file
`lib/rex/payloads/meterpreter/uri_checksum.rb`:

| Constant | Value | Meaning |
|---|---|---|
| `URI_CHECKSUM_INITP` | 80 | Python stager handshake |
| `URI_CHECKSUM_INITJ` | 88 | Java stager handshake |
| `URI_CHECKSUM_INITW` | 92 | 32-bit Windows stager handshake |
| `URI_CHECKSUM_INITW_X64` | **139** | **64-bit Windows stager handshake** |

Computing the checksum of the recovered URI yields `sum(ord(c) for c in
"/DoSaKUGGHJcVXRRffO9-ggcg2uPT9Oxuy8xGfQfirY7yO23UxNc4jDSyqGoZ7c040azjJqAMGe4nUjWYYXyEajzPQIC5LT9OUMP4ysU35sPczVGyXNyMZra") % 256 = 139`.

The match to 139 (`0x8B`) is **conclusive** identification of the sample as
a 64-bit Windows Metasploit stager. The checksum scheme is documented in
Metasploit's source, ships with every copy of the framework, and would not
be reproduced by coincidence in non-Metasploit software. From this point
forward in the analysis we treat attribution as established and use the
Metasploit upstream source code as an authoritative reference to verify
subsequent findings.

#### Shellcode entry-point discovery with radare2

Having established the framework identity, we turned to the shellcode itself.
The Metasploit x64 Windows shellcode blocks all share a canonical entry
prologue beginning with the byte sequence `fc 48 83 e4 f0` — this decodes to
`cld; and rsp, 0xfffffffffffffff0`, which clears the direction flag and
aligns the stack to a 16-byte boundary as required by the x64 calling
convention. radare2 was used to locate this prologue in `group2.exe`.

![r2 search /x fc4883 returning single hit at 0x140005000 followed by disassembly of block_api prologue](images/r2_prologue_search.png)

*Figure 19: radare2 identifies the shellcode entry point.*

The command `/x fc4883` searches for the byte pattern `fc 48 83` and returns exactly one
match, at virtual address `0x140005000`. Seeking to that address and
disassembling reveals the Stephen Fewer `block_api` resolver prologue in
full: `cld` (direction-flag clear), `and rsp, 0xfffffffffffffff0` (stack
align), `call sub.fcn.1400050d6` (transfer into the resolver body), and
then the characteristic register-saving push sequence
`push r9 / push r8 / push rdx / xor rdx, rdx / push rcx`. The next instruction
`mov rdx, gs:[rdx+0x60]` is the canonical x64 PEB access: `gs:[0x60]` is the
Thread Environment Block offset of the Process Environment Block pointer.
Subsequent instructions (`mov rdx, [rdx+0x18]` and `mov rdx, [rdx+0x20]`)
walk `PEB.Ldr` and `Ldr.InMemoryOrderModuleList`, traversing the linked
list of loaded modules. radare2 labels this function entry as `entry0`,
`hit9_0` (from our search), and `rip` — all collocated at `0x140005000`,
confirming that the PE entry point *is* the shellcode entry point with no
separate PE wrapper. The section banner confirms the section is `.glav` and
marked `-rwx`.

The instruction sequence from `0x140005000` onward is not merely similar to
Metasploit's `block_api.asm`; it is **byte-for-byte identical** to the
upstream source at
`metasploit-framework/external/source/shellcode/windows/x64/src/block/block_api.asm`.
Every byte of the prologue, every register choice, every stack operation
corresponds exactly. This is the structural equivalent of matching a
fingerprint.

#### Enumerating all API calls

Every API call through the resolver follows the same structure: the shellcode
loads the 32-bit ROR13 hash of the target function name into `r10`, places
other arguments in the platform-standard locations (`rcx`, `rdx`, `r8`, `r9`,
and the stack), and then `call rbp` to invoke the resolver, which returns
with the resolved function having been called and its return value in `rax`.
The resolver's address is held in `rbp` throughout the shellcode's lifetime.

To enumerate every API call, we searched for the byte pattern `ff d5` — the
x64 encoding of `call rbp` — across the entire binary.

![r2 session showing pd -3 at final call sites displaying Sleep, VirtualAlloc, InternetReadFile, ExitProcess hash constants and argument setup](images/r2_hash_args.png)

*Figure 20: radare2 extraction of hash constants and arguments at the final
four `call rbp` sites in the shellcode.*

At `0x1400052a2`, the preceding instructions `jne 0x1400052b0 / mov rcx, 0x1388 / movabs r10, 0xe035f044`
identify the call as `Sleep(5000)` — `0x1388` is 5000 in decimal, confirming
a 5-second sleep. At `0x1400052cc`, the sequence `shl edx, 0x10 / mov r8,
0x1000 / movabs r10, 0xe553a458` identifies the call as `VirtualAlloc`. The
`shl edx, 0x10` is a compact way to produce `0x400000` (4 MiB) from `0x40`
(which is simultaneously `PAGE_EXECUTE_READWRITE`); `r8 = 0x1000` is
`MEM_COMMIT`. The net call is `VirtualAlloc(NULL, 0x400000, MEM_COMMIT,
PAGE_EXECUTE_READWRITE)`. At `0x1400052ef`, `mov r8, 0x2000 / mov r9, rdi /
movabs r10, 0xe2899612` identifies the call as `InternetReadFile` with an
8 KB (0x2000) chunk size. At `0x140005310`, `push 0 / pop rcx / mov r10,
0x56a2b5f0` identifies the final call as `ExitProcess(0)`.

Combining this extraction with the earlier hashes visible in the Ghidra
disassembly (Figures 17 and 18) and additional radare2 seeks across the
remaining call sites produced the complete API call inventory:

| # | Call site     | ROR13 hash   | Resolved API          | Purpose                                |
|---|---------------|--------------|----------------------|----------------------------------------|
| 0 | `0x1400050f1` | `0x0726774C` | `LoadLibraryA`       | Loads `wininet.dll`                    |
| 1 | `0x14000517f` | `0xA779563A` | `InternetOpenA`      | Creates WinINet session; sets User-Agent |
| 2 | `0x1400051ae` | `0xC69F8957` | `InternetConnectA`   | TCP connect to `212.22.1.3`            |
| 3 | `0x14000524d` | `0x3B2E55EB` | `HttpOpenRequestA`   | Prepares HTTPS GET with inline URI     |
| 4 | `0x140005272` | `0x869E4675` | `InternetSetOptionA` | Disables certificate validation        |
| 5 | `0x14000528b` | `0x7B18062D` | `HttpSendRequestA`   | Sends the HTTPS request                |
| 6 | `0x1400052a2` | `0xE035F044` | `Sleep`              | 5000 ms between failed-send retries    |
| 7 | `0x1400052cc` | `0xE553A458` | `VirtualAlloc`       | Allocates 4 MiB RWX stage-2 buffer     |
| 8 | `0x1400052ef` | `0xE2899612` | `InternetReadFile`   | Downloads stage-2 in 8 KB chunks       |
| 9 | `0x140005310` | `0x56A2B5F0` | `ExitProcess`        | Exit code 0 on failure                 |

Every hash in this table matches the canonical Stephen Fewer ROR13 hash of
the corresponding Windows API as recorded in Metasploit's framework sources.
The correspondence is complete and exact: no hash is unaccounted for, no hash
fails to match, and no extra hashes exist. This is a ten-for-ten match
against the upstream `block_reverse_https.asm` source.

#### Interpretation — complete runtime behavior

Combining the API inventory, the argument values, and the URI checksum result
yields a complete behavioral description of `group2.exe` without ever
executing it:

1. On launch, the Windows loader maps the PE into memory. The entry point
   lies at the start of the `.glav` section (`0x140005000`), which is marked
   RWX. Control transfers there directly.
2. The first instruction (`cld`) clears the direction flag; the second
   (`and rsp, -16`) aligns the stack. These are house-keeping operations
   required before any C-convention call.
3. A `call` into the API-resolver stub initializes `rbp` to point to the
   resolver. From this point forward, every WinINet/Kernel32 call is
   dispatched through `rbp` using the 32-bit ROR13 hash passed in `r10`.
4. `LoadLibraryA("wininet")` loads the HTTP library into the process.
5. `InternetOpenA` opens a WinINet session, registering the hardcoded
   `Mozilla/5.0 ... Chrome/131.0.0.0` User-Agent.
6. `InternetConnectA` connects to the C2 host `212.22.1.3` using service
   type `INTERNET_SERVICE_HTTP`. The port is loaded from the immediate
   `0x01BB` (decimal 443) in an argument-preparation instruction.
7. `HttpOpenRequestA` prepares an HTTP GET request with the inline URI as
   the object name. The request flags (`0x84A83200`) include
   `INTERNET_FLAG_SECURE`, identifying the connection as HTTPS.
8. `InternetSetOptionA` is called with option 31
   (`INTERNET_OPTION_SECURITY_FLAGS`) and value `0x3380`, disabling all
   certificate validation. This is necessary because the Metasploit C2
   server's TLS certificate is self-signed.
9. `HttpSendRequestA` sends the request. On failure, `Sleep(5000)` is called
   and the send is retried; after ten failures, control falls through to
   `ExitProcess(0)`.
10. On successful send, `VirtualAlloc` allocates a 4 MiB RWX buffer to hold
    the downloaded stage-2 payload.
11. `InternetReadFile` reads the response body in 8 KB chunks until the
    response is exhausted, appending each chunk to the RWX buffer.
12. Control transfers into the start of the downloaded buffer via a
    `pop rax; ret` idiom, executing the stage-2 payload — which is, by
    framework design, the Meterpreter reflective DLL.

This description — retry policy, buffer sizes, cert-validation bypass, chunk
size, exit behavior — corresponds line-by-line with Metasploit's published
`block_reverse_https.asm` source file, confirming both the framework and the
specific stager variant.

#### Quantitative similarity against vanilla msfvenom output

To provide one further independent line of evidence, and to narrow down the
exact msfvenom build options used to produce the sample, a reference binary
was generated with the inferred parameters: payload
`windows/x64/meterpreter/reverse_https`, LHOST `212.22.1.3`, LPORT `443`,
output format `exe`. This reference was compared against `group2.exe` using
the ssdeep fuzzy-hashing algorithm, which produces a similarity score from
0 to 100 based on context-triggered piecewise hashing — a technique robust
to small edits and insertions in the compared files.

![msfvenom generating reference.exe followed by ssdeep -d comparing group2.exe against reference.exe, returning similarity score 38](images/msfvenom_ssdeep.png)

*Figure 21: Generation of a vanilla Metasploit reference binary and ssdeep
similarity comparison.*

The reference `reference.exe` is 7168 bytes. The similarity score between `group2.exe`
and `reference.exe` is 38/100. Inspecting the two ssdeep hashes side by side reveals 
common substrings at both ends — both hashes begin with `eFGS` and both contain `qqilk`
at their tails — indicating that large regions of the two binaries are structurally
equivalent at equivalent offsets. The 38/100 score quantifies the overall
similarity of the files including their differing PE wrappers, the higher
local similarity at the start and end of the hash reflects the shared PE
header conventions and the shared shellcode epilogue.

#### Summary of Advanced Static Analysis findings

`group2.exe` is a Metasploit Framework `windows/x64/meterpreter/reverse_https`
stager, built with `EXITFUNC=process`, configured to connect back to
`https://212.22.1.3:443/DoSaKUGGHJcVXRRffO9-ggcg2uPT9Oxuy8xGfQfirY7yO23UxNc4jDSyqGoZ7c040azjJqAMGe4nUjWYYXyEajzPQIC5LT9OUMP4ysU35sPczVGyXNyMZra`.
The stager employs three evasion techniques: Stephen Fewer's API-hashing
resolver (to hide its imports from static inspection), a self-signed TLS
certificate bypass (so its C2 channel looks like ordinary HTTPS), and a
URI-checksum handshake (so its initial C2 request is indistinguishable from
random web traffic to a defender who does not know the checksum scheme).
On successful connection, the stager downloads a 4 MiB stage-2 payload — by
framework convention, a reflectively-loaded Meterpreter DLL — and transfers
control into it. Attribution is supported by the URI checksum result (139 =
`URI_CHECKSUM_INITW_X64`), the byte-exact match of the shellcode prologue
to Metasploit's upstream `block_api.asm`, the ten-for-ten match of all API
ROR13 hashes to Metasploit's canonical hash table, the matching flag
constants and retry policy, and the ssdeep similarity score of 38 against a
locally-generated vanilla reference.

**Tools used in Advanced Static Analysis:** Ghidra (disassembly and
cross-reference navigation), radare2 (`-AAA` auto-analysis, `/x` byte-pattern
search, `pd` disassembly, `s` seek), Python (URI checksum computation),
`msfvenom` (reference binary generation), `ssdeep` (fuzzy-hash similarity
comparison), the Rapid7 Metasploit Framework source code
(`external/source/shellcode/windows/x64/src/block/block_api.asm`,
`external/source/shellcode/windows/x64/src/block/block_reverse_https.asm`,
`lib/rex/payloads/meterpreter/uri_checksum.rb` — used as authoritative
reference for ROR13 hash values, flag constants, and URI checksum constants).

## Dynamic Analysis

### Basic Dynamic Analysis
- Behavior
- Network traffic
- Processes

### Advanced Dynamic Analysis
- Debugging
- Memory analysis
- Persistence mechanisms

---

## Findings
- C2 communication (Telegram, etc.)
- Data exfiltration
- Indicators of compromise

---

## Conclusion
(what malware does, risk level, key insights)

---

## Team Contributions
- Who did what
