# Malware Analysis Report - Group 2
Malware analysis project including static and dynamic analysis of a real-world sample, with detailed findings, reverse engineering, and network behavior investigation.

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

In static analysis, a malware sample is analyzed without being run, and identifying characteristics, structural properties, and behavioral intent are derived out of the binary. In the case of `group2.exe`, static analysis was enough to identify the sample, map its command-and-control infrastructure, generate all Windows API calls that the sample would make at runtime, and assign the sample to a particular offensive-security framework with its specific build-time options, all without a single instruction being emulated or executed.

This part will be split into Basic Static Analysis, which identifies file type, structure, and surface-level indicators, and Advanced Static Analysis, which re-creates the malware runtime behavior by disassembling it, performing control-flow analysis, and cross-referencing with known threat-actor techniques. Each screenshot has the group identifier and a system timestamp.

### Basic Static Analysis

#### Initial sample identification

The sample provided to Group 2 came in a single file: `group2.pdf`, which has a size of 295.04 KiB. PDF is an unconventional malware delivery mechanism since PDF files are not directly executable. They are rendered and displayed using a PDF reader application like Adobe Reader, Foxit, the Windows built-in reader, or web browsers rather than by the operating system itself. When malware is delivered as a PDF, it is almost always for one of three reasons: to exploit a vulnerability in the PDF reader software itself, to execute embedded Javascript that will download a separate piece of malware, or to be a passive delivery container that must be manually unpacked by the user. Accordingly, we started by first identifying the correct file type of the given file and by exploring the file to look for signs of which of the three categories applies to the sample.
As the first stage of identification, a Windows GUI tool called Detect It Easy (DIE) version 3.10 which integrates PE identification, packer detection and entropy analysis was used. It was determined that the file was a genuine version 1.7 PDF and that it was "with binary data" is an indication that non-textual streams are being used. They could provide binary data within the document (fonts, images or attachments). On the PDF layer no packers, obfuscators or signature-related anomalies were registered.

![Detect It Easy identifying group2.pdf as PDF 1.7 with binary data](images/pdf_die.png)

*Figure 1: Detect It Easy identifies `group2.pdf` as a legitimate PDF file
(format `PDF(1.7)[with binary data]`).*

In static analysis, we should identify the correct file type before continuing. It is possible that a malicious attacker will "mask" a file with the wrong file extension to trick analysis tools, while the actual magic bytes of the file at the beginning of the file (`%PDF-1.7`) tell which tools we should use in the following stages.

#### Triaging the PDF structure

The `pdfid.py` utility, developed by Didier Stevens, has become the tool of choice for rapid PDF triage. It reads the raw PDF object stream and counts the occurrences of all keywords commonly used to trigger malware, the parts of the PDF specification that both Adobe and 3rd party PDF readers have historically allowed to execute code or pull from external sources. Non-zero count on `/JavaScript`, `/JS`, `/OpenAction`, `/AA`, `/Launch`, `/RichMedia`,
`/JBIG2Decode`, or `/EmbeddedFile` suggests the need for further inspection, whereas any PDF without any of the above is generally harmless.

Executing `pdfid.py` on the `group2.pdf` created a diagnostic profile which significantly reduced the scope of the threat model.

![pdfid output showing /EmbeddedFile = 1 and all other suspicious keywords at zero](images/pdfid.png)

*Figure 2: `pdfid.py` parses the PDF and counts abuse-prone keywords. In
`group2.pdf`, only one such keyword appears: `/EmbeddedFile = 1`. Every
script-execution and auto-action keyword — `/JavaScript`, `/JS`,
`/OpenAction`, `/AA`, `/Launch` — is zero.*

The PDF document seems to not contain any JavaScript that will be executed on load or with user interaction, there is no open action to execute code on open, and there is no launch action which will open a program on load. The only noteworthy anomaly is the presence of a single embedded file, which definitely requires further analysis.

#### Locating the embedded file reference

Now that we have verified the presence of a single `/EmbeddedFile`, we need to determine which PDF object contains the embedded content and what filename is referred to by. The structure of embedded in PDF files follow the certain pattern. Each embedded file is defined by a dictionary, known as the `/Filespec`, which contains the filename, MIME-type and other relationships. The `/Filespec` is then linked via another dictionary (`/EF` or Embedded File) to an individual stream object which contain the bytes of the actual file. Finding this `/Filespec` object would give us the path to the embedded file and so is where we should start.

The command `pdf-parser.py --search Filespec` goes through the graph of objects within the document and returns a list of each `/Filespec` dictionary in the document.

![pdf-parser --search Filespec showing object 4 references /F (group2.exe)](images/pdfparser_filespec.png)

*Figure 3: `pdf-parser.py` locates object `4 0` with `/Type /Filespec`. The
critical line is `/F (group2.exe)` — the filename of the embedded attachment,
stored as an ASCII literal. The parallel `/UF` field encodes the same filename
as UTF-16 for Unicode support (the escape sequence `\x00g\x00r\x00o\x00u\x00p
\x00 2\x002 \x00.\x00e\x00x\x00e` is UTF-16LE for `group2.exe` with a leading
byte-order mark). The `/EF /F 3 0 R` line references object `3 0` as the
container of the actual file content.*

#### Inspecting the embedded file object

Before we extract out payload, we directly inspect the object `3 0` to understand the nature of the structure, specifically, what compression or filters the PDF specification applies to the stream. A PDF stream may be accompanied by any of the combination of `/Filter` values. These commonly occurring values are `/FlateDecode` (zlib deflate which is the compression algorithm used in ZIP), `/ASCIIHexDecode`, `/ASCII85Decode`, `/LZWDecode`, and `/Crypt`. To revert the stream back to the original file, we need to apply these filters in reverse order.

![pdf-parser --object 3 showing /Type /EmbeddedFile, /Subtype /application/octet-stream, /Filter /FlateDecode](images/pdfparser_object3.png)

*Figure 4: Object `3 0` is confirmed as `/Type /EmbeddedFile` with
`/Subtype /application/octet-stream` and `/Filter /FlateDecode`. The subtype
`application/octet-stream` is the MIME type for "arbitrary binary data" —
PDF is deliberately not committing to whether the payload is an executable, a
document, or anything else. The `/FlateDecode` filter means the stream bytes
on disk are zlib-compressed, they must be inflated to recover the original
file.*

#### Extracting the payload

Knowing the object and how it's compressed, dumping it was simple. We used `pdf-parser.py --object 3 --filter --dump <outpath>` which applies all defined streams filter sequentially to write the resulting bytes to the specified file. The recovered bytes were saved to `group2.exe` within the downloads directory of the FLARE VM analysis system.

#### Hashing and identifying the recovered binary

After the PE was on the disk as ia standalone file, common identification techniques could be employed.

![PowerShell Get-FileHash computing SHA-256 of the extracted group2.exe](images/pefile_hash.png)

*Figure 5: SHA-256 of the extracted binary*

The hash serves two uses, first is a canonical identifier of the sample, every subsequent finding in this report is attributable to this specific SHA-256 that the reader can recompute and verify on their own copy of the extracted file. Second, hash can be searched against threat intelligence sources like VirusTotal, MalwareBazaar, and Hybrid Analysis to see if the sample has been seen before in the wild.

The complete metadata for the extracted binary is:

| Property  | Value |
|---|---|
| File type | PE32+ executable for MS Windows, x86-64 |
| File size | 7.50 KiB (7680 bytes) |
| MD5       | `0ce70f0f07c21bf4290a1c0308fc4f46` |
| SHA-1     | `1562f662214044749c1fa5601f52332ed347e011` |
| SHA-256   | `89dfbfeda4ec1d4f6d28ab376cc28468f42f98ccc694cd8e9a5033a34c2f7a7b` |
| ssdeep    | `24:eFGSGj30pFLknehtht6dp506WcNYKan2DOIRwQa/FlGVKbuqiksvckOp:iGb0onehthEdc2GJCO1Qa9QQqilk` |

The low size of the binary (less than 8KB) also appears to be a behavioural characteristic. A sophisticated malware application like a banking trojan, a piece of ransomware, or a backdoor, when fully implemented (with their necessary functionality and configuration files, along with statically-linked dependencies in most cases), will often range between several hundreds of kilobytes and several megabytes in size. A Windows PE of 7.5KB has a minimal amount of real code it. It is size that would be expected from a **stager**, a light first-stage payload designed solely for the purpose of downloading and executing the second-stage payload from the attackers' servers in memory. The static analysis conducted below helps to prove this.

#### Threat intelligence lookup

![VirusTotal search returns no matching results for the extracted SHA-256](images/virustotal_nohits.png)

*Figure 6: VirusTotal returns no matching results for the extracted SHA-256
as of the analysis date.* 

The sample has never been seen by any of the AV engines feeding into VirusTotal, nor by the community comment system. A later Hybrid Analysis submission identified both the executable and the PDF samples as malicious with a high threat score and broad AV detection with multiple mapped ATT&CK techniques. Either way, we have to do our own classification and not rely on other external results.

![HybridAnalysis search returns matching results for the extracted SHA-256 of the PDF file.](images/HybridAnalysis_PDF1.png)

*Figure 7: HybridAnalysis returns matching results for the extracted SHA-256 of the PDF file.* 

![HybridAnalysis search returns matching results for the extracted SHA-256 of the exe file.](images/HybridAnalysis_exe1.png)

*Figure 8: HybridAnalysis returns matching results for the extracted SHA-256 of the embedded executable file.* 

#### Binary identification with Detect It Easy

We then used DIE to get the compiler, linker, architecture, and potentially high-level indicators, such as packers or protectors, from the dumped executable.

![Detect It Easy on group2.exe reporting PE64 AMD64 GUI, MSVC 19.36.35207, Visual Studio 2022 v17.6, and a packer heuristic](images/die_exe.png)

*Figure 9: DIE reports `group2.exe` as a 64-bit GUI-subsystem PE (`PE64`,
`AMD64`, `GUI`), built with Microsoft Visual C/C++ version 19.36.35207 and
linked with Microsoft Linker 14.36.35207 (Visual Studio 2022, v17.6). The
heuristic line `(Heur)Packer: Compressed or packed data [Last section EP]` is
the most interesting single finding from this step* 

DIE's packer heuristic reported the entry point to be in the **last** section of the PE rather than in the first section of the file (`.text`). An normal MSVC produced binary has all executable code located in `.text`, which is the first code section, an entry point in a trailing section will most certainly indicate either a packer that uncompresses and then jumps into the original code or a bespoke loader. Given the file's tiny size, a loader is more probable.

#### PE structure analysis

The portable executable structure of the extracted binary was analyzed with two different, but complimentary analysis tools. PE-bear allowed for exploration and inspection of the binary at the section level, while CFF Explorer was used to examine the section detailed characteristics.

![PE-bear tree view showing DOS Header, NT Headers, Section Headers, and five sections ending with .glav containing the entry point](images/pebear_sections.png)

*Figure 10: PE-bear's tree view of `group2.exe`.*

The section tree has 5 sections, named `.text`, `.rdata`, `.data`, `.pdata`, and `.glav`. The first four sections are as expected from the Microsoft linker output for a 64 bit PE. The section named `.glav` is **non-standard**. Normally, this section will not be generated by Microsoft's linker under any default compilation settings. The entry point mark (`EP=1A00`) clearly shows the program starts execution at this location inside `.glav`, which is the last loaded section. This is an clear indicator of a manually assembled PE loader with an embedded shellcode, not a typical compiled program.

![CFF Explorer section table showing .glav with virtual size 0x375, characteristics 0xE0000020](images/cff_sections.png)

*Figure 11: CFF Explorer VIII section characteristics table. The `.glav`
section has virtual size `0x375`, virtual address `0x5000`, raw size `0x400`,
and **Characteristics `0xE0000020`**. This value decodes to the bitwise OR
of four PE section flags: `IMAGE_SCN_CNT_CODE (0x00000020)`,
`IMAGE_SCN_MEM_EXECUTE (0x20000000)`, `IMAGE_SCN_MEM_READ (0x40000000)`, and
`IMAGE_SCN_MEM_WRITE (0x80000000)`.* 

The combinations `MEMEXECUTE | MEMREAD | MEM_WRITE`, or simply RWX, is exceedingly rare to find among normal applications. Compilers ans operating systems enforce the W^X principle, stating a page can either be writable or executable, but not both through the use of section flags in compilation time and Data Execution Prevention at runtime. If a PE section is built with the RWX flag, it bypasses this first layer of security and suggests a shellcode container: code which needs to be writeable, as it will alter itself while executing, and executable, as it is the final place the control is transferred to.

Given the combination of the name of the section, `.glav`, the section having RWX permissions, the entry point being located within the trailing section, and the presence of very little content within the `.text` section clearly indicates that `group2.exe` is not a normal program, but a loader. The other sections, `.text`, `.rdata`, `.data`, `.pdata`, have been added purely to make it seem like a fully compliant PE, when the main part of the malicious application is in fact in `.glav`.

#### Entropy analysis

The expected next step after finding something unusual is to check the entropy of its contents. This gives a value from 0-8 (measured in bits per byte) indicating how randomly distributed the byte values are in that region of the file. This value often indicates what kind of data is stored: a value close to 0 means repetitive data (e.g. long runs of the same byte), 4-5 indicates ASCII text, 5.5-6.5 means x86/x64 machine code and anything above 7.5 is likely compressed/encrypted.

![DIE entropy analysis of group2.exe showing per-section entropy values and overall profile](images/pebear_entropy.png)

*Figure 12: Detect It Easy's entropy analysis of `group2.exe`.*

While the heuristic scanner in DIE flags the binary as "probably packed" (Figure 9), the entropy analyzer says "not packed (21%)" at the end. As seen from the two analyses, the two subsystems are looking at two different things. The heuristic analysis looks for **structural** clues that a packer may be used (location of the EP, arrangement of the sections, format of the IAT). The entropy analysis, on the other hand, looks for **statistical** clues (distribution of the bytes values). A "packed" file must display both features: it must show a structural anomaly, and the section containing the compressed data must have an entropy that suggests its content is not regular machine code (e.g., entropy of 7.5 bits/byte or higher). In this case, section entropies are: 2.87 bits/byte (`.rdata`), 0.03 (`.data`), 0.10 (`.pdata`) and 5.76 (`.glav`). Overall file entropy is 1.72 bits/byte. The entropy 5.76 bits/byte in section `.glav` is indeed higher than that in other sections. It correlates with the local maximum seen in the entropy plot around this section, showing a peak of about 6.6 bits/byte. However, this peak is well within the expected entropy for tightly hand-written x64 machine code (which can be in the range 5.5-6.5 bits/byte), and very far from the threshold that would suggest encryption (about 7.9 bits/byte) or compression (about 7.5 bits/byte). In summary, the reason for two different results from the tools is: this binary shows the **structure** of a packed file (EP located inside a trailing custom section), but not the **content**. It is the signature of a shellcode loader. Machine code in `.glav` is intended for direct execution in x64, not for unzipping before being executed. As confirmed below in the "Advanced Static Analysis" section, this implies we will be able to disassemble this section directly without having to peel off any encryption or compression wrapper.

#### Import Address Table

PE file's Import Address Table (IAT) is the list of externall DLL functions that the binary declares that it will need to import at load time. Once loaded, the Windows loader binds each entry in the IAT to a function pointer before control is passed to the entry point of the program. Usually the IAT is one of the most useful sources of information to a static analyst: an application that imports `CreateFileA`, `WriteFile`, and `CloseHandle` clearly performs file I/O, an application that imports `InternetOpenUrlA` and `HttpSendRequestA` performs HTTP, and an application that imports `CryptAcquireContextA`, `CryptHashData`, and `CryptEncrypt` performs cryptography. Typically, the IAT of a PE provides a good summary of the functions used by the executable.

![PE-bear imports tab showing a single entry: KERNEL32.dll!VirtualProtect](images/pebear_imports.png)

*Figure 13: The complete Import Address Table of `group2.exe`.*

Interestingly, there is only **one** function imported among all DLLs: `KERNEL32.dll!VirtualProtect`. It is extraordinary. A Windows GUI Application (as PE Header tells us that this binary is one) should import at least window-creation, message-pump and GDI functions from `user32.dll` and `gdi32.dll`, and lots of utility functions from `kernel32.dll`. A 1-function IAT is not only small, but also the smallest possible useful IAT.

The interpretation is simple and follows the well-documented malware technique: **the binary does not declare its dependencies in the import table because it looks them up dynamically at runtime**. In other words, instead of relying on the Windows loader to fill in pointers for WinINet, kernel, and networking functions in the IAT, it does the look up on its own. By walking the Process Environment Block (PEB) at runtime and enumerating through loaded modules, it will then hash the exported function name with a very lightweight hashing function and compare that hash value against pre-defined hash constants in the shellcode. This method is called **API hashing**, and was made famous by Stephen Fewer in mid-2000s when he released his public version of `block_api` shellcode. There are two obvious defensive purposes for the attacker. Static analysts looking only at the IAT can't tell what the intentions of the binary are, since the real API call surface lies behind meaningless 32-bit hashes. Also, the absence of an IAT reference to, for example, `InternetConnectA` makes the binary safe from generic detection rules flagging any binary importing functions for WinINet as suspicious.

The only import present, `VirtualProtect`, is in line with this assumption as a runtime loader will need to make the code pages executable after writing them and `VirtualProtect` is the standard Windows API call to set memory-protection flags on an allocated region. Because the loader will be able to gain a valid function pointer to `VirtualProtect` via the IAT and no function signature maliciousity would appear to be tied to this single function the attacker has built out the rest of its API resolution mechanism from this one starting point.

#### Static string extraction

The extracted strings of a binary often reveal hardcoded URLs, filenames,
error messages, and configuration data. FLOSS (FireEye Labs Obfuscated String
Solver) was used in addition to the simpler `strings` utility because FLOSS
applies control-flow analysis to the binary's code and can recover strings
that are assembled or decoded at runtime rather than stored as static data.

![FLOSS static strings output showing section names, PAYLOAD marker, shellcode fragments, wininet, User-Agent, 212.22.1.3, and a 120-character URI](images/floss_strings_1.png)

*Figure 14: FLOSS static strings output — the richer half.*

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

*Figure 15: FLOSS stack strings and decoded strings output.*

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

*Figure 16: `capa` reports "no capabilities found" for `group2.exe`.*

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

*Figure 17: `osslsigncode verify group2.exe` reports "No signature found".*

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

*Figure 18: `rabin2` cross-verification.*
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

*Figure 19: Ghidra's disassembly of `FUN_140005191`.*

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

*Figure 20: Ghidra's disassembly of `FUN_14000522E`.*

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

*Figure 21: radare2 identifies the shellcode entry point.*

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

*Figure 22: radare2 extraction of hash constants and arguments at the final
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
disassembly (Figures 19 and 20) and additional radare2 seeks across the
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

*Figure 23: Generation of a vanilla Metasploit reference binary and ssdeep
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
