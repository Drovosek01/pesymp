// pesymp - symbol search in PE files (Windows analog of macOS symp).
// Scans the export table, import table, COFF symbol table, and import thunks,
// prints name, RVA, VA and file offset for each match.
//
// Build (see build.ps1):
//   csc /nologo /optimize+ /out:pesymp.exe Program.cs
//
// Examples:
//   pesymp.exe CreateFile C:\Windows\System32\kernel32.dll
//   pesymp.exe -r "Api.*Buffer" app.exe other.dll
//   pesymp.exe -l app.exe          (list all symbols)
//   pesymp.exe -a WinVerifyTrust app.exe  (addresses only)
//   pesymp.exe -n CreateFile kernel32.dll  (names only)
//   pesymp.exe -f json -l app.exe > output.json
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

internal static class Pesym
{
    private sealed class Options
    {
        public string Pattern;
        public List<string> Files = new List<string>();
        public bool Regex;
        public bool IgnoreCase = true;
        public bool All;
        public bool ExportsOnly;
        public bool CoffOnly;
        
        // Опции для гибкого вывода
        public bool AddressesOnly;
        public bool NamesOnly;
        public bool NoHeader;
        public string Format = "table"; // table, raw, csv, json
    }

    private sealed class Section
    {
        public string Name;
        public uint VirtualSize;
        public uint VirtualAddress;
        public uint SizeOfRawData;
        public uint PointerToRawData;
        public uint Characteristics;
        public bool IsExecutable { get { return (Characteristics & 0x20000000) != 0; } }
    }

    private sealed class Symbol
    {
        public string Name;
        public string Source;   // "export" | "import" | "coff" | "thunk" | "thunk-call"
        public uint Value;      // RVA (export/import/thunk) or section offset (coff)
        public string Section;  // section name or ""
        public bool RvaBased;
    }

    private static int Main(string[] args)
    {
        try { Console.OutputEncoding = Encoding.UTF8; } catch { }
        
        Options opt;
        try { opt = ParseArgs(args); }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Argument error: " + ex.Message);
            PrintUsage();
            return 2;
        }
        
        if (opt == null) { PrintUsage(); return 0; }

        Regex regex = null;
        if (!opt.All)
        {
            var opts = RegexOptions.CultureInvariant;
            if (opt.IgnoreCase) opts |= RegexOptions.IgnoreCase;
            regex = opt.Regex
                ? new Regex(opt.Pattern, opts)
                : new Regex(Regex.Escape(opt.Pattern), opts);
        }

        int exitCode = 0;
        var allResults = new List<Dictionary<string, object>>();

        foreach (string fileSpec in opt.Files)
        {
            string[] files;
            if (fileSpec.IndexOfAny(new[] { '*', '?' }) >= 0)
            {
                string dir = Path.GetDirectoryName(fileSpec);
                if (string.IsNullOrEmpty(dir)) dir = ".";
                string name = Path.GetFileName(fileSpec);
                files = Directory.GetFiles(dir, name);
            }
            else
            {
                files = new[] { fileSpec };
            }

            foreach (string file in files)
            {
                var results = AnalyzeFile(file, regex, opt);
                if (results == null)
                {
                    exitCode = 1;
                    continue;
                }
                
                if (opt.Format == "json")
                {
                    allResults.AddRange(results);
                }
            }
        }

        // Безопасный вывод JSON без использования форматных строк Console.WriteLine
        if (opt.Format == "json" && allResults.Count > 0)
        {
            Console.WriteLine("[");
            for (int i = 0; i < allResults.Count; i++)
            {
                var r = allResults[i];
                Console.Write("  {");
                Console.Write("\"file\":\"" + EscapeJson(Convert.ToString(r["file"])) + "\",");
                Console.Write("\"source\":\"" + EscapeJson(Convert.ToString(r["source"])) + "\",");
                Console.Write("\"name\":\"" + EscapeJson(Convert.ToString(r["name"])) + "\",");
                Console.Write("\"rva\":\"" + Convert.ToString(r["rva"]) + "\",");
                Console.Write("\"va\":\"" + Convert.ToString(r["va"]) + "\",");
                Console.Write("\"offset\":\"" + Convert.ToString(r["offset"]) + "\",");
                Console.Write("\"section\":\"" + EscapeJson(Convert.ToString(r["section"])) + "\"");
                
                // Добавляем запятую для всех элементов, кроме последнего
                string comma = (i < allResults.Count - 1) ? "," : "";
                Console.WriteLine("}" + comma);
            }
            Console.WriteLine("]");
        }

        return exitCode;
    }

    private static string EscapeJson(string s)
    {
        if (string.IsNullOrEmpty(s)) return "";
        return s.Replace("\\", "\\\\")
                .Replace("\"", "\\\"")
                .Replace("\n", "\\n")
                .Replace("\r", "\\r")
                .Replace("\t", "\\t");
    }

    private static void PrintUsage()
    {
        Console.WriteLine("Usage: pesymp [options] <pattern> <file...>");
        Console.WriteLine("  pattern          substring (or -r regexp) of symbol name");
        Console.WriteLine();
        Console.WriteLine("Search options:");
        Console.WriteLine("  -r               treat pattern as regular expression");
        Console.WriteLine("  -c               case-sensitive search");
        Console.WriteLine("  -l               list all symbols (pattern not needed)");
        Console.WriteLine("  -x               export table only");
        Console.WriteLine("  -s               COFF symbol table only");
        Console.WriteLine();
        Console.WriteLine("Output options:");
        Console.WriteLine("  -a               output addresses only (one per line)");
        Console.WriteLine("  -n               output names only (one per line)");
        Console.WriteLine("  --no-header      suppress table headers");
        Console.WriteLine("  -f <format>      output format: table (default), raw, csv, json");
        Console.WriteLine();
        Console.WriteLine("Examples:");
        Console.WriteLine("  pesymp.exe CreateFile kernel32.dll");
        Console.WriteLine("  pesymp.exe -a WinVerifyTrust app.exe > addresses.txt");
        Console.WriteLine("  pesymp.exe -n -l app.exe > all_symbols.txt");
        Console.WriteLine("  pesymp.exe -f json -l app.exe > output.json");
    }

    private static Options ParseArgs(string[] args)
    {
        var opt = new Options();
        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i];
            if (a == "-r" || a == "/r") opt.Regex = true;
            else if (a == "-c" || a == "/c") opt.IgnoreCase = false;
            else if (a == "-l" || a == "/l") opt.All = true;
            else if (a == "-x" || a == "/x") opt.ExportsOnly = true;
            else if (a == "-s" || a == "/s") opt.CoffOnly = true;
            else if (a == "-a" || a == "/a" || a == "--addresses-only") opt.AddressesOnly = true;
            else if (a == "-n" || a == "/n" || a == "--names-only") opt.NamesOnly = true;
            else if (a == "--no-header") opt.NoHeader = true;
            else if (a == "-f" || a == "/f" || a == "--format")
            {
                if (i + 1 >= args.Length) throw new Exception("missing format after -f");
                opt.Format = args[++i].ToLower();
                if (opt.Format != "table" && opt.Format != "raw" && opt.Format != "csv" && opt.Format != "json")
                    throw new Exception("unknown format: " + opt.Format);
            }
            else if (a == "-h" || a == "/h" || a == "--help") return null;
            else if (a.Length > 1 && (a[0] == '-' || a[0] == '/'))
                throw new Exception("unknown option: " + a);
            else if (opt.Pattern == null && !opt.All) opt.Pattern = a;
            else opt.Files.Add(a);
        }

        if (!opt.All && opt.Pattern == null) throw new Exception("no pattern given (or use -l)");
        if (opt.Files.Count == 0) throw new Exception("no input file given");
        if (opt.ExportsOnly && opt.CoffOnly) throw new Exception("-x and -s are mutually exclusive");
        if (opt.AddressesOnly && opt.NamesOnly) throw new Exception("-a and -n are mutually exclusive");
        
        return opt;
    }

    private static List<Dictionary<string, object>> AnalyzeFile(string path, Regex regex, Options opt)
    {
        byte[] data;
        try { data = File.ReadAllBytes(path); }
        catch (Exception ex)
        {
            Console.Error.WriteLine("pesym: cannot read {0}: {1}", path, ex.Message);
            return null;
        }

        PeImage pe;
        try { pe = PeImage.Parse(data); }
        catch (Exception ex)
        {
            Console.Error.WriteLine("pesym: {0}: {1}", path, ex.Message);
            return null;
        }

        var symbols = new List<Symbol>();
        List<Symbol> imports = null;

        if (!opt.CoffOnly)
            try { symbols.AddRange(pe.GetExports()); }
            catch (Exception ex) { Console.Error.WriteLine("pesym: {0}: export table error: {1}", path, ex.Message); }

        if (!opt.ExportsOnly)
            try { imports = pe.GetImports(); symbols.AddRange(imports); }
            catch (Exception ex) { Console.Error.WriteLine("pesym: {0}: import table error: {1}", path, ex.Message); }

        if (!opt.ExportsOnly)
            try { symbols.AddRange(pe.GetCoffSymbols()); }
            catch (Exception ex) { Console.Error.WriteLine("pesym: {0}: COFF symbol table error: {1}", path, ex.Message); }

        if (imports != null)
            try { symbols.AddRange(pe.GetImportThunks(imports)); }
            catch (Exception ex) { Console.Error.WriteLine("pesym: {0}: thunk scan error: {1}", path, ex.Message); }

        var results = new List<Dictionary<string, object>>();
        bool printedHeader = false;

        foreach (Symbol sym in symbols)
        {
            if (sym == null || string.IsNullOrEmpty(sym.Name)) continue;
            if (regex != null && !regex.IsMatch(sym.Name)) continue;

            try
            {
                uint rva = sym.RvaBased ? sym.Value : 0;
                ulong va = rva != 0 ? pe.ImageBase + rva : 0;
                long? fileOffset = sym.RvaBased
                    ? pe.RvaToFileOffset(rva)
                    : (pe.SectionByName(sym.Section) != null ? pe.SectionalToFileOffset(sym.Section, sym.Value) : (long?)null);

                // Инициализация словаря, совместимая с C# 5.0
                var result = new Dictionary<string, object>();
                result.Add("file", path);
                result.Add("source", sym.Source);
                result.Add("name", sym.Name);
                result.Add("rva", rva != 0 ? "0x" + rva.ToString("X") : "-");
                result.Add("va", va != 0 ? "0x" + va.ToString("X") : "-");
                result.Add("offset", fileOffset.HasValue ? "0x" + fileOffset.Value.ToString("X") : "?");
                result.Add("section", sym.Section != null && sym.Section.Length > 0 ? sym.Section : "-");

                results.Add(result);

                // Вывод в зависимости от формата (JSON обрабатывается отдельно в Main)
                if (opt.Format == "json") continue;

                if (opt.AddressesOnly)
                {
                    if (fileOffset.HasValue)
                        Console.WriteLine("0x{0:X}", fileOffset.Value);
                    else if (va != 0)
                        Console.WriteLine("0x{0:X}", va);
                    else if (rva != 0)
                        Console.WriteLine("0x{0:X}", rva);
                }
                else if (opt.NamesOnly)
                {
                    Console.WriteLine(sym.Name);
                }
                else if (opt.Format == "raw")
                {
                    Console.WriteLine("{0}\t{1}\t{2}\t{3}\t{4}\t{5}",
                        sym.Source, sym.Name, result["rva"], result["va"], result["offset"], result["section"]);
                }
                else if (opt.Format == "csv")
                {
                    if (!printedHeader && !opt.NoHeader)
                    {
                        Console.WriteLine("file,source,name,rva,va,offset,section");
                        printedHeader = true;
                    }
                    Console.WriteLine("{0},{1},{2},{3},{4},{5},{6}",
                        EscapeCsv(path), EscapeCsv(sym.Source), EscapeCsv(sym.Name),
                        result["rva"], result["va"], result["offset"], EscapeCsv(result["section"].ToString()));
                }
                else // table format
                {
                    if (!printedHeader && !opt.NoHeader)
                    {
                        Console.WriteLine("== {0} (ImageBase=0x{1:X}) ==", path, pe.ImageBase);
                        Console.WriteLine("  {0,-10} {1,-12} {2,-12} {3,-12} {4,-8} {5}",
                            "Source", "RVA", "VA", "FileOffset", "Section", "Name");
                        printedHeader = true;
                    }
                    Console.WriteLine("  {0,-10} {1,-12} {2,-12} {3,-12} {4,-8} {5}",
                        sym.Source, result["rva"], result["va"], result["offset"], result["section"], sym.Name);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("  {0,-10} <error resolving symbol '{1}': {2}>",
                    sym.Source, sym.Name, ex.Message);
            }
        }

        return results;
    }

    private static string EscapeCsv(string s)
    {
        if (string.IsNullOrEmpty(s)) return "";
        if (s.Contains(",") || s.Contains("\"") || s.Contains("\n"))
            return "\"" + s.Replace("\"", "\"\"") + "\"";
        return s;
    }

    private sealed class PeImage
    {
        private byte[] _data;
        public ulong ImageBase;
        public List<Section> Sections = new List<Section>();
        private uint _exportRva;
        private uint _importRva;
        private bool _isPe32Plus;

        public static PeImage Parse(byte[] data)
        {
            if (data.Length < 0x40 || data[0] != 'M' || data[1] != 'Z')
                throw new Exception("not an MZ file");
            uint peOff = ReadU32(data, 0x3C);
            if (peOff + 4 > data.Length || data[peOff] != 'P' || data[peOff + 1] != 'E' || data[peOff + 2] != 0 || data[peOff + 3] != 0)
                throw new Exception("PE signature not found");
            var pe = new PeImage { _data = data };
            ushort numSections = ReadU16(data, (int)peOff + 6);
            ushort sizeOptHeader = ReadU16(data, (int)peOff + 20);
            int optStart = (int)peOff + 24;
            ushort magic = ReadU16(data, optStart);
            if (magic != 0x10B && magic != 0x20B) throw new Exception("unknown optional header");
            pe._isPe32Plus = (magic == 0x20B);
            pe.ImageBase = magic == 0x20B
                ? ReadU64(data, optStart + 24)
                : ReadU32(data, optStart + 28);
            int dataDirStart = optStart + (magic == 0x20B ? 112 : 96);
            pe._exportRva = ReadU32(data, dataDirStart);
            pe._importRva = ReadU32(data, dataDirStart + 8);
            int secStart = optStart + sizeOptHeader;
            for (int i = 0; i < numSections && i < 96; i++)
            {
                int p = secStart + i * 40;
                if (p + 40 > data.Length) break;
                var s = new Section
                {
                    Name = Encoding.ASCII.GetString(data, p, 8).TrimEnd('\0'),
                    VirtualSize = ReadU32(data, p + 8),
                    VirtualAddress = ReadU32(data, p + 12),
                    SizeOfRawData = ReadU32(data, p + 16),
                    PointerToRawData = ReadU32(data, p + 20),
                    Characteristics = ReadU32(data, p + 36),
                };
                pe.Sections.Add(s);
            }
            return pe;
        }

        public List<Symbol> GetExports()
        {
            var list = new List<Symbol>();
            if (_exportRva == 0) return list;
            long dirOff = RvaToFileOffset(_exportRva) ?? -1;
            if (dirOff < 0 || dirOff + 40 > _data.Length) return list;
            uint numNames = ReadU32(_data, dirOff + 24);
            uint addrNames = ReadU32(_data, dirOff + 32);
            if (numNames == 0 || numNames > 1000000) return list;
            long namesOff = RvaToFileOffset(addrNames) ?? -1;
            if (namesOff < 0) return list;
            for (uint i = 0; i < numNames; i++)
            {
                if (namesOff + (i + 1) * 4 > _data.Length) break;
                uint nameRva = ReadU32(_data, namesOff + (int)(i * 4));
                string name = ReadCString(nameRva);
                if (string.IsNullOrEmpty(name)) continue;
                list.Add(new Symbol { Name = name, Source = "export", Value = nameRva, RvaBased = true });
            }
            return list;
        }

        public List<Symbol> GetImports()
        {
            var list = new List<Symbol>();
            if (_importRva == 0) return list;
            int size = 0;
            for (uint rva = _importRva; ; rva += 20)
            {
                long? off = RvaToFileOffset(rva);
                if (!off.HasValue || off.Value + 20 > _data.Length) break;
                if (ReadU32(_data, off.Value) == 0 && ReadU32(_data, off.Value + 12) == 0) break;
                uint originalThunk = ReadU32(_data, off.Value);
                uint firstThunk = ReadU32(_data, off.Value + 16);
                if (originalThunk == 0 || firstThunk == 0) continue;
                uint thunkRva = originalThunk != 0 ? originalThunk : firstThunk;
                long? thunkOff = RvaToFileOffset(thunkRva);
                if (!thunkOff.HasValue) continue;
                for (uint i = 0; ; i++)
                {
                    uint entryRva = thunkRva + i * 4;
                    long? eo = RvaToFileOffset(entryRva);
                    if (!eo.HasValue || eo.Value + 4 > _data.Length) break;
                    uint entry = ReadU32(_data, eo.Value);
                    if (entry == 0) break;
                    string name;
                    if ((entry & 0x80000000) != 0)
                    {
                        name = "#" + (entry & 0xFFFF);
                    }
                    else
                    {
                        long? hintOff = RvaToFileOffset(entry);
                        name = hintOff.HasValue && hintOff.Value + 2 < _data.Length
                            ? ReadCStringAt(hintOff.Value + 2)
                            : null;
                    }
                    if (string.IsNullOrEmpty(name)) continue;
                    uint iatSlotRva = firstThunk + i * 4;
                    list.Add(new Symbol { Name = name, Source = "import", Value = iatSlotRva, RvaBased = true });
                }
                if (++size > 4096) break;
            }
            return list;
        }

        public List<Symbol> GetImportThunks(List<Symbol> imports)
        {
            var list = new List<Symbol>();
            if (imports == null || imports.Count == 0) return list;
            var iatMap = new Dictionary<uint, Symbol>();
            foreach (Symbol s in imports)
            {
                if (!iatMap.ContainsKey(s.Value)) iatMap[s.Value] = s;
            }
            foreach (Section sec in Sections)
            {
                if (!sec.IsExecutable || sec.SizeOfRawData < 6) continue;
                long start = sec.PointerToRawData;
                long limit = Math.Min(sec.SizeOfRawData, _data.Length - start) - 6;
                for (long i = 0; i < limit; i++)
                {
                    long p = start + i;
                    byte op0 = _data[p];
                    byte op1 = _data[p + 1];
                    bool isJmp = (op0 == 0xFF && op1 == 0x25);
                    bool isCall = (op0 == 0xFF && op1 == 0x15);
                    if (!isJmp && !isCall) continue;
                    uint insnRva = sec.VirtualAddress + (uint)i;
                    uint targetRva;
                    if (_isPe32Plus)
                    {
                        int disp = (int)ReadU32(_data, p + 2);
                        targetRva = unchecked(insnRva + 6 + (uint)disp);
                    }
                    else
                    {
                        uint targetVa = ReadU32(_data, p + 2);
                        if (targetVa < (uint)ImageBase || (ulong)targetVa - ImageBase > 0xFFFFFFFF) continue;
                        targetRva = (uint)((ulong)targetVa - ImageBase);
                    }
                    Symbol imp;
                    if (!iatMap.TryGetValue(targetRva, out imp)) continue;
                    var thunk = new Symbol
                    {
                        Name = imp.Name,
                        Source = isJmp ? "thunk" : "thunk-call",
                        Value = insnRva,
                        Section = sec.Name,
                        RvaBased = true
                    };
                    list.Add(thunk);
                    if (isJmp) i += 5;
                }
            }
            return list;
        }

        public List<Symbol> GetCoffSymbols()
        {
            var list = new List<Symbol>();
            uint peOff = ReadU32(_data, 0x3C);
            uint symPtr = ReadU32(_data, (int)peOff + 12);
            uint numSyms = ReadU32(_data, (int)peOff + 16);
            if (symPtr == 0 || numSyms == 0 || numSyms > 10000000) return list;
            if (symPtr >= _data.Length) return list;
            long strTable = symPtr + numSyms * 18;
            if (strTable + 4 > _data.Length) return list;
            uint strTableSize = ReadU32(_data, strTable);
            uint i = 0;
            while (i < numSyms)
            {
                long p = (long)symPtr + (long)i * 18;
                if (p < 0 || p + 18 > _data.Length) break;
                string name;
                if (ReadU32(_data, p) == 0)
                {
                    uint strOff = ReadU32(_data, p + 4);
                    name = (strOff + 4 < strTableSize && strTable + strOff < _data.Length)
                        ? ReadCStringAt(strTable + strOff) : null;
                }
                else
                {
                    name = Encoding.ASCII.GetString(_data, (int)p, 8).TrimEnd('\0');
                }
                uint value = ReadU32(_data, p + 8);
                short sectionNum = (short)ReadU16(_data, p + 12);
                byte aux = _data[p + 17];
                if (!string.IsNullOrEmpty(name) && sectionNum > 0 && sectionNum <= Sections.Count)
                {
                    list.Add(new Symbol
                    {
                        Name = name,
                        Source = "coff",
                        Value = value,
                        Section = Sections[sectionNum - 1].Name,
                        RvaBased = false
                    });
                }
                i += (uint)(1 + aux);
            }
            return list;
        }

        public long? RvaToFileOffset(uint rva)
        {
            foreach (var s in Sections)
            {
                uint size = Math.Max(s.VirtualSize, s.SizeOfRawData);
                if (rva >= s.VirtualAddress && rva < s.VirtualAddress + size)
                {
                    long off = (long)s.PointerToRawData + (rva - s.VirtualAddress);
                    return off < _data.Length ? off : (long?)null;
                }
            }
            long hdr = rva;
            return hdr < _data.Length ? hdr : (long?)null;
        }

        public Section SectionByName(string name)
        {
            foreach (var s in Sections) if (s.Name == name) return s;
            return null;
        }

        public long? SectionalToFileOffset(string sectionName, uint value)
        {
            var s = SectionByName(sectionName);
            if (s == null || value >= s.SizeOfRawData) return null;
            return (long)s.PointerToRawData + value;
        }

        private string ReadCString(uint rva)
        {
            long? off = RvaToFileOffset(rva);
            return off.HasValue ? ReadCStringAt(off.Value) : null;
        }

        private string ReadCStringAt(long offset)
        {
            if (offset < 0 || offset >= _data.Length) return null;
            long end = offset;
            while (end < _data.Length && _data[end] != 0) end++;
            return Encoding.ASCII.GetString(_data, (int)offset, (int)(end - offset));
        }
    }

    private static ushort ReadU16(byte[] b, long o)
    {
        return (ushort)(b[o] | (b[o + 1] << 8));
    }

    private static uint ReadU32(byte[] b, long o)
    {
        return (uint)(b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24));
    }

    private static ulong ReadU64(byte[] b, long o)
    {
        return ReadU32(b, o) | ((ulong)ReadU32(b, o + 4) << 32);
    }
}