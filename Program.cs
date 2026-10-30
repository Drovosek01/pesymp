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
//   pesymp.exe -t thunk -q --addr va WinVerifyTrust app.exe  (VA of thunks only)
//   pesymp.exe -t export -t import -f json -l app.exe > output.json
//   pesymp.exe CreateFile kernel32.dll -x 909090             (patch found offsets)
//   pesymp.exe -x 909090 -- 0x10002a704 file.exe             (patch by direct offset)
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
        
        // Таблицы для поиска (export, import, coff, thunk, thunk-call, all)
        public HashSet<string> Tables = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "all" };
        
        // Опции для гибкого вывода
        public bool Quiet;
        public string AddrType = "offset"; // rva, va, offset
        public bool NamesOnly;
        public bool NoHeader;
        public string Format = "table"; // table, raw, csv, json
        
        // Опции для патчинга
        public byte[] PatchData;
        public long? PatchOffset;
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

    // ---------------------------------------------------------------------
    // Windowed buffered reader over a FileStream.
    // ---------------------------------------------------------------------
    private sealed class PeReader : IDisposable
    {
        private const int BufferSize = 64 * 1024;
        private readonly FileStream _stream;
        private readonly byte[] _buffer = new byte[BufferSize];
        private long _bufferStart = -1;
        private int _bufferLen;
        public readonly long Length;

        public PeReader(string path)
        {
            _stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            Length = _stream.Length;
        }

        public bool CanRead(long offset, int len)
        {
            return offset >= 0 && len >= 0 && offset + len <= Length;
        }

        private void EnsureRange(long offset, int len)
        {
            if (offset < 0 || offset + len > Length)
                throw new IOException("read past EOF");
            if (_bufferStart >= 0 &&
                offset >= _bufferStart &&
                offset + len <= _bufferStart + _bufferLen)
                return;

            _stream.Seek(offset, SeekOrigin.Begin);
            int toRead = (int)Math.Min(BufferSize, Length - offset);
            int read = 0;
            while (read < toRead)
            {
                int n = _stream.Read(_buffer, read, toRead - read);
                if (n <= 0) break;
                read += n;
            }
            _bufferStart = offset;
            _bufferLen = read;
        }

        public byte ReadByte(long offset)
        {
            EnsureRange(offset, 1);
            return _buffer[offset - _bufferStart];
        }

        public ushort ReadU16(long offset)
        {
            EnsureRange(offset, 2);
            int i = (int)(offset - _bufferStart);
            return (ushort)(_buffer[i] | (_buffer[i + 1] << 8));
        }

        public uint ReadU32(long offset)
        {
            EnsureRange(offset, 4);
            int i = (int)(offset - _bufferStart);
            return (uint)(_buffer[i] | (_buffer[i + 1] << 8) |
                          (_buffer[i + 2] << 16) | (_buffer[i + 3] << 24));
        }

        public ulong ReadU64(long offset)
        {
            return ReadU32(offset) | ((ulong)ReadU32(offset + 4) << 32);
        }

        /// <summary>Reads a byte range into dst. For small requests uses the cache,
        /// for large ones reads directly from the stream.</summary>
        public int ReadBytes(long offset, byte[] dst, int dstOffset, int count)
        {
            if (count <= 0) return 0;
            if (offset < 0 || offset + count > Length)
                throw new IOException("read past EOF");

            if (count <= BufferSize / 2)
            {
                EnsureRange(offset, count);
                int srcIdx = (int)(offset - _bufferStart);
                Buffer.BlockCopy(_buffer, srcIdx, dst, dstOffset, count);
                return count;
            }

            // Large read: bypass cache.
            _stream.Seek(offset, SeekOrigin.Begin);
            int total = 0;
            while (total < count)
            {
                int n = _stream.Read(dst, dstOffset + total, count - total);
                if (n <= 0) break;
                total += n;
            }
            _bufferStart = -1; // invalidate cache
            return total;
        }

        /// <summary>Reads an ASCII C-string starting at offset.</summary>
        public string ReadCStringAt(long offset)
        {
            if (offset < 0 || offset >= Length) return null;
            var sb = new StringBuilder();
            long pos = offset;
            while (pos < Length)
            {
                EnsureRange(pos, 1);
                int idx = (int)(pos - _bufferStart);
                int avail = _bufferLen - idx;
                int zeroAt = -1;
                for (int i = 0; i < avail; i++)
                {
                    if (_buffer[idx + i] == 0) { zeroAt = i; break; }
                }
                if (zeroAt >= 0)
                {
                    for (int i = 0; i < zeroAt; i++) sb.Append((char)_buffer[idx + i]);
                    break;
                }
                for (int i = 0; i < avail; i++) sb.Append((char)_buffer[idx + i]);
                pos += avail;
            }
            return sb.ToString();
        }

        /// <summary>Reads up to maxLen ASCII bytes, stopping at NUL or EOF.</summary>
        public string ReadAsciiString(long offset, int maxLen)
        {
            if (offset < 0 || offset >= Length || maxLen <= 0) return "";
            var sb = new StringBuilder(maxLen);
            long pos = offset;
            long endPos = Math.Min(offset + maxLen, Length);
            while (pos < endPos)
            {
                EnsureRange(pos, 1);
                int idx = (int)(pos - _bufferStart);
                int avail = _bufferLen - idx;
                int remaining = (int)(endPos - pos);
                if (avail > remaining) avail = remaining;

                int stopAt = avail;
                for (int i = 0; i < avail; i++)
                {
                    if (_buffer[idx + i] == 0) { stopAt = i; break; }
                }
                for (int i = 0; i < stopAt; i++) sb.Append((char)_buffer[idx + i]);
                if (stopAt < avail) break;
                pos += avail;
            }
            return sb.ToString();
        }

        public void Dispose()
        {
            if (_stream != null) _stream.Dispose();
        }
    }

    // ---------------------------------------------------------------------
    // Helper to check if file can be modified
    // ---------------------------------------------------------------------
    private static bool CheckFileWritable(string path)
    {
        try
        {
            FileAttributes attrs = File.GetAttributes(path);
            if ((attrs & FileAttributes.ReadOnly) != 0)
            {
                Console.Error.WriteLine("pesym: {0}: file is marked as read-only", path);
                return false;
            }
            return true;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("pesym: {0}: cannot check file attributes: {1}", path, ex.Message);
            return false;
        }
    }

    // ---------------------------------------------------------------------
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

        // Режим прямого патчинга по указанному адресу
        if (opt.PatchData != null && opt.PatchOffset.HasValue)
        {
            int exitCode = 0;
            foreach (string file in opt.Files)
            {
                if (!CheckFileWritable(file)) { exitCode = 1; continue; }

                try
                {
                    using (var fs = new FileStream(file, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                    {
                        long off = opt.PatchOffset.Value;
                        if (off < 0 || off + opt.PatchData.Length > fs.Length)
                        {
                            Console.Error.WriteLine("pesym: {0}: offset 0x{1:X} + {2} bytes out of file bounds (file size: 0x{3:X})", 
                                file, off, opt.PatchData.Length, fs.Length);
                            exitCode = 1;
                            continue;
                        }
                        
                        fs.Seek(off, SeekOrigin.Begin);
                        fs.Write(opt.PatchData, 0, opt.PatchData.Length);
                        
                        if (!opt.Quiet)
                            Console.WriteLine("Patched {0} at offset 0x{1:X} with {2} bytes", file, off, opt.PatchData.Length);
                    }
                }
                catch (UnauthorizedAccessException)
                {
                    Console.Error.WriteLine("pesym: {0}: access denied (file might be locked by another process or OS)", file);
                    exitCode = 1;
                }
                catch (IOException ioEx)
                {
                    Console.Error.WriteLine("pesym: {0}: I/O error (file might be in use): {1}", file, ioEx.Message);
                    exitCode = 1;
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine("pesym: {0}: patch failed: {1}", file, ex.Message);
                    exitCode = 1;
                }
            }
            return exitCode;
        }

        Regex regex = null;
        if (!opt.All)
        {
            var opts = RegexOptions.CultureInvariant;
            if (opt.IgnoreCase) opts |= RegexOptions.IgnoreCase;
            regex = opt.Regex
                ? new Regex(opt.Pattern, opts)
                : new Regex(Regex.Escape(opt.Pattern), opts);
        }

        int exitCodeSearch = 0;
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
                if (results == null) { exitCodeSearch = 1; continue; }
                if (opt.Format == "json" && !opt.Quiet) allResults.AddRange(results);
            }
        }

        // Безопасный вывод JSON без использования форматных строк Console.WriteLine
        if (opt.Format == "json" && !opt.Quiet && allResults.Count > 0)
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

        return exitCodeSearch;
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
        Console.WriteLine("  -t <table>       search in specific table: export, import, coff, thunk, thunk-call, all (default)");
        Console.WriteLine();
        Console.WriteLine("Patch options:");
        Console.WriteLine("  -x, --hex <data> patch found offsets (or specified address) with hex data");
        Console.WriteLine("                   (case-insensitive, spaces allowed, e.g. -x \"90 90 90\" or -x 31c0c3)");
        Console.WriteLine("  --               separate options from positional arguments (pattern/address and files)");
        Console.WriteLine();
        Console.WriteLine("Output options:");
        Console.WriteLine("  -q               quiet mode (output addresses only)");
        Console.WriteLine("  --addr <type>    address type for quiet mode: rva, va, offset (default)");
        Console.WriteLine("  -n               output names only (one per line)");
        Console.WriteLine("  --no-header      suppress table headers");
        Console.WriteLine("  -f <format>      output format: table (default), raw, csv, json");
        Console.WriteLine();
        Console.WriteLine("Examples:");
        Console.WriteLine("  pesymp.exe CreateFile kernel32.dll");
        Console.WriteLine("  pesymp.exe CreateFile kernel32.dll -x 909090");
        Console.WriteLine("  pesymp.exe -x 909090 -- 0x10002a704 file.exe");
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
            
            // Новый аргумент для выбора таблицы
            else if (a == "-t" || a == "/t" || a == "--table")
            {
                if (i + 1 >= args.Length) throw new Exception("missing table name after -t");
                string tbl = args[++i].ToLower();
                if (tbl == "all") 
                { 
                    opt.Tables.Clear(); 
                    opt.Tables.Add("all"); 
                }
                else if (tbl == "export" || tbl == "import" || tbl == "coff" || tbl == "thunk" || tbl == "thunk-call")
                {
                    opt.Tables.Remove("all");
                    opt.Tables.Add(tbl);
                }
                else throw new Exception("unknown table: " + tbl + ". Use export, import, coff, thunk, thunk-call, or all.");
            }
            
            // Quiet mode
            else if (a == "-q" || a == "/q" || a == "--quiet") opt.Quiet = true;
            
            // Тип адреса для quiet mode
            else if (a == "--addr")
            {
                if (i + 1 >= args.Length) throw new Exception("missing address type after --addr");
                string at = args[++i].ToLower();
                if (at != "rva" && at != "va" && at != "offset")
                    throw new Exception("unknown address type: " + at + ". Use rva, va, or offset.");
                opt.AddrType = at;
            }
            else if (a == "-n" || a == "/n" || a == "--names-only") opt.NamesOnly = true;
            else if (a == "--no-header") opt.NoHeader = true;
            else if (a == "-f" || a == "/f" || a == "--format")
            {
                if (i + 1 >= args.Length) throw new Exception("missing format after -f");
                opt.Format = args[++i].ToLower();
                if (opt.Format != "table" && opt.Format != "raw" && opt.Format != "csv" && opt.Format != "json")
                    throw new Exception("unknown format: " + opt.Format);
            }
            else if (a == "-x" || a == "/x" || a == "--hex")
            {
                if (i + 1 >= args.Length) throw new Exception("missing hex data after -x");
                try { opt.PatchData = ParseHex(args[++i]); }
                catch (Exception ex) { throw new Exception("invalid hex data: " + ex.Message); }
            }
            else if (a == "--")
            {
                // Все последующие аргументы считаем позиционными
                for (int j = i + 1; j < args.Length; j++)
                {
                    string posArg = args[j];
                    if (opt.PatchData != null && opt.PatchOffset == null && IsHexAddress(posArg))
                    {
                        opt.PatchOffset = ParseAddress(posArg);
                    }
                    else if (opt.Pattern == null && !opt.All && opt.PatchOffset == null)
                    {
                        opt.Pattern = posArg;
                    }
                    else
                    {
                        opt.Files.Add(posArg);
                    }
                }
                break; // Завершаем основной цикл парсинга
            }
            else if (a == "-h" || a == "/h" || a == "--help") return null;
            else if (a.Length > 1 && (a[0] == '-' || a[0] == '/'))
                throw new Exception("unknown option: " + a);
            else if (opt.Pattern == null && !opt.All)
            {
                // Поддержка адреса без явного использования "--"
                if (opt.PatchData != null && opt.PatchOffset == null && IsHexAddress(a))
                    opt.PatchOffset = ParseAddress(a);
                else
                    opt.Pattern = a;
            }
            else opt.Files.Add(a);
        }

        if (!opt.All && opt.Pattern == null && !opt.PatchOffset.HasValue) 
            throw new Exception("no pattern given (or use -l, or specify address with -x)");
        if (opt.Files.Count == 0) 
            throw new Exception("no input file given");
            
        return opt;
    }

    private static List<Dictionary<string, object>> AnalyzeFile(string path, Regex regex, Options opt)
    {
        PeReader reader = null;
        var offsetsToPatch = new HashSet<long>();
        List<Dictionary<string, object>> results = null;
        try
        {
            reader = new PeReader(path);
            PeImage pe;
            try { pe = PeImage.Parse(reader); }
            catch (Exception ex)
            {
                Console.Error.WriteLine("pesym: {0}: {1}", path, ex.Message);
                return null;
            }

            bool searchAll = opt.Tables.Contains("all");
            bool searchExport = searchAll || opt.Tables.Contains("export");
            bool searchImport = searchAll || opt.Tables.Contains("import");
            bool searchCoff = searchAll || opt.Tables.Contains("coff");
            bool searchThunks = searchAll || opt.Tables.Contains("thunk") || opt.Tables.Contains("thunk-call");

            var symbols = new List<Symbol>();
            List<Symbol> imports = null;

            if (searchExport) { try { symbols.AddRange(pe.GetExports()); } catch (Exception ex) { Console.Error.WriteLine("pesym: {0}: export table error: {1}", path, ex.Message); } }
            if (searchImport || searchThunks) {
                try { imports = pe.GetImports(); if (searchImport) symbols.AddRange(imports); } 
                catch (Exception ex) { Console.Error.WriteLine("pesym: {0}: import table error: {1}", path, ex.Message); }
            }
            if (searchCoff) { try { symbols.AddRange(pe.GetCoffSymbols()); } catch (Exception ex) { Console.Error.WriteLine("pesym: {0}: COFF symbol table error: {1}", path, ex.Message); } }
            if (searchThunks && imports != null) { try { symbols.AddRange(pe.GetImportThunks(imports)); } catch (Exception ex) { Console.Error.WriteLine("pesym: {0}: thunk scan error: {1}", path, ex.Message); } }

            results = new List<Dictionary<string, object>>();
            bool printedHeader = false;

            foreach (Symbol sym in symbols)
            {
                if (sym == null || string.IsNullOrEmpty(sym.Name)) continue;
                
                // Фильтрация по запрошенным таблицам (например, отсечь thunk, если просили только thunk-call)
                if (!searchAll && !opt.Tables.Contains(sym.Source)) continue;

                if (regex != null && !regex.IsMatch(sym.Name)) continue;

                try
                {
                    uint rva = sym.RvaBased ? sym.Value : 0;
                    ulong va = rva != 0 ? pe.ImageBase + rva : 0;
                    long? fileOffset = sym.RvaBased
                        ? pe.RvaToFileOffset(rva)
                        : (pe.SectionByName(sym.Section) != null ? pe.SectionalToFileOffset(sym.Section, sym.Value) : (long?)null);

                    if (fileOffset.HasValue && opt.PatchData != null)
                    {
                        offsetsToPatch.Add(fileOffset.Value);
                    }
                    
                    // Если включен Quiet mode, просто печатаем нужный адрес и идем дальше
                    if (opt.Quiet)
                    {
                        string outAddr = "-";
                        if (opt.AddrType == "rva") outAddr = rva != 0 ? "0x" + rva.ToString("X") : "-";
                        else if (opt.AddrType == "va") outAddr = va != 0 ? "0x" + va.ToString("X") : "-";
                        else if (opt.AddrType == "offset") outAddr = fileOffset.HasValue ? "0x" + fileOffset.Value.ToString("X") : "-";
                        
                        Console.WriteLine(outAddr);
                        continue;
                    }

                    // Инициализация словаря, совместимая с C# 5.0
                    var result = new Dictionary<string, object>();
                    result.Add("file", path);
                    result.Add("source", sym.Source);
                    result.Add("name", sym.Name);
                    result.Add("rva", rva != 0 ? "0x" + rva.ToString("X") : "-");
                    result.Add("va", va != 0 ? "0x" + va.ToString("X") : "-");
                    result.Add("offset", fileOffset.HasValue ? "0x" + fileOffset.Value.ToString("X") : "?");
                    result.Add("section", !string.IsNullOrEmpty(sym.Section) ? sym.Section : "-");

                    results.Add(result);

                    // Вывод в зависимости от формата (JSON обрабатывается отдельно в Main)
                    if (opt.Format == "json") continue;

                    if (opt.NamesOnly) Console.WriteLine(sym.Name);
                    else if (opt.Format == "raw") Console.WriteLine("{0}\t{1}\t{2}\t{3}\t{4}\t{5}", sym.Source, sym.Name, result["rva"], result["va"], result["offset"], result["section"]);
                    else if (opt.Format == "csv")
                    {
                        if (!printedHeader && !opt.NoHeader) { Console.WriteLine("file,source,name,rva,va,offset,section"); printedHeader = true; }
                        Console.WriteLine("{0},{1},{2},{3},{4},{5},{6}", EscapeCsv(path), EscapeCsv(sym.Source), EscapeCsv(sym.Name), result["rva"], result["va"], result["offset"], EscapeCsv(result["section"].ToString()));
                    }
                    else
                    {
                        if (!printedHeader && !opt.NoHeader) { Console.WriteLine("== {0} (ImageBase=0x{1:X}) ==", path, pe.ImageBase); Console.WriteLine("  {0,-10} {1,-12} {2,-12} {3,-12} {4,-8} {5}", "Source", "RVA", "VA", "FileOffset", "Section", "Name"); printedHeader = true; }
                        Console.WriteLine("  {0,-10} {1,-12} {2,-12} {3,-12} {4,-8} {5}", sym.Source, result["rva"], result["va"], result["offset"], result["section"], sym.Name);
                    }
                }
                catch (Exception ex) { Console.WriteLine("  {0,-10} <error resolving symbol '{1}': {2}>", sym.Source, sym.Name, ex.Message); }
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("pesym: {0}: {1}", path, ex.Message);
            return null;
        }
        finally
        {
            if (reader != null) reader.Dispose(); // Закрываем файл для чтения, чтобы освободить для записи
        }

        // Выполняем патчинг после того, как PeReader освободил файл
        if (opt.PatchData != null && offsetsToPatch.Count > 0)
        {
            if (!CheckFileWritable(path)) return results;

            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                {
                    foreach (var off in offsetsToPatch)
                    {
                        if (off < 0 || off + opt.PatchData.Length > fs.Length)
                        {
                            Console.Error.WriteLine("pesym: {0}: patch offset 0x{1:X} + {2} bytes out of file bounds (file size: 0x{3:X})", path, off, opt.PatchData.Length, fs.Length);
                            continue;
                        }
                        fs.Seek(off, SeekOrigin.Begin);
                        fs.Write(opt.PatchData, 0, opt.PatchData.Length);
                        if (!opt.Quiet)
                            Console.WriteLine("Patched {0} at offset 0x{1:X} with {2} bytes", path, off, opt.PatchData.Length);
                    }
                }
            }
            catch (UnauthorizedAccessException)
            {
                Console.Error.WriteLine("pesym: {0}: access denied (file might be locked by another process or OS)", path);
            }
            catch (IOException ioEx)
            {
                Console.Error.WriteLine("pesym: {0}: I/O error (file might be in use): {1}", path, ioEx.Message);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("pesym: {0}: patch failed: {1}", path, ex.Message);
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

    // ---------------------------------------------------------------------
    // Hex parsing & Address helpers
    // ---------------------------------------------------------------------
    private static byte[] ParseHex(string hex)
    {
        if (string.IsNullOrEmpty(hex)) throw new Exception("empty hex data");
        hex = hex.Replace(" ", "").Replace("-", "");
        if (hex.Length % 2 != 0) throw new Exception("hex string length must be even");
        
        byte[] bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        }
        return bytes;
    }

    private static bool IsHexAddress(string s)
    {
        if (string.IsNullOrEmpty(s) || s.Length < 3) return false;
        if (!s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) return false;
        for (int i = 2; i < s.Length; i++)
        {
            char c = s[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                return false;
        }
        return true;
    }

    private static long ParseAddress(string s)
    {
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return Convert.ToInt64(s.Substring(2), 16);
        return Convert.ToInt64(s, 16);
    }

    private sealed class PeImage
    {
        private PeReader _reader;
        public ulong ImageBase;
        public List<Section> Sections = new List<Section>();
        private uint _exportRva;
        private uint _importRva;
        private bool _isPe32Plus;

        public static PeImage Parse(PeReader reader)
        {
            if (reader.Length < 0x40) throw new Exception("file too small");
            if (reader.ReadByte(0) != 'M' || reader.ReadByte(1) != 'Z') throw new Exception("not an MZ file");

            uint peOff = reader.ReadU32(0x3C);
            if (peOff + 4 > reader.Length) throw new Exception("PE signature not found");
            if (reader.ReadByte(peOff) != 'P' || reader.ReadByte(peOff + 1) != 'E' ||
                reader.ReadByte(peOff + 2) != 0 || reader.ReadByte(peOff + 3) != 0)
                throw new Exception("PE signature not found");

            var pe = new PeImage { _reader = reader };

            ushort numSections = reader.ReadU16(peOff + 6);
            ushort sizeOptHeader = reader.ReadU16(peOff + 20);
            int optStart = (int)peOff + 24;
            ushort magic = reader.ReadU16(optStart);
            if (magic != 0x10B && magic != 0x20B) throw new Exception("unknown optional header");

            pe._isPe32Plus = (magic == 0x20B);
            pe.ImageBase = magic == 0x20B
                ? reader.ReadU64(optStart + 24)
                : reader.ReadU32(optStart + 28);

            int dataDirStart = optStart + (magic == 0x20B ? 112 : 96);
            pe._exportRva = reader.ReadU32(dataDirStart);
            pe._importRva = reader.ReadU32(dataDirStart + 8);

            int secStart = optStart + sizeOptHeader;
            for (int i = 0; i < numSections && i < 96; i++)
            {
                int p = secStart + i * 40;
                if (p + 40 > reader.Length) break;
                var s = new Section
                {
                    Name = reader.ReadAsciiString(p, 8),
                    VirtualSize = reader.ReadU32(p + 8),
                    VirtualAddress = reader.ReadU32(p + 12),
                    SizeOfRawData = reader.ReadU32(p + 16),
                    PointerToRawData = reader.ReadU32(p + 20),
                    Characteristics = reader.ReadU32(p + 36),
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
            if (dirOff < 0 || dirOff + 40 > _reader.Length) return list;

            uint numNames = _reader.ReadU32(dirOff + 24);
            uint addrNames = _reader.ReadU32(dirOff + 32);
            if (numNames == 0 || numNames > 1000000) return list;

            long namesOff = RvaToFileOffset(addrNames) ?? -1;
            if (namesOff < 0) return list;

            for (uint i = 0; i < numNames; i++)
            {
                if (namesOff + (i + 1) * 4 > _reader.Length) break;
                uint nameRva = _reader.ReadU32(namesOff + (int)(i * 4));
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
                if (!off.HasValue || off.Value + 20 > _reader.Length) break;
                if (_reader.ReadU32(off.Value) == 0 && _reader.ReadU32(off.Value + 12) == 0) break;

                uint originalThunk = _reader.ReadU32(off.Value);
                uint firstThunk = _reader.ReadU32(off.Value + 16);
                if (originalThunk == 0 && firstThunk == 0) continue;

                uint thunkRva = originalThunk != 0 ? originalThunk : firstThunk;
                long? thunkOff = RvaToFileOffset(thunkRva);
                if (!thunkOff.HasValue) continue;

                for (uint i = 0; ; i++)
                {
                    uint entryRva = thunkRva + i * 4;
                    long? eo = RvaToFileOffset(entryRva);
                    if (!eo.HasValue || eo.Value + 4 > _reader.Length) break;
                    uint entry = _reader.ReadU32(eo.Value);
                    if (entry == 0) break;

                    string name;
                    if ((entry & 0x80000000) != 0)
                    {
                        name = "#" + (entry & 0xFFFF);
                    }
                    else
                    {
                        long? hintOff = RvaToFileOffset(entry);
                        name = hintOff.HasValue && hintOff.Value + 2 < _reader.Length
                            ? _reader.ReadCStringAt(hintOff.Value + 2)
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

            // Sliding window scan: keeps memory bounded even for large .text sections.
            const int CHUNK = 64 * 1024;
            const int OVERLAP = 16;
            byte[] chunk = new byte[CHUNK + OVERLAP];

            foreach (Section sec in Sections)
            {
                if (!sec.IsExecutable || sec.SizeOfRawData < 6) continue;

                long start = sec.PointerToRawData;
                long avail = _reader.Length - start;
                if (avail <= 0) continue;
                long rawSize = Math.Min((long)sec.SizeOfRawData, avail);
                long limit = rawSize - 6;
                if (limit < 0) continue;

                long pos = start;
                long endPos = start + limit;
                while (pos < endPos)
                {
                    int toRead = (int)Math.Min(chunk.Length, endPos - pos);
                    int read = _reader.ReadBytes(pos, chunk, 0, toRead);
                    if (read <= 6) break;

                    int scanLimit = read - 6;
                    for (int i = 0; i < scanLimit; i++)
                    {
                        byte op0 = chunk[i];
                        byte op1 = chunk[i + 1];
                        bool isJmp = (op0 == 0xFF && op1 == 0x25);
                        bool isCall = (op0 == 0xFF && op1 == 0x15);
                        if (!isJmp && !isCall) continue;

                        uint insnRva = sec.VirtualAddress + (uint)(pos - start + i);
                        uint targetRva;

                        if (_isPe32Plus)
                        {
                            int disp = (int)(chunk[i + 2] | (chunk[i + 3] << 8) |
                                             (chunk[i + 4] << 16) | (chunk[i + 5] << 24));
                            targetRva = unchecked((uint)((long)insnRva + 6 + disp));
                        }
                        else
                        {
                            uint targetVa = (uint)(chunk[i + 2] | (chunk[i + 3] << 8) |
                                                   (chunk[i + 4] << 16) | (chunk[i + 5] << 24));
                            if (targetVa < (uint)ImageBase ||
                                (ulong)targetVa - ImageBase > 0xFFFFFFFF) continue;
                            targetRva = (uint)((ulong)targetVa - ImageBase);
                        }

                        Symbol imp;
                        if (!iatMap.TryGetValue(targetRva, out imp)) continue;

                        list.Add(new Symbol
                        {
                            Name = imp.Name,
                            Source = isJmp ? "thunk" : "thunk-call",
                            Value = insnRva,
                            Section = sec.Name,
                            RvaBased = true
                        });
                        if (isJmp) i += 5;
                    }

                    if (read < chunk.Length) break;
                    pos += read - OVERLAP;
                }
            }
            return list;
        }

        public List<Symbol> GetCoffSymbols()
        {
            var list = new List<Symbol>();
            uint peOff = _reader.ReadU32(0x3C);
            if (peOff + 20 > _reader.Length) return list;

            uint symPtr = _reader.ReadU32(peOff + 12);
            uint numSyms = _reader.ReadU32(peOff + 16);
            if (symPtr == 0 || numSyms == 0 || numSyms > 10000000) return list;
            if (symPtr >= _reader.Length) return list;

            long strTable = (long)symPtr + (long)numSyms * 18;
            if (strTable + 4 > _reader.Length) return list;
            uint strTableSize = _reader.ReadU32(strTable);

            uint i = 0;
            while (i < numSyms)
            {
                long p = (long)symPtr + (long)i * 18;
                if (p < 0 || p + 18 > _reader.Length) break;

                string name;
                if (_reader.ReadU32(p) == 0)
                {
                    uint strOff = _reader.ReadU32(p + 4);
                    name = (strOff + 4 < strTableSize && strTable + strOff < _reader.Length)
                        ? _reader.ReadCStringAt(strTable + strOff) : null;
                }
                else
                {
                    name = _reader.ReadAsciiString(p, 8);
                }

                uint value = _reader.ReadU32(p + 8);
                short sectionNum = (short)_reader.ReadU16(p + 12);
                byte aux = _reader.ReadByte(p + 17);

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
                    return off < _reader.Length ? off : (long?)null;
                }
            }
            long hdr = rva;
            return hdr < _reader.Length ? hdr : (long?)null;
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
            return off.HasValue ? _reader.ReadCStringAt(off.Value) : null;
        }
    }
}
