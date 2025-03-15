using System.IO.MemoryMappedFiles;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace NtDllCrossReferencer
{
    public static class Program
    {
        private static readonly string[] DefaultExcludedDirectories = {
            "Installer", "Servicing", "SysWOW64", "WinSxS"
        };
        private static string[] ExcludedDirectories = DefaultExcludedDirectories;
        private static Dictionary<string, Dictionary<string, List<FileInfo>>> _referencersByFunctionNameByExporter =
            new Dictionary<string, Dictionary<string, List<FileInfo>>>();
        private static Verb _verb;

        public static int Main(string[] args)
        {
            int resultCode = ParseArgs(args);
            if (0 != resultCode) {
                return resultCode;
            }
            int totalCandidateFiles = 0;
            DateTime startTime = DateTime.UtcNow;
            switch (_verb) {
                case Verb.CollectLocal:
                    // FindDllImports(new FileInfo(@""));
                    PlatformID platformId = System.Environment.OSVersion.Platform;
                    string serviePack = System.Environment.OSVersion.ServicePack;
                    string versionString = System.Environment.OSVersion.VersionString;

                    foreach (FileInfo candidate in WalkCandidates()) {
                        totalCandidateFiles++;
                        FindDllImports(candidate);
                    }
                    DateTime endTime = DateTime.UtcNow;
                    Console.WriteLine($"{totalCandidateFiles} files found in {(int)((endTime - startTime).TotalSeconds)} sec.");
                    SerializeResults();
                    break;
                default:
                    Console.WriteLine($"BUG : Unexpected unknown verb {(int)_verb}");
                    resultCode = -2;
                    break;
            }
            return resultCode;
        }

        private static void FindDllImports(FileInfo candidate)
        {
            // const int addressOfNamesOffsetInExportDirectory = 32;
            MemoryMappedFile? mapping;

            if ("procexp152.sys" == candidate.Name.ToLower()) {
                // Be nice with our EDR.
                return;
            }
            try {
                mapping = MemoryMappedFile.CreateFromFile(candidate.FullName,
                    FileMode.Open, null, 0, MemoryMappedFileAccess.Read);
            }
            catch {
                // Some drivers may be found offending from an EDR pow.
                return;
            }
            try {
                int importedFunctionsCount = 0;
                using (MemoryMappedViewAccessor reader = mapping.CreateViewAccessor(0, candidate.Length,
                    MemoryMappedFileAccess.Read))
                {
                    PEDescriptor peDescriptor;

                    // NT header offsets are computed assuming the header includes the magic 'PE\0\0' marker.
                    peDescriptor.ntHeader64Offset = reader.ReadUInt32(PEDescriptor.ElfanewDosHeaderOffset);
                    peDescriptor.sectionsCount = reader.ReadUInt16(
                        peDescriptor.ntHeader64Offset + PEDescriptor.SectionsCountOffsetInNtHeader64);
                    peDescriptor.optionalHeader64FileOffset = 
                        peDescriptor.ntHeader64Offset + PEDescriptor.OptionalHeader64OffsetInNtHeader64;
                    peDescriptor.peHeaderMagic = reader.ReadUInt16(peDescriptor.optionalHeader64FileOffset);
                    if (0x20B != peDescriptor.peHeaderMagic) {
                        // We don't handle anything else than PE32+ files (i.e. 64 bits executables). 
                        return;
                    }
                    Console.WriteLine($"{candidate.Name} =============================");
                    long readPosition = peDescriptor.optionalHeader64FileOffset +
                        PEDescriptor.DataDirectoryCountOffsetInOptionalHeader64;
                    peDescriptor.dataDirectoryCount = reader.ReadUInt32(readPosition);
                    peDescriptor.sectionTableFileOffset = peDescriptor.optionalHeader64FileOffset +
                        PEDescriptor.FirstDataDirectoryOffsetInOptionalHeader64 +
                        (peDescriptor.dataDirectoryCount * 8);

                    HandleImportTable(candidate, reader, peDescriptor, ref importedFunctionsCount);

                    // Delay-load import table
                    HandleDelayImportTable(candidate, reader, peDescriptor, ref importedFunctionsCount);
                }
            }
            finally { mapping.Dispose(); }
        }

        private static void HandleDelayImportTable(FileInfo candidate, MemoryMappedViewAccessor reader,
            PEDescriptor peDescriptor, ref int importedFunctionsCount)
        {
            uint delayImportTable64FileOffset = peDescriptor.optionalHeader64FileOffset +
                PEDescriptor.DelayImportTableOffsetInOptionalHeader64;
            uint delayImportDataDirectoryRVA = reader.ReadUInt32(delayImportTable64FileOffset);
            if (0 == delayImportDataDirectoryRVA) {
                // No delay import found.
                return;
            }
            uint delayImportDataDirectoryFileOffset = ResolveRVAToFileOffset(reader,
                peDescriptor.sectionTableFileOffset, peDescriptor.sectionsCount,
                delayImportDataDirectoryRVA);
            long readPosition = delayImportDataDirectoryFileOffset;
            while (true) {
                uint attributes = reader.ReadUInt32(readPosition);
                uint lookupTableRVA = reader.ReadUInt32(readPosition +
                    PEDescriptor.DelayImportNameTableOffset);
                if (0 == lookupTableRVA) {
                    // Technically we should check the other directory entry fields to be
                    // zero also.
                    break;
                }
                uint dllNameRVA = reader.ReadUInt32(readPosition +
                    PEDescriptor.DelayLoadDllNameOffsetInDirectoryEntry);
                uint dllNameFileOffset = ResolveRVAToFileOffset(reader,
                    peDescriptor.sectionTableFileOffset, peDescriptor.sectionsCount, dllNameRVA);
                string dllName = ReadAnsiNTBString(reader, dllNameFileOffset).ToUpper();
                Console.WriteLine($"  importing from {dllName}");
                Dictionary<string, List<FileInfo>> referencersByFunctionName;
                if (!_referencersByFunctionNameByExporter.TryGetValue(dllName,
                    out referencersByFunctionName))
                {
                    referencersByFunctionName = new Dictionary<string, List<FileInfo>>();
                    _referencersByFunctionNameByExporter.Add(dllName, referencersByFunctionName);
                }
                uint lookupTableFileOffset = ResolveRVAToFileOffset(reader,
                    peDescriptor.sectionTableFileOffset, peDescriptor.sectionsCount, lookupTableRVA);
                while (true) {
                    ulong lookupTableEntryValue = reader.ReadUInt64(lookupTableFileOffset);
                    if (0 == lookupTableEntryValue) {
                        break;
                    }
                    if (0 == (0x8000000000000000 & lookupTableEntryValue)) {
                        // Ignore imports by ordinal
                        uint functionNameRVA = (uint)lookupTableEntryValue;
                        uint functionNameFileOffset = ResolveRVAToFileOffset(reader,
                            peDescriptor.sectionTableFileOffset, peDescriptor.sectionsCount,
                            functionNameRVA);
                        // Skip hint value.
                        functionNameFileOffset += sizeof(ushort);
                        string functionName = ReadAnsiNTBString(reader, functionNameFileOffset);
                        // No need to consume the additional null byte after name (if any)
                        // Console.WriteLine("  " + functionName);
                        List<FileInfo> referencers;
                        if (!referencersByFunctionName.TryGetValue(functionName,
                            out referencers))
                        {
                            referencers = new List<FileInfo>();
                            referencersByFunctionName.Add(functionName, referencers);
                        }
                        referencers.Add(candidate);
                        importedFunctionsCount++;
                    }
                    lookupTableFileOffset += sizeof(ulong);
                }
                readPosition += PEDescriptor.DelayLoadDirectoryEntrySize;
            }
        }

        private static void HandleImportTable(FileInfo candidate, MemoryMappedViewAccessor reader,
            PEDescriptor peDescriptor, ref int importedFunctionsCount)
        {
            uint importTable64FileOffset = peDescriptor.optionalHeader64FileOffset +
                PEDescriptor.ImportTableOffsetInOptionalHeader64;
            uint importDataDirectoryRVA = reader.ReadUInt32(importTable64FileOffset);
            if (0 == importDataDirectoryRVA) {
                // No import found. See C:\Windows\System32\tcblaunch.exe for example
                return;
            }
            uint importDataDirectoryFileOffset = ResolveRVAToFileOffset(reader,
                peDescriptor.sectionTableFileOffset, peDescriptor.sectionsCount, importDataDirectoryRVA);

            long readPosition = importDataDirectoryFileOffset;
            while (true) {
                uint lookupTableRVA = reader.ReadUInt32(readPosition);
                if (0 == lookupTableRVA) {
                    // Technically we should check the other directory entry fields to be
                    // zero also.
                    break;
                }
                uint dllNameRVA = reader.ReadUInt32(readPosition +
                    PEDescriptor.DllNameOffsetInDirectoryEntry);
                uint dllNameFileOffset = ResolveRVAToFileOffset(reader,
                    peDescriptor.sectionTableFileOffset, peDescriptor.sectionsCount, dllNameRVA);
                string dllName = ReadAnsiNTBString(reader, dllNameFileOffset).ToUpper();
                Console.WriteLine($"  importing from {dllName}");
                Dictionary<string, List<FileInfo>> referencersByFunctionName;
                if (!_referencersByFunctionNameByExporter.TryGetValue(dllName,
                    out referencersByFunctionName))
                {
                    referencersByFunctionName = new Dictionary<string, List<FileInfo>>();
                    _referencersByFunctionNameByExporter.Add(dllName, referencersByFunctionName);
                }
                uint lookupTableFileOffset = ResolveRVAToFileOffset(reader,
                    peDescriptor.sectionTableFileOffset, peDescriptor.sectionsCount, lookupTableRVA);
                while (true) {
                    ulong lookupTableEntryValue = reader.ReadUInt64(lookupTableFileOffset);
                    if (0 == lookupTableEntryValue) {
                        break;
                    }
                    if (0 == (0x8000000000000000 & lookupTableEntryValue)) {
                        // Ignore imports by ordinal
                        uint functionNameRVA = (uint)lookupTableEntryValue;
                        uint functionNameFileOffset = ResolveRVAToFileOffset(reader,
                            peDescriptor.sectionTableFileOffset, peDescriptor.sectionsCount,
                            functionNameRVA);
                        // Skip hint value.
                        functionNameFileOffset += sizeof(ushort);
                        string functionName = ReadAnsiNTBString(reader, functionNameFileOffset);
                        // No need to consume the additional null byte after name (if any)
                        // Console.WriteLine("  " + functionName);
                        List<FileInfo> referencers;
                        if (!referencersByFunctionName.TryGetValue(functionName,
                            out referencers))
                        {
                            referencers = new List<FileInfo>();
                            referencersByFunctionName.Add(functionName, referencers);
                        }
                        referencers.Add(candidate);
                        importedFunctionsCount++;
                    }
                    lookupTableFileOffset += sizeof(ulong);
                }
                readPosition += PEDescriptor.DirectoryEntrySize;
            }
        }

        private static int ParseArgs(string[] args)
        {
            if (0 == args.Length) {
                _verb = Verb.CollectLocal;
                return 0;
            }
            return -1;
        }
        
        private static string ReadAnsiNTBString(MemoryMappedViewAccessor reader, uint fileOffset)
        {
            StringBuilder builder = new StringBuilder();
            while(true) {
                byte inputByte = reader.ReadByte(fileOffset++);
                if (0 == inputByte) {
                    return builder.ToString();
                }
                builder.Append((char)inputByte);
            }
        }

        // Doesn't work when there is no in file data for the searched VA. 
        private static uint ResolveRVAToFileOffset(MemoryMappedViewAccessor reader,
            uint sectionTableFileOffset, ushort sectionsCount, uint searchedVA)
        {
            const int vaSectionOffset = 12;
            const int sizeOfRawDataSectionOffset = 16;
            const int fileOffsetSectionOffset = 20;
            const int sectionRecordSize = 40;

            for(uint index = 0; index < sectionsCount; index++) {
                uint currentSectionFileOffset = sectionTableFileOffset + (index * sectionRecordSize);
                uint currentSectionVA = reader.ReadUInt32(currentSectionFileOffset + vaSectionOffset);
                uint currentSectionSizeOfRawData = reader.ReadUInt32(
                    currentSectionFileOffset + sizeOfRawDataSectionOffset);
                uint currentSectionDataFileOffset = reader.ReadUInt32(
                    currentSectionFileOffset + fileOffsetSectionOffset);

                if (searchedVA < currentSectionVA) {
                    continue;
                }
                uint currentSectionLastValidVA = currentSectionVA + currentSectionSizeOfRawData - 1;
                if (searchedVA > currentSectionLastValidVA) {
                    continue;
                }
                return (searchedVA - currentSectionVA) + currentSectionDataFileOffset;
            }
            throw new ApplicationException("VA not found.");
        }

        private static void SerializeResults()
        {
            ResultData toBeSerialized = new ResultData() {
                CollectedAt = DateTime.UtcNow,
                OsVersion = Environment.OSVersion.Version,
                ReferencersByFunctionNameByExporter =
                    new SortedDictionary<string, SortedDictionary<string, List<string>>>()
            };
            foreach(KeyValuePair<string, Dictionary<string, List<FileInfo>>> mainPair in
                _referencersByFunctionNameByExporter)
            {
                SortedDictionary<string, List<string>> convertedDictionary =
                    new SortedDictionary<string, List<string>>();
                toBeSerialized.ReferencersByFunctionNameByExporter.Add(mainPair.Key,
                    convertedDictionary);
                foreach (KeyValuePair<string, List<FileInfo>> secondaryPair in mainPair.Value) {
                    List<string> convertedList = new List<string>();
                    foreach (FileInfo fileInfo in secondaryPair.Value) {
                        convertedList.Add(fileInfo.Name);
                    }
                    convertedDictionary.Add(secondaryPair.Key, convertedList);
                }
            }
            // Sort innermost referencers lists.
            foreach(SortedDictionary<string, List<string>> scannedDictionary in
                toBeSerialized.ReferencersByFunctionNameByExporter.Values)
            {
                foreach (List<string> scannedList in scannedDictionary.Values) {
                    scannedList.Sort();
                }
            }

            string timeTag = toBeSerialized.CollectedAt.ToString("yyyyMMddHHmmss");
            FileInfo outputFile = new FileInfo($"ExportsXRefs-{toBeSerialized.OsVersion}-{timeTag}");
            JsonSerializerOptions options = new JsonSerializerOptions() {
                IndentCharacter = ' ',
                IndentSize = 2,
                WriteIndented = true,
            };
            using (Stream outputStream = File.OpenWrite(outputFile.FullName)) {
                JsonSerializer.Serialize<ResultData>(outputStream, toBeSerialized, options);
            }
            Console.WriteLine($"Result successfully serialized in '{outputFile.FullName}'");
        }

        private static IEnumerable<FileInfo> WalkCandidates()
        {
            Stack<DirectoryInfo> pendingDirectories = new Stack<DirectoryInfo>();
            DirectoryInfo sysInternalsDirectory =
                new DirectoryInfo(Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    "sysinternals"));
            if (sysInternalsDirectory.Exists) {
                pendingDirectories.Push(sysInternalsDirectory);
            }
            DirectoryInfo baseDirectory = new DirectoryInfo(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows));
            pendingDirectories.Push(baseDirectory);

            while (0 < pendingDirectories.Count) {
                DirectoryInfo currentDirectory = pendingDirectories.Pop();
                try {
                    foreach (DirectoryInfo subDirectory in currentDirectory.GetDirectories()) {
                        bool excluded = false;
                        foreach(string excludedName in ExcludedDirectories) {
                            if (0 == string.Compare(subDirectory.Name, excludedName, true)) {
                                excluded = true;
                                break;
                            }
                        }
                        if (excluded) {
                            continue;
                        }
                        pendingDirectories.Push(subDirectory);
                    }
                }
                catch (UnauthorizedAccessException) {
                    // Some directories may be unreachable. Ignore them.
                }
                string[] filters = new string[] { "*.exe", "*.dll", "*.sys" };
                foreach(string filter in filters) {
                    FileInfo[]? candidates = null;
                    try { candidates = currentDirectory.GetFiles(filter); }
                    catch (UnauthorizedAccessException) { }
                    if (null != candidates) {
                        foreach (FileInfo candidate in candidates) {
                            yield return candidate;
                        }
                    }
                }
            }
        }

        private struct PEDescriptor
        {
            internal const int DataDirectoryEntrySize = 8;
            internal const int DelayImportTableEntryIndex = 13;
            internal const int ImportTableEntryIndex = 1;
            internal const int ElfanewDosHeaderOffset = 60;
            internal const int ImageFileHeaderSize = 20;
            internal const int OptionalHeader64OffsetInNtHeader64 =
                sizeof(uint) + ImageFileHeaderSize;
            internal const int DataDirectoryCountOffsetInOptionalHeader64 = 108;
            internal const int FirstDataDirectoryOffsetInOptionalHeader64 = 112;
            internal const int ImportTableOffsetInOptionalHeader64 =
                FirstDataDirectoryOffsetInOptionalHeader64 +
                (ImportTableEntryIndex * DataDirectoryEntrySize);
            internal const int DelayImportTableOffsetInOptionalHeader64 =
                FirstDataDirectoryOffsetInOptionalHeader64 +
                (DelayImportTableEntryIndex * DataDirectoryEntrySize);
            internal const int NumberOfNamesOffsetInImportDirectory = 24;
            internal const int SectionsCountOffsetInNtHeader64 = 6;
            internal const int DirectoryEntrySize = 20;
            internal const int DllNameOffsetInDirectoryEntry = 12;
            internal const int DelayLoadDirectoryEntrySize = 32;
            internal const int DelayLoadDllNameOffsetInDirectoryEntry = 4;
            internal const int DelayImportNameTableOffset = 16;

            internal uint ntHeader64Offset;
            internal ushort sectionsCount;
            internal uint optionalHeader64FileOffset;
            internal ushort peHeaderMagic;
            internal uint dataDirectoryCount;
            internal uint sectionTableFileOffset;
        }

        public class ResultData
        {
            private const int CurrentSchemaVersion = 1;
            private int _schemaVersion = CurrentSchemaVersion;

            [JsonPropertyOrder(-1)]
            public int SchemaVersion
            {
                get { return _schemaVersion; }
                set { _schemaVersion = value; }
            }
            public DateTime CollectedAt { get; set; }
            public Version OsVersion { get; set; }
            public SortedDictionary<string, SortedDictionary<string, List<string>>>
                ReferencersByFunctionNameByExporter { get; set; }
        }

        private enum Verb
        {
            CollectLocal = 0,

        }
    }
}
