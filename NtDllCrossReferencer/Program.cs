using System.IO.MemoryMappedFiles;
using System.Reflection.PortableExecutable;
using System.Text;

namespace NtDllCrossReferencer
{
    public static class Program
    {
        private static Dictionary<string, Dictionary<string, List<FileInfo>>> _referencersByFunctionNameByExporter =
            new Dictionary<string, Dictionary<string, List<FileInfo>>>();
        private static string[] ExcludedDirectories = {
            "Installer", "Servicing", "SysWOW64", "WinSxS"
        };

        public static int Main(string[] args)
        {
            int totalCandidateFiles = 0;
            DateTime startTime = DateTime.UtcNow;
            // FindDllImports(new FileInfo(@"C:\Windows\System32\tcblaunch.exe"));

            foreach (FileInfo candidate in WalkCandidates()) {
                totalCandidateFiles++;
                FindDllImports(candidate);
            }
            DateTime endTime = DateTime.UtcNow;
            Console.WriteLine($"{totalCandidateFiles} files found in {(int)((endTime - startTime).TotalSeconds)} sec.");
            return 0;
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

                    if (0 == importedFunctionsCount) {
                        int i = 1;
                    }
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
                peDescriptor.sectionTableFileOffset, peDescriptor.sectionsCount, delayImportDataDirectoryRVA);

            long readPosition = delayImportDataDirectoryFileOffset;
            if (0 != reader.ReadInt32(readPosition)) {
                throw new ApplicationException($"Invalid delay-load table attribute at 0x{readPosition:X8}");
            }
            readPosition += sizeof(int);

            const int directoryEntrySize = 20;
            const int dllNameOffsetInDirectoryEntry = 12;
            while (true) {
                uint lookupTableRVA = reader.ReadUInt32(readPosition);
                uint dllNameRVA = reader.ReadUInt32(readPosition + dllNameOffsetInDirectoryEntry);
                if (0 == lookupTableRVA) {
                    // Technically we should check the other directory entry fields to be
                    // zero also.
                    break;
                }
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
                    }
                    lookupTableFileOffset += sizeof(ulong);
                }
                readPosition += directoryEntrySize;
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
            const int directoryEntrySize = 20;
            const int dllNameOffsetInDirectoryEntry = 12;
            while (true) {
                uint lookupTableRVA = reader.ReadUInt32(readPosition);
                uint dllNameRVA = reader.ReadUInt32(readPosition + dllNameOffsetInDirectoryEntry);
                if (0 == lookupTableRVA) {
                    // Technically we should check the other directory entry fields to be
                    // zero also.
                    break;
                }
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
                    }
                    lookupTableFileOffset += sizeof(ulong);
                }
                readPosition += directoryEntrySize;
            }
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

            internal uint ntHeader64Offset;
            internal ushort sectionsCount;
            internal uint optionalHeader64FileOffset;
            internal ushort peHeaderMagic;
            internal uint dataDirectoryCount;
            internal uint sectionTableFileOffset;
        }
    }
}
