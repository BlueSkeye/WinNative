using System.IO.MemoryMappedFiles;
using System.Text;

namespace NtDllCrossReferencer
{
    public static class Program
    {
        private static Dictionary<string, List<FileInfo>> _referencersByFunctionName =
            new Dictionary<string, List<FileInfo>>();

        public static int Main(string[] args)
        {
            int totalCandidateFiles = 0;
            DateTime startTime = DateTime.UtcNow;
            foreach(FileInfo candidate in WalkCandidates()) {
                totalCandidateFiles++;
                FindNtDllImports(candidate);
            }
            DateTime endTime = DateTime.UtcNow;
            Console.WriteLine($"{totalCandidateFiles} files found in {(int)((endTime - startTime).TotalSeconds)} sec.");
            return 0;
        }

        private static void FindNtDllImports(FileInfo candidate)
        {
            const int elfanewDosHeaderOffset = 60;
            const int imageFileHeaderSize = 20;
            const int optionalHeader64OffsetInNtHeader64 = sizeof(uint) + imageFileHeaderSize;
            const int dataDirectoryCountOffsetInOptionalHeader64 = 108;
            const int firstDataDirectoryOffsetInOptionalHeader64 = 112;
            const int importTableOffsetInOptionalHeader64 = firstDataDirectoryOffsetInOptionalHeader64 + (1 * 8);
            const int numberOfNamesOffsetInImportDirectory = 24;
            const int sectionsCountOffsetInNtHeader64 = 6;
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
            MemoryMappedViewAccessor reader = mapping.CreateViewAccessor(0, candidate.Length,
                MemoryMappedFileAccess.Read);
            // NT header offsets are computed assuming the header includes the magic 'PE\0\0' marker.
            uint ntHeader64Offset = reader.ReadUInt32(elfanewDosHeaderOffset);
            ushort sectionsCount = reader.ReadUInt16(ntHeader64Offset + sectionsCountOffsetInNtHeader64); // Valid
            uint optionalHeader64FileOffset = ntHeader64Offset + optionalHeader64OffsetInNtHeader64; // Valid
            long readPosition = optionalHeader64FileOffset + dataDirectoryCountOffsetInOptionalHeader64;
            uint dataDirectoryCount = reader.ReadUInt32(readPosition);
            uint sectionTableFileOffset = optionalHeader64FileOffset +
                firstDataDirectoryOffsetInOptionalHeader64 + (dataDirectoryCount * 8);
            uint importTable64FileOffset = optionalHeader64FileOffset + importTableOffsetInOptionalHeader64;
            uint importDataDirectoryRVA = reader.ReadUInt32(importTable64FileOffset);
            uint importDataDirectoryFileOffset = ResolveRVAToFileOffset(reader, sectionTableFileOffset,
                sectionsCount, importDataDirectoryRVA);

            readPosition = importDataDirectoryFileOffset;
            const int directoryEntrySize = 20;
            const int dllNameOffsetInDirectoryEntry = 12;
            while (true) {
                uint lookupTableRVA = reader.ReadUInt32(readPosition);
                uint dllNameRVA = reader.ReadUInt32(readPosition + dllNameOffsetInDirectoryEntry);
                if (0 == lookupTableRVA) {
                    // Technically we should check the other directory entry fields to be zero also.
                    break;
                }
                uint dllNameFileOffset = ResolveRVAToFileOffset(reader, sectionTableFileOffset,
                    sectionsCount, dllNameRVA);
                string dllName = ReadAnsiNTBString(reader, dllNameFileOffset).ToUpper();
                uint lookupTableFileOffset = ResolveRVAToFileOffset(reader, sectionTableFileOffset,
                    sectionsCount, lookupTableRVA);
                while (true) {
                    ulong lookupTableEntryValue = reader.ReadUInt64(lookupTableFileOffset);
                    if (0 == lookupTableEntryValue) {
                        break;
                    }
                    if (0 == (0x8000000000000000 & lookupTableEntryValue)) {
                        // Ignore imports by ordinal
                        uint functionNameRVA = (uint)lookupTableEntryValue;
                        uint functionNameFileOffset = ResolveRVAToFileOffset(reader, sectionTableFileOffset,
                            sectionsCount, functionNameRVA);
                        string functionName = ReadAnsiNTBString(reader, functionNameFileOffset);
                        string compositeName = $"{dllName}::{functionName}";
                        List<FileInfo> referencers;
                        if (!_referencersByFunctionName.TryGetValue(compositeName, out referencers)) {
                            referencers = new List<FileInfo>();
                            _referencersByFunctionName.Add(compositeName, referencers);
                        }
                        referencers.Add(candidate);
                    }
                    lookupTableFileOffset += sizeof(uint);
                }
                readPosition += directoryEntrySize;
            }
            reader.Dispose();
            mapping.Dispose();
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
        private static uint ResolveRVAToFileOffset(MemoryMappedViewAccessor reader, uint sectionTableFileOffset,
            ushort sectionsCount, uint searchedVA)
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
            pendingDirectories.Push(new DirectoryInfo(Environment.SystemDirectory));

            while (0 < pendingDirectories.Count) {
                DirectoryInfo currentDirectory = pendingDirectories.Pop();
                try {
                    foreach (DirectoryInfo subDirectory in currentDirectory.GetDirectories()) {
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
    }
}
