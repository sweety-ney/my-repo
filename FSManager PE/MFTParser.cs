using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace FSManager_PE
{
    public class MFTReader
    {
        private const int DefaultBufferSize = 65536;
        private const uint FILE_READ_ATTRIBUTES = 0x0080;
        private const uint FILE_OPEN_FOR_BACKUP_INTENT = 0x4000;
        private const uint FILE_OPEN_BY_FILE_ID = 0x2000;

        private readonly string _volumeLetter;
        private readonly IntPtr _volumeHandle;

        public MFTReader(string volumeLetter)
        {
            _volumeLetter = volumeLetter;
            _volumeHandle = Win32API.CreateFileW(
                string.Format(@"\\.\{0}:", volumeLetter),
                FILE_READ_ATTRIBUTES,
                (int)FileShare.ReadWrite,
                IntPtr.Zero,
                (int)FileMode.Open,
                FILE_OPEN_FOR_BACKUP_INTENT | FILE_OPEN_BY_FILE_ID,
                IntPtr.Zero);
            if (_volumeHandle.ToInt32() == -1)
            {
                throw new IOException("Failed to open volume.");
            }
        }

        public void Close()
        {
            Win32API.CloseHandle(_volumeHandle);
        }

        public void EnumerateEntries(Action<MFTEntry> action, int bufferSize = DefaultBufferSize)
        {
            byte[] buffer = new byte[bufferSize];
            GCHandle gcHandle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            try
            {
                long currentOffset = 0;
                IntPtr bufferPtr = Marshal.AllocHGlobal(buffer.Length);
                try
                {
                    Marshal.Copy(buffer, 0, bufferPtr, buffer.Length);
                    while (Win32API.DeviceIoControl(_volumeHandle, 0x000900b3, IntPtr.Zero, 0, bufferPtr, (uint)buffer.Length, out uint bytesRead, IntPtr.Zero))
                    {
                        int entryOffset = 0;
                        while (entryOffset < bytesRead)
                        {
                            IntPtr ptr = new IntPtr(gcHandle.AddrOfPinnedObject().ToInt64() + entryOffset);
                            MFTEntry entry = (MFTEntry)Marshal.PtrToStructure(ptr, typeof(MFTEntry));
                            if (entry.RecordType == (int)MFTEntryType.File || entry.RecordType == (int)MFTEntryType.Directory)
                            {
                                action(entry);
                            }
                            entryOffset += (int)entry.RecordLength;
                        }
                        currentOffset += bytesRead;
                        if (bytesRead == 0)
                        {
                            break;
                        }
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(bufferPtr);
                }
            }
            finally
            {
                gcHandle.Free();
            }
        }
    }

    public enum MFTEntryType : uint
    {
        Unknown = 0,
        File = 0x10,
        Directory = 0x20,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MFTEntry
    {
        public uint RecordType;
        public uint RecordLength;
        public ushort Flags;
        public ushort Usn;
        public long FileReferenceNumber;
        public long ParentFileReferenceNumber;
        public uint FileNameLength;
        public uint FileNameOffset;
        public string FileName
        {
            get
            {
                byte[] buffer = new byte[FileNameLength * 2];
                Marshal.Copy(IntPtr.Add(new IntPtr(FileNameOffset), (int)IntPtr.Zero), buffer, 0, buffer.Length);
                return System.Text.Encoding.Unicode.GetString(buffer);
            }
        }
    }


}