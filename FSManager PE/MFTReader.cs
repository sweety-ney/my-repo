using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FSManager_PE
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel;
    using System.Diagnostics;
    using System.Runtime.InteropServices;

    


    class MFTReader
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateFile(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadFile(
            IntPtr hFile,
            byte[] lpBuffer,
            uint nNumberOfBytesToRead,
            out uint lpNumberOfBytesRead,
            IntPtr lpOverlapped);

        private const uint GENERIC_READ = 0x80000000;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint FILE_SHARE_WRITE = 0x00000002;
        private const uint OPEN_EXISTING = 0x00000003;
        private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;

        private const uint ERROR_INSUFFICIENT_BUFFER = 122;
        private const uint FSCTL_GET_NTFS_VOLUME_DATA = 0x00090064;

        private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        private const uint TOKEN_QUERY = 0x0008;
        private const string SE_DEBUG_NAME = "SeDebugPrivilege";
        private const int SE_PRIVILEGE_ENABLED = 0x00000002;

        private IntPtr _handle;
        private uint _bytesPerFileRecord;

        public MFTReader()
        {
            GetPrivileges();
        }

        public Dictionary<long, MFTEntry> ReadEntries(string drive)
        {
            var entries = new Dictionary<long, MFTEntry>();
            uint bytesRead = 0;
            uint bufferLength = 1024;
            byte[] buffer = new byte[bufferLength];

            string path = string.Format(@"\\.\{0}:", drive);

            _handle = CreateFile(
                path,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                IntPtr.Zero,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                IntPtr.Zero);

            if (_handle == IntPtr.Zero || _handle.ToInt64() == -1)
            {
                throw new Exception("Error opening drive");
            }

            try
            {
                _bytesPerFileRecord = GetBytesPerFileRecord(_handle);
                ulong mftSize = GetMftSize(_handle);

                for (ulong i = 0; i < mftSize; i++)
                {
                    ulong offset = i * _bytesPerFileRecord;

                    if (!ReadFile(_handle, buffer, bufferLength, out bytesRead, new IntPtr((long)offset)))
                    {
                        throw new Exception("Error reading MFT entry");
                    }

                    if (bytesRead > 0)
                    {
                        var entry = new MFTEntry(buffer, (long)offset);

                        if (entry.EntryID >= 0 && !entries.ContainsKey(entry.EntryID))
                        {
                            entries.Add(entry.EntryID, entry);
                        }
                    }
                }
            }
            finally
            {
                CloseHandle(_handle);
            }

            return entries;
        }

        private uint GetBytesPerFileRecord(IntPtr handle)
        {
            uint bytesReturned = 0;
            byte[] output = new byte[0];

            while (output.Length == 0)
            {
                uint bufferSize = (uint)Marshal.SizeOf(typeof(NTFS_VOLUME_DATA_BUFFER));
                IntPtr bufferPtr = Marshal.AllocHGlobal((int)bufferSize);

                try
                {
                    if (!DeviceIoControl(handle, FSCTL_GET_NTFS_VOLUME_DATA, IntPtr.Zero, 0, bufferPtr, bufferSize, out bytesReturned, IntPtr.Zero))
                    {
                        throw new Exception("Error getting NTFS volume data");
                    }

                    output = new byte[bytesReturned];
                    Marshal.Copy(bufferPtr, output, 0, (int)bytesReturned);
                }
                catch (Win32Exception)
                {
                    Marshal.FreeHGlobal(bufferPtr);
                    throw;
                }

                Marshal.FreeHGlobal(bufferPtr);
            }

            NTFS_VOLUME_DATA_BUFFER ntfsVolData = new NTFS_VOLUME_DATA_BUFFER();
            ntfsVolData = (NTFS_VOLUME_DATA_BUFFER)Marshal.PtrToStructure(Marshal.UnsafeAddrOfPinnedArrayElement(output, 0), typeof(NTFS_VOLUME_DATA_BUFFER));

            return ntfsVolData.BytesPerFileRecordSegment;
        }

        private ulong GetMftSize(IntPtr handle)
        {
            uint bytesReturned = 0;
            byte[] output = new byte[0];

            while (output.Length == 0)
            {
                uint bufferSize = (uint)Marshal.SizeOf(typeof(NTFS_VOLUME_DATA_BUFFER));
                IntPtr bufferPtr = Marshal.AllocHGlobal((int)bufferSize);

                try
                {
                    if (!DeviceIoControl(handle, FSCTL_GET_NTFS_VOLUME_DATA, IntPtr.Zero, 0, bufferPtr, bufferSize, out bytesReturned, IntPtr.Zero))
                    {
                        throw new Exception("Error getting NTFS volume data");
                    }

                    output = new byte[bytesReturned];
                    Marshal.Copy(bufferPtr, output, 0, (int)bytesReturned);
                }
                catch (Win32Exception)
                {
                    Marshal.FreeHGlobal(bufferPtr);
                    throw;
                }

                Marshal.FreeHGlobal(bufferPtr);
            }

            NTFS_VOLUME_DATA_BUFFER ntfsVolData = new NTFS_VOLUME_DATA_BUFFER();
            ntfsVolData = (NTFS_VOLUME_DATA_BUFFER)Marshal.PtrToStructure(Marshal.UnsafeAddrOfPinnedArrayElement(output, 0), typeof(NTFS_VOLUME_DATA_BUFFER));

            return ntfsVolData.MftValidDataLength / _bytesPerFileRecord;
        }

        private void GetPrivileges()
        {
            Process currentProcess = Process.GetCurrentProcess();
            IntPtr tokenHandle;

            if (!OpenProcessToken(currentProcess.Handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out tokenHandle))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            TOKEN_PRIVILEGES newState = new TOKEN_PRIVILEGES();
            newState.PrivilegeCount = 1;
            newState.Privileges = new LUID_AND_ATTRIBUTES[1];

            if (!LookupPrivilegeValue(null, SE_DEBUG_NAME, out newState.Privileges[0].Luid))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            newState.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            TOKEN_PRIVILEGES previousState = new TOKEN_PRIVILEGES();
            uint previousStateSize = 0;

            if (!AdjustTokenPrivileges(tokenHandle, false, ref newState, (uint)Marshal.SizeOf(previousState), ref previousState, ref previousStateSize))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            if (Marshal.GetLastWin32Error() != ERROR_SUCCESS)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
    }
}
