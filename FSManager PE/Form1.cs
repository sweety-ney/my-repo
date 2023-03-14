using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace FSManager_PE
{
    public static class PrivilegesManager
    {
        private const int TOKEN_ADJUST_PRIVILEGES = 0x0020;
        private const int TOKEN_QUERY = 0x0008;
        private const string SE_MANAGE_VOLUME_NAME = "SeManageVolumePrivilege";
        private const uint SE_PRIVILEGE_ENABLED = 0x00000002;

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public LUID_AND_ATTRIBUTES[] Privileges;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint Zero, IntPtr Null1, IntPtr Null2);

        public static void EnableManageVolumePrivilege()
        {
            IntPtr tokenHandle = IntPtr.Zero;
            try
            {
                if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out tokenHandle))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                LUID luid;
                if (!LookupPrivilegeValue(null, SE_MANAGE_VOLUME_NAME, out luid))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                TOKEN_PRIVILEGES newState = new TOKEN_PRIVILEGES();
                newState.PrivilegeCount = 1;
                newState.Privileges = new LUID_AND_ATTRIBUTES[1];
                newState.Privileges[0].Luid = luid;
                newState.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                if (!AdjustTokenPrivileges(tokenHandle, false, ref newState, 0, IntPtr.Zero, IntPtr.Zero))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
            }
            finally
            {
                if (tokenHandle != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(tokenHandle);
                }
            }
        }
    }

    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
            PrivilegesManager.EnableManageVolumePrivilege();
            MFTReader mftReader = new MFTReader("C");
            mftReader.EnumerateEntries(entry =>
            {
                Debug.WriteLine(entry.FileName);
            });
            mftReader.Close();

        }
    }
}