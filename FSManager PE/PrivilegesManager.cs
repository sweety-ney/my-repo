using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security;
using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;

namespace FSManager_PE
{

    public class VolumeManager
    {
        private const int SE_MANAGE_VOLUME_NAME = 0x0024;
        private const int SE_CREATE_SYMBOLIC_LINK_NAME = 0x002D;
        private const int TOKEN_ADJUST_PRIVILEGES = 0x0020;
        private const int TOKEN_QUERY = 0x0008;
        private const int ERROR_NOT_ALL_ASSIGNED = 1300;

        private readonly IntPtr processToken;
        private readonly NativeMethods.LUID luidManageVolume;
        private readonly NativeMethods.LUID luidCreateSymbolicLink;

        public VolumeManager()
        {
            NativeMethods.OpenProcessToken(NativeMethods.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out processToken);

            NativeMethods.LookupPrivilegeValue(null, "SeManageVolumePrivilege", out luidManageVolume);
            NativeMethods.LookupPrivilegeValue(null, "SeCreateSymbolicLinkPrivilege", out luidCreateSymbolicLink);
        }

        public bool AdjustPrivilege(string privilegeName, bool enable)
        {
            NativeMethods.LUID luid;
            if (privilegeName == "SeManageVolumePrivilege")
            {
                luid = luidManageVolume;
            }
            else if (privilegeName == "SeCreateSymbolicLinkPrivilege")
            {
                luid = luidCreateSymbolicLink;
            }
            else
            {
                throw new ArgumentException("Invalid privilege name", nameof(privilegeName));
            }

            NativeMethods.TOKEN_PRIVILEGES tokenPrivileges = new NativeMethods.TOKEN_PRIVILEGES
            {
                PrivilegeCount = 1,
                Privileges = new NativeMethods.LUID_AND_ATTRIBUTES[1]
                {
                    new NativeMethods.LUID_AND_ATTRIBUTES
                    {
                        Luid = luid,
                        Attributes = (uint)(enable ? NativeMethods.SE_PRIVILEGE_ENABLED : 0)
                    }
                }
            };

            if (NativeMethods.AdjustTokenPrivileges(processToken, false, ref tokenPrivileges, 0, IntPtr.Zero, IntPtr.Zero))
            {
                return true;
            }

            int error = Marshal.GetLastWin32Error();
            if (error == ERROR_NOT_ALL_ASSIGNED)
            {
                throw new UnauthorizedAccessException("Insufficient privileges");
            }

            throw new InvalidOperationException($"Failed to adjust privilege (error code: {error})");
        }
    }
}
