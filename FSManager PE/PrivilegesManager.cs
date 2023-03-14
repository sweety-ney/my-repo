using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FSManager_PE
{
    public class PrivilegesManager
    {
        private const string SE_MANAGE_VOLUME_NAME = "SeManageVolumePrivilege";
        private const string SE_TAKE_OWNERSHIP_NAME = "SeTakeOwnershipPrivilege";

        private readonly Win32API _win32Api;

        public PrivilegesManager()
        {
            _win32Api = new Win32API();
        }

        public bool EnableManageVolumePrivilege()
        {
            return _win32Api.EnablePrivilege(SE_MANAGE_VOLUME_NAME);
        }

        public bool DisableManageVolumePrivilege()
        {
            return _win32Api.DisablePrivilege(SE_MANAGE_VOLUME_NAME);
        }

        public bool EnableTakeOwnershipPrivilege()
        {
            return _win32Api.EnablePrivilege(SE_TAKE_OWNERSHIP_NAME);
        }

        public bool DisableTakeOwnershipPrivilege()
        {
            return _win32Api.DisablePrivilege(SE_TAKE_OWNERSHIP_NAME);
        }
    }

}
