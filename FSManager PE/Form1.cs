using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace FSManager_PE
{
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