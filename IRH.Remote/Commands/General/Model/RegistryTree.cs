using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IRH.Remote.Commands.General.Model
{
    internal enum RegistryTree : uint
    {
        HKEY_CLASSES_ROOT = 2147483648,
        HKEY_CURRENT_USER = 2147483649,
        HKEY_LOCAL_MACHINE = 2147483650,
        HKEY_USERS = 2147483651,
        HKEY_CURRENT_CONFIG = 2147483653
    }
}
