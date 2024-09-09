using IRH.Kerberos.Utilities.Memory;
using IRH.Kerberos.Win32;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;

namespace IRH.Kerberos.Ndr
{
#pragma warning disable 1591
    [Flags]
    [Serializable]
    public enum NdrInterpreterOptFlags : byte
    {
        ServerMustSize = 0x01,
        ClientMustSize = 0x02,
        HasReturn = 0x04,
        HasPipes = 0x08,
        HasAsyncUuid = 0x20,
        HasExtensions = 0x40,
        HasAsyncHandle = 0x80,
    }

    [Flags]
    [Serializable]
    public enum NdrInterpreterOptFlags2 : byte
    {
        HasNewCorrDesc = 0x01,
        ClientCorrCheck = 0x02,
        ServerCorrCheck = 0x04,
        HasNotify = 0x08,
        HasNotify2 = 0x10,
        HasComplexReturn = 0x20,
        HasRangeOnConformance = 0x40,
        HasBigByValParam = 0x80,
        Valid = HasNewCorrDesc | ClientCorrCheck | ServerCorrCheck | HasNotify | HasNotify2 | HasRangeOnConformance
    }

#pragma warning restore 1591



    [Flags]
    public enum NdrParserFlags
    {
        None = 0,
        IgnoreUserMarshal = 1,
    }


}
