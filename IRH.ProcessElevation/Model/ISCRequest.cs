using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IRH.ProcessElevation.Model
{
    internal enum ISCRequest
    {
        Delegate = 1,
        MutualAuth = 2,
        ReplayDetect = 4,
        SequenceDetect = 8,
        Confidentiality = 16,
        UseSessionKey = 32,
        PromptForCreds = 64,
        UseSuppliedCreds = 128,
        AllocateMemory = 256,
        UseDCEStyle = 512,
        Datagram = 1024,
        Connection = 2048,
        ExtendedError = 16384,
        Stream = 32768,
        Integrity = 65536,
        ManualCredValidation = 524288,
        HTTP = 268435456
    }
}
