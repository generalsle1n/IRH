using System;

namespace Mono.Math.Prime
{
#if INSIDE_CORLIB
	internal
#else
    public
#endif
    enum ConfidenceFactor
    {
        ExtraLow,
        Low,
        Medium,
        High,
        ExtraHigh,
        Provable
    }
}