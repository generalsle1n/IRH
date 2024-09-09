using Mono.Math.Prime.Generator;
using System;

namespace Mono.Math.Generator
{

#if INSIDE_CORLIB
	internal
#else
    public
#endif
    class NextPrimeFinder : SequentialSearchPrimeGeneratorBase
    {

        protected override BigInteger GenerateSearchBase(int bits, object Context)
        {
            if (Context == null)
                throw new ArgumentNullException("Context");

            BigInteger ret = new BigInteger((BigInteger)Context);
            ret.SetBit(0);
            return ret;
        }
    }
}