using System;

namespace Mono.Math.Prime.Generator
{

#if INSIDE_CORLIB
	internal
#else
	public
#endif
	abstract class PrimeGeneratorBase
	{

		public virtual ConfidenceFactor Confidence
		{
			get
			{
#if DEBUG
				return ConfidenceFactor.ExtraLow;
#else
				return ConfidenceFactor.Medium;
#endif
			}
		}

		public virtual Prime.PrimalityTest PrimalityTest
		{
			get
			{
				return new Prime.PrimalityTest(PrimalityTests.RabinMillerTest);
			}
		}

		public virtual int TrialDivisionBounds
		{
			get { return 4000; }
		}

		protected bool PostTrialDivisionTests(BigInteger bi)
		{
			return PrimalityTest(bi, this.Confidence);
		}

		public abstract BigInteger GenerateNewPrime(int bits);
	}
}