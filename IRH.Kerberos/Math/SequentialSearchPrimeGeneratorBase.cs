using System;

namespace Mono.Math.Prime.Generator
{

#if INSIDE_CORLIB
	internal
#else
	public
#endif
	class SequentialSearchPrimeGeneratorBase : PrimeGeneratorBase
	{

		protected virtual BigInteger GenerateSearchBase(int bits, object context)
		{
			BigInteger ret = BigInteger.GenerateRandom(bits);
			ret.SetBit(0);
			return ret;
		}


		public override BigInteger GenerateNewPrime(int bits)
		{
			return GenerateNewPrime(bits, null);
		}


		public virtual BigInteger GenerateNewPrime(int bits, object context)
		{
			BigInteger curVal = GenerateSearchBase(bits, context);

			const uint primeProd1 = 3u * 5u * 7u * 11u * 13u * 17u * 19u * 23u * 29u;

			uint pMod1 = curVal % primeProd1;

			int DivisionBound = TrialDivisionBounds;
			uint[] SmallPrimes = BigInteger.smallPrimes;
			PrimalityTest PostTrialDivisionTest = this.PrimalityTest;
			while (true)
			{

				if (pMod1 % 3 == 0) goto biNotPrime;
				if (pMod1 % 5 == 0) goto biNotPrime;
				if (pMod1 % 7 == 0) goto biNotPrime;
				if (pMod1 % 11 == 0) goto biNotPrime;
				if (pMod1 % 13 == 0) goto biNotPrime;
				if (pMod1 % 17 == 0) goto biNotPrime;
				if (pMod1 % 19 == 0) goto biNotPrime;
				if (pMod1 % 23 == 0) goto biNotPrime;
				if (pMod1 % 29 == 0) goto biNotPrime;

				for (int p = 10; p < SmallPrimes.Length && SmallPrimes[p] <= DivisionBound; p++)
				{
					if (curVal % SmallPrimes[p] == 0)
						goto biNotPrime;
				}

				if (!IsPrimeAcceptable(curVal, context))
					goto biNotPrime;

				if (PrimalityTest(curVal, Confidence))
					return curVal;

				biNotPrime:
				pMod1 += 2;
				if (pMod1 >= primeProd1)
					pMod1 -= primeProd1;
				curVal.Incr2();
			}
		}

		protected virtual bool IsPrimeAcceptable(BigInteger bi, object context)
		{
			return true;
		}
	}
}