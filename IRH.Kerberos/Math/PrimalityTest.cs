using System;

namespace Mono.Math.Prime
{

#if INSIDE_CORLIB
	internal
#else
    public
#endif
    delegate bool PrimalityTest(BigInteger bi, ConfidenceFactor confidence);

#if INSIDE_CORLIB
	internal
#else
    public
#endif
    sealed class PrimalityTests
    {

        private PrimalityTests()
        {
        }

        #region SPP Test

        private static int GetSPPRounds(BigInteger bi, ConfidenceFactor confidence)
        {
            int bc = bi.BitCount();

            int Rounds;

            if (bc <= 100) Rounds = 27;
            else if (bc <= 150) Rounds = 18;
            else if (bc <= 200) Rounds = 15;
            else if (bc <= 250) Rounds = 12;
            else if (bc <= 300) Rounds = 9;
            else if (bc <= 350) Rounds = 8;
            else if (bc <= 400) Rounds = 7;
            else if (bc <= 500) Rounds = 6;
            else if (bc <= 600) Rounds = 5;
            else if (bc <= 800) Rounds = 4;
            else if (bc <= 1250) Rounds = 3;
            else Rounds = 2;

            switch (confidence)
            {
                case ConfidenceFactor.ExtraLow:
                    Rounds >>= 2;
                    return Rounds != 0 ? Rounds : 1;
                case ConfidenceFactor.Low:
                    Rounds >>= 1;
                    return Rounds != 0 ? Rounds : 1;
                case ConfidenceFactor.Medium:
                    return Rounds;
                case ConfidenceFactor.High:
                    return Rounds << 1;
                case ConfidenceFactor.ExtraHigh:
                    return Rounds << 2;
                case ConfidenceFactor.Provable:
                    throw new Exception("The Rabin-Miller test can not be executed in a way such that its results are provable");
                default:
                    throw new ArgumentOutOfRangeException("confidence");
            }
        }

        public static bool Test(BigInteger n, ConfidenceFactor confidence)
        {
            if (n.BitCount() < 33)
                return SmallPrimeSppTest(n, confidence);
            else
                return RabinMillerTest(n, confidence);
        }

        public static bool RabinMillerTest(BigInteger n, ConfidenceFactor confidence)
        {
            int bits = n.BitCount();
            int t = GetSPPRounds(bits, confidence);

            BigInteger n_minus_1 = n - 1;
            int s = n_minus_1.LowestSetBit();
            BigInteger r = n_minus_1 >> s;

            BigInteger.ModulusRing mr = new BigInteger.ModulusRing(n);

            BigInteger y = null;
            if (n.BitCount() > 100)
                y = mr.Pow(2, r);

            for (int round = 0; round < t; round++)
            {

                if ((round > 0) || (y == null))
                {
                    BigInteger a = null;

                    do
                    {
                        a = BigInteger.GenerateRandom(bits);
                    } while ((a <= 2) && (a >= n_minus_1));

                    y = mr.Pow(a, r);
                }

                if (y == 1)
                    continue;

                for (int j = 0; ((j < s) && (y != n_minus_1)); j++)
                {

                    y = mr.Pow(y, 2);
                    if (y == 1)
                        return false;
                }

                if (y != n_minus_1)
                    return false;
            }
            return true;
        }

        public static bool SmallPrimeSppTest(BigInteger bi, ConfidenceFactor confidence)
        {
            int Rounds = GetSPPRounds(bi, confidence);

            BigInteger p_sub1 = bi - 1;
            int s = p_sub1.LowestSetBit();

            BigInteger t = p_sub1 >> s;


            BigInteger.ModulusRing mr = new BigInteger.ModulusRing(bi);

            for (int round = 0; round < Rounds; round++)
            {

                BigInteger b = mr.Pow(BigInteger.smallPrimes[round], t);

                if (b == 1) continue;

                bool result = false;
                for (int j = 0; j < s; j++)
                {

                    if (b == p_sub1)
                    {
                        result = true;
                        break;
                    }

                    b = (b * b) % bi;
                }

                if (result == false)
                    return false;
            }
            return true;
        }

        #endregion

    }
}