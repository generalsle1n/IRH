namespace Kerberos.NET.Crypto
{
    public class ManagedDiffieHellmanOakley2 : ManagedDiffieHellman
    {
        public ManagedDiffieHellmanOakley2()
            : base(Oakley.Group2.Prime, Oakley.Group2.Generator, Oakley.Group2.Factor)
        {
        }
    }
}