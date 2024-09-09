namespace Kerberos.NET.Crypto
{
    public class ManagedDiffieHellmanOakley14 : ManagedDiffieHellman
    {
        public ManagedDiffieHellmanOakley14()
            : base(Oakley.Group14.Prime, Oakley.Group14.Generator, Oakley.Group14.Factor)
        {
        }
    }
}