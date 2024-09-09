using System;

namespace Kerberos.NET.Crypto
{
    public interface IKeyAgreement : IDisposable
    {
        IExchangeKey PublicKey { get; }

        IExchangeKey PrivateKey { get; }

        byte[] GenerateAgreement();

        void ImportPartnerKey(IExchangeKey publicKey);
    }
}