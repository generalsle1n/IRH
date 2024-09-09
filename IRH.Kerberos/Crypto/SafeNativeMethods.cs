using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

internal static class SafeNativeMethods
{

    public static void SetPinForPrivateKey(this X509Certificate2 certificate, string pin)
    {

        if (certificate == null)
            throw new ArgumentNullException("certificate");


        if (certificate.PrivateKey is RSACryptoServiceProvider rsaCsp)
        {

            var providerHandle = IntPtr.Zero;
            var pinBuffer = Encoding.ASCII.GetBytes(pin);

            SafeNativeMethods.Execute(() => SafeNativeMethods.CryptAcquireContext(ref providerHandle,
                                            rsaCsp.CspKeyContainerInfo.KeyContainerName,
                                            rsaCsp.CspKeyContainerInfo.ProviderName,
                                            rsaCsp.CspKeyContainerInfo.ProviderType,
                                            SafeNativeMethods.CryptContextFlags.Silent));
            SafeNativeMethods.Execute(() => SafeNativeMethods.CryptSetProvParam(providerHandle,
                                            SafeNativeMethods.CryptParameter.KeyExchangePin,
                                            pinBuffer, 0));
            SafeNativeMethods.Execute(() => SafeNativeMethods.CertSetCertificateContextProperty(
                                            certificate.Handle,
                                            SafeNativeMethods.CertificateProperty.CryptoProviderHandle,
                                            0, providerHandle));
        }
    }

    internal enum CryptContextFlags
    {
        None = 0,
        Silent = 0x40
    }

    internal enum CertificateProperty
    {
        None = 0,
        CryptoProviderHandle = 0x1
    }

    internal enum CryptParameter
    {
        None = 0,
        KeyExchangePin = 0x20
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern bool CryptAcquireContext(
        ref IntPtr hProv,
        string containerName,
        string providerName,
        int providerType,
        CryptContextFlags flags
        );

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern bool CryptSetProvParam(
        IntPtr hProv,
        CryptParameter dwParam,
        [In] byte[] pbData,
        uint dwFlags);

    [DllImport("CRYPT32.DLL", SetLastError = true)]
    internal static extern bool CertSetCertificateContextProperty(
        IntPtr pCertContext,
        CertificateProperty propertyId,
        uint dwFlags,
        IntPtr pvData
        );

    public static void Execute(Func<bool> action)
    {
        if (!action())
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }
}