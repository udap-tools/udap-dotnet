#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.X509.Extension;
using Org.BouncyCastle.X509;
using System.Reflection;
using System.Resources;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Math;
using Xunit.Abstractions;
using X509Extension = System.Security.Cryptography.X509Certificates.X509Extension;
using X509Extensions = Org.BouncyCastle.Asn1.X509.X509Extensions;

namespace Udap.PKI.Generator;
public class CertificateBase
{
    private static string _baseDir;

    protected static string BaseDir
    {
        get
        {
            if (!String.IsNullOrEmpty(_baseDir))
            {
                return _baseDir;
            }

            var assembly = Assembly.GetExecutingAssembly();
            var resourcePath = String.Format(
                $"{Regex.Replace(assembly.ManifestModule.Name, @"\.(exe|dll)$", string.Empty, RegexOptions.IgnoreCase)}" +
                $".Resources.ProjectDirectory.txt");

            var rm = new ResourceManager("Resources", assembly);

            // string[] names = assembly.GetManifestResourceNames(); // Help finding names

            using var stream = assembly.GetManifestResourceStream(resourcePath);
            using var streamReader = new StreamReader(stream);

            _baseDir = streamReader.ReadToEnd().Trim();

            return _baseDir;
        }
    }

    protected string DefaultPKCS12Password { get; set; }

    protected void UpdateWindowsMachineStore(X509Certificate2 certificate)
    {
        //This could be modified to handle Linux also... Maybe later.
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite);

            var oldCert = store.Certificates.SingleOrDefault(c => c.Subject == certificate.Subject);

            if (oldCert != null)
            {
                store.Remove(oldCert);
            }

            store.Add(certificate);
            store.Close();
        }
    }

    protected static void AddAuthorityKeyIdentifier(X509Certificate2 caCert, CertificateRequest intermediateReq, ITestOutputHelper testOutputHelper)
    {
        //
        // Found way to generate intermediate below
        //
        // https://github.com/rwatjen/AzureIoTDPSCertificates/blob/711429e1b6dee7857452233a73f15c22c2519a12/src/DPSCertificateTool/CertificateUtil.cs#L69
        // https://blog.rassie.dk/2018/04/creating-an-x-509-certificate-chain-in-c/
        //


        var issuerSubjectKey = caCert.Extensions?["2.5.29.14"].RawData;
        var segment = new ArraySegment<byte>(issuerSubjectKey, 2, issuerSubjectKey.Length - 2);
        var authorityKeyIdentifier = new byte[segment.Count + 4];
        // these bytes define the "KeyID" part of the AuthorityKeyIdentifier
        authorityKeyIdentifier[0] = 0x30;
        authorityKeyIdentifier[1] = 0x16;
        authorityKeyIdentifier[2] = 0x80;
        authorityKeyIdentifier[3] = 0x14;
        segment.CopyTo(authorityKeyIdentifier, 4);
        intermediateReq.CertificateExtensions.Add(new X509Extension("2.5.29.35", authorityKeyIdentifier, false));
    }

    protected static X509Extension MakeCdp(string url)
    {
        //
        // urls less than 119 char solution.
        // From Bartonjs of course.
        //
        // https://stackoverflow.com/questions/60742814/add-crl-distribution-points-cdp-extension-to-x509certificate2-certificate
        //
        // From Crypt32:  .NET doesn't support CDP extension. You have to use 3rd party libraries for that. BC is ok if it works for you.
        // Otherwise write you own. :)
        //

        byte[] encodedUrl = Encoding.ASCII.GetBytes(url);

        if (encodedUrl.Length > 119)
        {
            throw new NotSupportedException();
        }

        byte[] payload = new byte[encodedUrl.Length + 10];
        int offset = 0;
        payload[offset++] = 0x30;
        payload[offset++] = (byte)(encodedUrl.Length + 8);
        payload[offset++] = 0x30;
        payload[offset++] = (byte)(encodedUrl.Length + 6);
        payload[offset++] = 0xA0;
        payload[offset++] = (byte)(encodedUrl.Length + 4);
        payload[offset++] = 0xA0;
        payload[offset++] = (byte)(encodedUrl.Length + 2);
        payload[offset++] = 0x86;
        payload[offset++] = (byte)(encodedUrl.Length);
        Buffer.BlockCopy(encodedUrl, 0, payload, offset, encodedUrl.Length);

        return new X509Extension("2.5.29.31", payload, critical: false);
    }

    protected static CrlNumber GetNextCrlNumber(string fileName)
    {
        CrlNumber nextCrlNum = new CrlNumber(BigInteger.One);

        if (File.Exists(fileName))
        {
            byte[] buf = File.ReadAllBytes(fileName);
            var crlParser = new X509CrlParser();
            var prevCrl = crlParser.ReadCrl(buf);
            var prevCrlNum = prevCrl.GetExtensionValue(X509Extensions.CrlNumber);
            var asn1Object = X509ExtensionUtilities.FromExtensionValue(prevCrlNum);
            var prevCrlNumVal = DerInteger.GetInstance(asn1Object).PositiveValue;
            nextCrlNum = new CrlNumber(prevCrlNumVal.Add(BigInteger.One));
        }

        return nextCrlNum;
    }

}
