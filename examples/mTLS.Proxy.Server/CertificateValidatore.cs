using Serilog;
using System.Resources;
using System.Security.Cryptography.X509Certificates;

namespace mTLS.Proxy.Server;

public interface ICertificateValidator
{
    bool Validate(X509Certificate2 clientCertificate);
}

public class CertificateValidator : ICertificateValidator
{
    public bool Validate(X509Certificate2 clientCertificate)
    {
        try
        {
            Console.WriteLine(clientCertificate.Subject);   
            return true;
        }
        catch (Exception ex)
        {
            throw ex;
        }
    }
}
