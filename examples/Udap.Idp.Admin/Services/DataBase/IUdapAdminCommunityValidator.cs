using System.Security.Cryptography.X509Certificates;
using Udap.Server.Entities;

namespace Udap.Idp.Admin.Services.DataBase;

public interface IUdapAdminCommunityValidator
{
}

public class UdapAdminCommunityValidator : IUdapAdminCommunityValidator
{

}

public interface IUdapCertificateValidator<in T> where T : ICertificateValidateMarker
{
    bool Validate(T certificateContainer);
}

public class UdapAdminAnchorValidator : IUdapCertificateValidator<Anchor>
{
    public bool Validate(Anchor anchor)
    {
        if (anchor == null)
        {
            throw new ArgumentNullException(nameof(anchor));
        }

        var cert = X509Certificate2.CreateFromPem(anchor.X509Certificate);

        if (anchor.BeginDate != cert.NotBefore)
        {
            throw new Exception("Invalid begin date.");
        }

        if (anchor.EndDate != cert.NotAfter)
        {
            throw new Exception("Invalid end date.");
        }

        return true;
    }
}

public class UdapAdminRootCertificateValidator : IUdapCertificateValidator<RootCertificate>
{
    public bool Validate(RootCertificate anchor)
    {
        if (anchor == null)
        {
            throw new ArgumentNullException(nameof(anchor));
        }

        var cert = X509Certificate2.CreateFromPem(anchor.X509Certificate);

        if (anchor.BeginDate != cert.NotBefore)
        {
            throw new Exception("Invalid begin date.");
        }

        if (anchor.EndDate != cert.NotAfter)
        {
            throw new Exception("Invalid end date.");
        }

        return true;
    }
}