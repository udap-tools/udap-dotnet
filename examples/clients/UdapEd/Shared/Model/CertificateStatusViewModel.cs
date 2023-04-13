namespace UdapEd.Shared.Model;

public class CertificateStatusViewModel
{
    public CertLoadedEnum CertLoaded { get; set;} = CertLoadedEnum.Negative;

    public List<string> SubjectAltNames { get; set;} = new List<string>();
}