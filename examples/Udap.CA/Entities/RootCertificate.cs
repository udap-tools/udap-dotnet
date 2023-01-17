using System.Security.Cryptography.X509Certificates;
using Udap.CA.Services;

namespace Udap.CA.Entities;

public class RootCertificate 
{
    public int Id { get; set; }

    public int CommunityId { get; set; }

    public bool Enabled { get; set; }
    public string Name { get; set; }
    /// <summary>
    /// Certificate Bytes
    /// If CertSecurityLevel <see cref="CertSecurityLevel.Software"/>, store in RSAPriateKey pem format and X509Certificate format;
    /// If CertSecurityLevel <see cref="CertSecurityLevel.Fips1402"/>, store in X509Certificate pem format only; 
    /// </summary>
    public string RSAPriateKey { get; set; }

    public string X509Certificate { get; set; }

    /// <summary>
    /// Default to Software type.  This will always be a PKCS12 format.
    /// </summary>
    public CertSecurityLevel CertSecurityLevel { get; set; } = CertSecurityLevel.Software;

    /// <summary>
    /// This is just a sample.  Sample is password in practice for this sample app.
    /// If we created a real implementation this would we would use and HSM
    /// and PKCS #11 protocol to communicate with it.  Maybe I will find some time
    /// to create an implementation.  
    /// </summary>
    public string Secret { get; set; }

    public string Thumbprint { get; set; }

    /// <summary>
    /// Place where public certificate is hosted.
    /// </summary>
    public string Url { get; set; }

    public DateTime BeginDate { get; set; }
    public DateTime EndDate { get; set; }

    public Community Community { get; set; }

    /// <summary>
    /// Generally a community has one Anchor.
    /// But during rollover from an expired anchor to a new anchor
    /// there could be two for a short time.
    /// </summary>
    public ICollection<Anchor>? Anchors { get; set; }


    
}

