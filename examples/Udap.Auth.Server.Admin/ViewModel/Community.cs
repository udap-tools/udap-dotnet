using System.Security.Cryptography.X509Certificates;

namespace Udap.Auth.Server.Admin.ViewModel
{
    public class Community
    {
        public long Id { get; set; }

        public string? Name { get; set; }

        public bool Enabled { get; set; }

        public bool Default { get; set; }

        public ICollection<Anchor> Anchors { get; set; } = new HashSet<Anchor>();

        public ICollection<IntermediateCertificate> IntermediateCertificates { get; set; } = new HashSet<IntermediateCertificate>();
        
        public ICollection<Certification> Certifications { get; set; } = new HashSet<Certification>();
        
        public bool ShowAnchors { get; set; }

        public bool ShowIntermediateCertificates { get; set; }

        public bool ShowCertifications { get; set; }
    }

    public class Anchor
    {
        public long Id { get; set; }
        public bool Enabled { get; set; }
        public string? Name { get; set; }
        public string? Community { get; set; }
        public long CommunityId { get; set; }
        public X509Certificate2? Certificate { get; set; }
        public string? Thumbprint { get; set; }
        public DateTime? BeginDate { get; set; }
        public DateTime? EndDate { get; set; }
    }

    public class IntermediateCertificate
    {
        public long Id { get; set; }
        public bool Enabled { get; set; }
        public string? Name { get; set; }
        public X509Certificate2? Certificate { get; set; }
        public string? Thumbprint { get; set; }
        public DateTime? BeginDate { get; set; }
        public DateTime? EndDate { get; set; }

        public virtual Anchor Anchor { get; set; } = default!;
    }

    public class Certification
    {
        public string? Id { get; set; }
        public string? Name { get; set; }
    }

    public class IssuedCertificate
    {
        public int Id { get; set; }
        public bool Enabled { get; set; }
        public string? Name { get; set; }
        public string? Community { get; set; }

        public X509Certificate2? Certificate { get; set; }
        public DateTime? BeginDate { get; set; }
        public DateTime? EndDate { get; set; }
    }
}
