namespace Udap.CA.ViewModel
{
    public class Community
    {
        public int Id { get; set; }

        public string Name { get; set; } = string.Empty;

        public bool Enabled { get; set; }

        public ICollection<RootCertificate> RootCertificates { get; set; } = new HashSet<RootCertificate>();
        
        public bool ShowRootCertificates { get; set; }
    }
}
