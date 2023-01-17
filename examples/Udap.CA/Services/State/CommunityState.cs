using Udap.CA.ViewModel;

namespace Udap.CA.Services.State
{
    public class CommunityState

    {
        public CommunityState() { }

        public Community? Community { get; set; }

        public ICollection<RootCertificate> RootCertificates { get; set;}

        public void SetState(Community value) {
            Community = value;
        }

        public void SetState(ICollection<RootCertificate> value)
        {
            RootCertificates = value;
        }
    }
}
