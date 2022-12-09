namespace Udap.Idp.Admin.Services.State
{
    public class CommunityState

    {
        public CommunityState() { }

        public ViewModel.Community? Community { get; set; }

        public ICollection<ViewModel.RootCertificate> RootCertificates { get; set;}

        public void SetState(ViewModel.Community value) {
            Community = value;
        }

        public void SetState(ICollection<ViewModel.RootCertificate> value)
        {
            RootCertificates = value;
        }
    }
}
