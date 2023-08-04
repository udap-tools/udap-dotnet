using Udap.Auth.Server.Admin.ViewModel;

namespace Udap.Auth.Server.Admin.Services.State
{
    public class CommunityState

    {
        public CommunityState() { }

        public ViewModel.Community? Community { get; set; }

        public ICollection<IntermediateCertificate>? IntermediateCertificates { get; set;}

        public void SetState(ViewModel.Community value) {
            Community = value;
        }

        public void SetState(ICollection<IntermediateCertificate>? value)
        {
            IntermediateCertificates = value;
        }
    }
}
