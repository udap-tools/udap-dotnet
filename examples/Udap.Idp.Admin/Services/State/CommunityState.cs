namespace Udap.Idp.Admin.Services.State
{
    public class CommunityState

    {
        public CommunityState() { }

        public ViewModel.Community? Community { get; set; }

        public void SetState(ViewModel.Community value) {
            Community = value;
        }
    }
}
