
using Microsoft.AspNetCore.Components;
using Udap.Idp.Admin.Services.State;
using Udap.Idp.Admin.ViewModel;

namespace Udap.Idp.Admin.Pages;

public partial class CAEdit
{
    [Inject] CommunityState communityState { get; set; }
    [Inject] NavigationManager navManager { get; set; }
    
    private Community? _community;

    protected override void OnInitialized()
    {
        base.OnInitialized();

        if (communityState.Community == null)
        {
            navManager.NavigateTo("/CommunityList");
        }

        _community = communityState.Community;
    }
}

