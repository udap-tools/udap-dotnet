#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.JSInterop;
using Udap.CA.Services;
using Udap.CA.Services.State;
using Udap.CA.ViewModel;

namespace Udap.CA.Pages;

public partial class CommunityList
{

    [Inject] private CommunityService CommunityService { get; set; } = null!;
    [Inject] private RootCertificateService RootCertificateService { get; set; } = null!;
    [Inject] CommunityState CommunityState { get; set; } = null!;
    [Inject] private IJSRuntime Js { get; set; } = null!;
    ErrorBoundary? ErrorBoundary { get; set; }
    private readonly List<string> _editEvents = new();
    private string _searchString = "";
    private Community? _communityBeforeEdit;
    private ICollection<Community> _communities = new List<Community>();
    private ICollection<RootCertificate> _rootCertificates = new List<RootCertificate>();

    protected override async Task OnInitializedAsync()
    {
        _communities = await CommunityService.Get();
        _rootCertificates = await RootCertificateService.Get();

        CommunityState.SetState(_rootCertificates);
    }

    protected override void OnParametersSet()
    {
        ErrorBoundary?.Recover();
    }

    private void ClearEventLog()
    {
        _editEvents.Clear();
    }

    private void AddEditionEvent(string message)
    {
        _editEvents.Add(message);
        StateHasChanged();
    }

    private void BackupItem(object community)
    {
        try
        {
            _communityBeforeEdit = new()
        {
            Id = ((Community)community).Id,
            Name = ((Community)community).Name,
            Enabled = ((Community)community).Enabled,
        };
        AddEditionEvent($"CommunityEditPreview event: made a backup of Community {((Community)community).Name}");
        }
        catch 
        {
            throw;
        }

        _communityRowIsInEdit = true;
    }

    private void ItemHasBeenCommitted(object community)
    {
        var communityViewModel = (Community)community;

        if (communityViewModel.Id > 0)
        {
            // While this is a sync over async problem it at least will not wrap the erro in AggregateException
            // https://github.com/davidfowl/AspNetCoreDiagnosticScenarios/blob/master/AsyncGuidance.md#warning-deadlocks
            // The MudBlazor table does not RowEditCommit is not async.  Here is a work around https://github.com/MudBlazor/MudBlazor/issues/3230
            // I am just not going to spend the time right now.  And if I come back to this maybe I try a PR to the Mudblazor project.
            Task.Run(() => CommunityService.Update(communityViewModel)).GetAwaiter().GetResult();
            AddEditionEvent($"CommunityEditCommit event: Updating anchor {communityViewModel.Name} committed");
        }
        else
        {
            // FYI there is a work around to this sync over async 
            var resultAnchor = Task.Run(() => CommunityService.Create(communityViewModel)).GetAwaiter().GetResult();
            
            if (_communityRowInEdit != null)
            {
                _communityRowInEdit.Id = resultAnchor.Id;
            }

            AddEditionEvent($"CommunityEditCommit event: Changes to Community {((Community)community).Name} committed");
        }

        _communityRowIsInEdit = false;
        StateHasChanged();
    }

    private void ResetItemToOriginalValues(object community)
    {
        if ( community == null ) {
            AddEditionEvent($"CommunityEditCancel event: Null community.  Probably related data open.");
            return;
        }

        if (_communityBeforeEdit != null)
        {
            ((Community)community).Id = _communityBeforeEdit.Id;
            ((Community)community).Name = _communityBeforeEdit.Name;
            ((Community)community).Enabled = _communityBeforeEdit.Enabled;
        }

        AddEditionEvent($"CommunityEditCancel event: Editing of Community {((Community)community).Name} cancelled");

        _communityRowIsInEdit = false;

    }

    private Community? _communityRowInEdit;
    private bool _communityRowIsInEdit = false;

    private async Task AddCommunity()
    {
        _communityRowInEdit = new Community()
        {
        };

        _communities.Add(_communityRowInEdit);
        await Task.Delay(1);
        StateHasChanged();

        await Js.InvokeVoidAsync("UdapCA.setFocus", "CommunityId:0");

        StateHasChanged();
    }

    private async Task<bool> DeleteRootCommunity(Community community)
    {
        if (await Js.InvokeAsync<bool>("confirm", $"Do you want to delete the {community.Name} Record?"))
        {
            var result = await CommunityService.Delete(community.Id);

            if (true)
            {
                _communityRowIsInEdit = false;
                _communities.Remove(community);
                _communityRowInEdit = null;
                StateHasChanged();
                return true;
            }
        }
        return false;
    }

    public void ShowRootCertificates(Community community)
    {
        community.ShowRootCertificates = true;
    }



    private bool FilterFunc(Community community)
    {
        if (string.IsNullOrWhiteSpace(_searchString))
            return true;
        if (community.Name.Contains(_searchString, StringComparison.OrdinalIgnoreCase))
            return true;        
        return false;
    }
}

