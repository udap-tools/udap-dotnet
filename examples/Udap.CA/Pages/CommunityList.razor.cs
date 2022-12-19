using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.JSInterop;
using Udap.CA.Services;
using Udap.CA.Services.State;
using Udap.CA.ViewModel;

namespace Udap.CA.Pages;

public partial class CommunityList
{

    [Inject] CommunityService CommunityService { get; set; }
    [Inject] RootCertificateService RootCertificateService { get; set; }
    [Inject] CommunityState CommunityState { get; set; }
    [Inject] private IJSRuntime Js { get; set; }
    ErrorBoundary? ErrorBoundary { get; set; }
    private List<string> editEvents = new();
    private string searchString = "";
    private Community communityBeforeEdit;
    private ICollection<Community> Communities = new List<Community>();
    private ICollection<RootCertificate> RootCertificates = new List<RootCertificate>();

    protected override async Task OnInitializedAsync()
    {
        var taskCommunities = CommunityService.Get();
        var taskRootCertificates = RootCertificateService.Get();

        await Task.WhenAll(taskCommunities, taskRootCertificates);

        Communities = await taskCommunities;
        RootCertificates = await taskRootCertificates;

        CommunityState.SetState(RootCertificates);
    }

    protected override void OnParametersSet()
    {
        ErrorBoundary?.Recover();
    }

    private void ClearEventLog()
    {
        editEvents.Clear();
    }

    private void AddEditionEvent(string message)
    {
        editEvents.Add(message);
        StateHasChanged();
    }

    private void BackupItem(object community)
    {
        try
        {
            communityBeforeEdit = new()
        {
            Id = ((Community)community).Id,
            Name = ((Community)community).Name,
            Enabled = ((Community)community).Enabled,
        };
        AddEditionEvent($"CommunityEditPreview event: made a backup of Community {((Community)community).Name}");
        }
        catch (Exception e)
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
            _communityRowInEdit.Id = resultAnchor.Id;
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
        ((Community)community).Id = communityBeforeEdit.Id;
        ((Community)community).Name = communityBeforeEdit.Name;
        ((Community)community).Enabled = communityBeforeEdit.Enabled;
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

        Communities.Add(_communityRowInEdit);
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
                Communities.Remove(community);
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
        if (string.IsNullOrWhiteSpace(searchString))
            return true;
        if (community.Name.Contains(searchString, StringComparison.OrdinalIgnoreCase))
            return true;        
        return false;
    }
}

