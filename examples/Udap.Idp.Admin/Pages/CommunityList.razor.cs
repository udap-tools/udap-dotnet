using Microsoft.AspNetCore.Components;
using Udap.Idp.Admin.Services;
using Udap.Idp.Admin.Services.State;
using Udap.Idp.Admin.ViewModel;

namespace Udap.Idp.Admin.Pages;

public partial class CommunityList
{

    [Inject]
    ApiService ApiService { get; set; }
    
    [Inject]
    CommunityState CommunityState { get; set; }

    private List<string> editEvents = new();
    private string searchString = "";
    private Community communityBeforeEdit;
    private IEnumerable<Community> Communities = new List<Community>();

    protected override async Task OnInitializedAsync()
    {
        Communities = await ApiService.GetCommunities();        
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
        communityBeforeEdit = new()
        {
            Id = ((Community)community).Id,
            Name = ((Community)community).Name,
            Enabled = ((Community)community).Enabled,
            Default = ((Community)community).Default
        };
        AddEditionEvent($"RowEditPreview event: made a backup of Community {((Community)community).Name}");
    }

    private void ItemHasBeenCommitted(object community)
    {
        AddEditionEvent($"RowEditCommit event: Changes to Community {((Community)community).Name} committed");
    }

    private void ResetItemToOriginalValues(object community)
    {
        if ( community == null ) {
            AddEditionEvent($"RowEditCancel event: Null community.  Probably related data open.");
            return;
        }
        ((Community)community).Id = communityBeforeEdit.Id;
        ((Community)community).Name = communityBeforeEdit.Name;
        ((Community)community).Enabled = communityBeforeEdit.Enabled;
        ((Community)community).Default = communityBeforeEdit.Default;
        AddEditionEvent($"RowEditCancel event: Editing of Community {((Community)community).Name} cancelled");
    }


    public void ShowAnchor(Community community)
    {
        community.ShowAnchors = true;
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

