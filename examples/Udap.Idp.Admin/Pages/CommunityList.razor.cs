using System.Diagnostics;
using Microsoft.AspNetCore.Components;
using Udap.Idp.Admin.Services;
using Udap.Idp.Admin.Services.DataBase;
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
    private Community? _communityRowInEdit;
    private bool _communityRowIsInEditMode;
    private ICollection<Community> Communities = new List<Community>();
    private ICollection<IntermediateCertificate>? RootCertificates = new List<IntermediateCertificate>();

    protected override async Task OnInitializedAsync()
    {
        var taskCommunities = ApiService.GetCommunities();
        var taskRootCertificates = ApiService.GetRootCertificates();

        await Task.WhenAll(taskCommunities, taskRootCertificates);

        Communities = await taskCommunities;
        RootCertificates = await taskRootCertificates;

        CommunityState.SetState(RootCertificates);
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

        _communityRowIsInEditMode = true;
    }

    private void ItemHasBeenCommitted(object community)
    {
        var communityView = (Community)community;

        if (communityView.Id > 0)
        {
            UpdateRecord(communityView);
        }
        else
        {
            // communityView.BeginDate = communityView.Certificate.NotBefore;
            // communityView.EndDate = communityView.Certificate.NotAfter;
            var resultAnchor = ApiService.Save(communityView).GetAwaiter().GetResult();
            AddEditionEvent($"RowEditCommit event: Changes to Community {((Community)community).Name} committed");
            Debug.Assert(_communityRowInEdit != null, nameof(_communityRowInEdit) + " != null");
            _communityRowInEdit.Id = resultAnchor.Id; //bind up the new id...
        }

        _communityRowIsInEditMode = false;
        StateHasChanged();
    }

    private void UpdateRecord(Community communityView)
    {
        ApiService.Update(communityView).GetAwaiter().GetResult();
        AddEditionEvent($"RowEditCommit event: Updating anchor {communityView.Name} committed");
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

        _communityRowIsInEditMode = false;
        StateHasChanged();
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
    
    private async Task AddCommunity()
    {
        _communityRowInEdit = new ViewModel.Community();

        Communities.Add(_communityRowInEdit);
        await Task.Delay(1);
        StateHasChanged();

        // await Js.InvokeVoidAsync("UdapAdmin.setFocus", "AnchorId:0");

        // StateHasChanged();
    }
}

