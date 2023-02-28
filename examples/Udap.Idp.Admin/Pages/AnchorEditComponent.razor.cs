using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Forms;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.JSInterop;
using Udap.Idp.Admin.Services;
using Udap.Idp.Admin.Services.State;
using Udap.Idp.Admin.ViewModel;

namespace Udap.Idp.Admin.Pages;

public partial class AnchorEditComponent
{
    [Inject] ApiService ApiService { get; set; }

    [Inject] CommunityState CommunityState { get; set; }

    [Inject] private IJSRuntime Js { get; set; } = null!;

    ErrorBoundary? ErrorBoundary { get; set; }

    private List<string> _editEvents = new();
    private Anchor _anchorBeforeEdit;
    private Community? _community;
    private Anchor? _anchorRowInEdit;
    private bool _anchorRowIsInEditMode;
    private ElementReference? newAnchorRowElement;
    private MudBlazor.MudTable<ICollection<Anchor>> _table;

    protected override void OnInitialized()
    {
        base.OnInitialized();
        
        _community = CommunityState.Community;
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

    private void BackupItem(object anchor)
    {
        try
        {
            _anchorBeforeEdit = new()
            {
                Id = ((Anchor)anchor).Id,
                Name = ((Anchor)anchor).Name,
                Enabled = ((Anchor)anchor).Enabled,
                Certificate = ((Anchor)anchor).Certificate,
                Thumbprint = ((Anchor)anchor).Thumbprint,
                Community = ((Anchor)anchor).Community
            };


            AddEditionEvent($"RowEditPreview event: made a backup of Community {((Anchor)anchor).Name}");
        }
        catch (Exception e)
        {
            throw;
        }

        _anchorRowIsInEditMode = true;

    }

    private void ItemHasBeenCommitted(object anchor)
    {
        var anchorView = (Anchor)anchor;

        if (anchorView.Id > 0)
        {
            UpdateRecord(anchorView);
        }
        else
        {
            anchorView.BeginDate = anchorView.Certificate.NotBefore;
            anchorView.EndDate = anchorView.Certificate.NotAfter;
            var resultAnchor = ApiService.Save(anchorView).GetAwaiter().GetResult();
            AddEditionEvent($"RowEditCommit event: Adding Anchor {((Anchor)anchor).Name} committed");
            _anchorRowInEdit.Id = resultAnchor.Id; //bind up the new id...
        }
        
        _anchorRowIsInEditMode = false;
        StateHasChanged();
    }

    private void UpdateRecord(Anchor anchorView)
    {
        ApiService.Update(anchorView).GetAwaiter().GetResult();
        AddEditionEvent($"RowEditCommit event: Updating anchor {anchorView.Name} committed");
    }

    private void ResetItemToOriginalValues(object anchor)
    {
        try
        {
            if (((Anchor)anchor).Id == 0)
            {
                _community.Anchors.Remove((Anchor)anchor);
                AddEditionEvent($"RowEditCancel event: Editing of new Anchor cancelled");
            }

            ((Anchor)anchor).Id = _anchorBeforeEdit.Id;
            ((Anchor)anchor).Name = _anchorBeforeEdit.Name;
            ((Anchor)anchor).Enabled = _anchorBeforeEdit.Enabled;
            ((Anchor)anchor).Certificate = _anchorBeforeEdit.Certificate;
            ((Anchor)anchor).Thumbprint = _anchorBeforeEdit.Thumbprint;
            ((Anchor)anchor).Community = _anchorBeforeEdit.Community;

            AddEditionEvent($"RowEditCancel event: Editing of Anchor {((ViewModel.Anchor)anchor).Name} cancelled");
        }
        catch
        {
            throw;
        }

        _anchorRowIsInEditMode = false;
        StateHasChanged();
    }

    private async Task AddAnchor()
    {
        _anchorRowInEdit = new ViewModel.Anchor()
        {
            Community = CommunityState.Community.Name
        };

        _community.Anchors.Add(_anchorRowInEdit);
        await Task.Delay(1);
        StateHasChanged();

        await Js.InvokeVoidAsync("UdapAdmin.setFocus", "AnchorId:0");

        StateHasChanged();
    }

    private async Task<bool> DeleteAnchor(Anchor anchor)
    {
        if (await Js.InvokeAsync<bool>("confirm", $"Do you want to delete the {anchor.Name} Record?"))
        {
            var result = await ApiService.DeleteAnchor(anchor.Id);

            if (true)
            {
                _anchorRowIsInEditMode = false;
                _community.Anchors.Remove(anchor);
                _anchorRowInEdit = null;
                StateHasChanged();
                return true;
            }
        }
        return false;
    }

    private async Task UploadFilesAsync(InputFileChangeEventArgs e)
    {
        long maxFileSize = 1024 * 10;

        var uploadStream = await new StreamContent(e.File.OpenReadStream(maxFileSize)).ReadAsStreamAsync();
        var ms = new MemoryStream();
        await uploadStream.CopyToAsync(ms);
        var certBytes = ms.ToArray();

        var cert = new X509Certificate2(certBytes);

        _anchorRowInEdit.Certificate = cert;

        if (_anchorRowInEdit.Name == null)
        {
            _anchorRowInEdit.Name = cert.GetNameInfo(X509NameType.SimpleName, false);
            _anchorRowInEdit.CommunityId = _community.Id;
            _anchorRowInEdit.Community = _community.Name;
            _anchorRowInEdit.Thumbprint = cert.Thumbprint;
        }
    }
}

