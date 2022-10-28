using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Forms;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.JSInterop;
using Udap.Idp.Admin.Services;
using Udap.Idp.Admin.Services.State;
using Udap.Idp.Admin.ViewModel;

namespace Udap.Idp.Admin.Pages;

public partial class AnchorEdit
{

    [Inject] ApiService apiService { get; set; }

    [Inject] CommunityState communityState { get; set; }

    [Inject] NavigationManager navManager { get; set; }

    [Inject] private IJSRuntime js { get; set; }

    ErrorBoundary? errorBoundary { get; set; }

    private List<string> editEvents = new();
    private Anchor anchorBeforeEdit;
    private Community Community;
    private Anchor? anchorRowInEdit;
    private bool anchorRowIsInEditMode;
    private ElementReference? newAnchorRowElement;
    private MudBlazor.MudTable<ICollection<Anchor>> table;
    
    protected override void OnInitialized()
    {
        base.OnInitialized();

        if (communityState.Community == null)
        {
            navManager.NavigateTo("/CommunityList");
        }

        Community = communityState?.Community;
    }

    protected override void OnParametersSet()
    {
         errorBoundary?.Recover();
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

    private void BackupItem(object anchor)
    {
        try
        {
            anchorBeforeEdit = new()
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

        anchorRowIsInEditMode = true;

    }

    private void ItemHasBeenCommitted(object anchor)
    {
        var anchorTyped = (Anchor)anchor;
        anchorTyped.BeginDate = anchorTyped.Certificate.NotBefore;
        anchorTyped.EndDate = anchorTyped.Certificate.NotAfter;
        var resultAnchor = apiService.Save(anchorTyped).GetAwaiter().GetResult();
        AddEditionEvent($"RowEditCommit event: Changes to Community {((Anchor)anchor).Name} committed");
        anchorRowInEdit.Id = resultAnchor.Id; //bind up the new id...
        anchorRowIsInEditMode = false;

        StateHasChanged();
    }

    private void ResetItemToOriginalValues(object anchor)
    {
        try
        {
            if (((Anchor)anchor).Id == 0)
            {
                Community.Anchors.Remove((Anchor)anchor);
                AddEditionEvent($"RowEditCancel event: Editing of new Anchor cancelled");                
            }

            ((Anchor)anchor).Id = anchorBeforeEdit.Id;
            ((Anchor)anchor).Name = anchorBeforeEdit.Name;
            ((Anchor)anchor).Enabled = anchorBeforeEdit.Enabled;
            ((Anchor)anchor).Certificate = anchorBeforeEdit.Certificate;
            ((Anchor)anchor).Thumbprint = anchorBeforeEdit.Thumbprint;
            ((Anchor)anchor).Community = anchorBeforeEdit.Community;

            AddEditionEvent($"RowEditCancel event: Editing of Anchor {((ViewModel.Anchor)anchor).Name} cancelled");
        }
        catch
        {
            throw;
        }

        anchorRowIsInEditMode = false;
        StateHasChanged();
    }

    private async Task AddAnchor()
    {
        anchorRowInEdit = new ViewModel.Anchor()
        {
            Community = communityState.Community.Name
        };

        Community.Anchors.Add(anchorRowInEdit);
        await Task.Delay(1);
        StateHasChanged();

        await js.InvokeVoidAsync("UdapAdmin.setFocus", "AnchorId:0");

        StateHasChanged();
    }

    private async Task<bool> DeleteAnchor(Anchor anchor)
    {
        if (await js.InvokeAsync<bool>("confirm", $"Do you want to delete the {anchor.Name} Record?"))
        {
            var result = await apiService.Delete(anchor.Id);

            if (true)
            {
                anchorRowIsInEditMode = false;
                Community.Anchors.Remove(anchor);
                anchorRowInEdit = null;
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
        
        anchorRowInEdit.Certificate = cert;
        
        if(anchorRowInEdit.Name == null)
        {
            anchorRowInEdit.Name = cert.GetNameInfo(X509NameType.SimpleName, false);
            anchorRowInEdit.CommunityId = Community.Id;
            anchorRowInEdit.Community = Community.Name;
            anchorRowInEdit.Thumbprint = cert.Thumbprint;
        }
    }
}

