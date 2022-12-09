using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Forms;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.JSInterop;
using Udap.Idp.Admin.Services;
using Udap.Idp.Admin.Services.State;
using Udap.Idp.Admin.ViewModel;

namespace Udap.Idp.Admin.Pages;

public partial class RootCertEditComponent
{
    [Inject] ApiService ApiService { get; set; }

    [Inject] CommunityState CommunityState { get; set; }

    [Inject] private IJSRuntime Js { get; set; }

    ErrorBoundary? ErrorBoundary { get; set; }

    private List<string> _editEvents = new();
    private RootCertificate _rootCertificateBeforeEdit;
    private ICollection<RootCertificate> _rootCertificates;
    private RootCertificate? _rootCertificateRowInEdit;
    private bool _rootCertificateRowIsInEditMode;
    private ElementReference? _newRootCertificateRowElement;
    private MudBlazor.MudTable<ICollection<RootCertificate>> table;

    protected override void OnInitialized()
    {
        base.OnInitialized();

        _rootCertificates = CommunityState.RootCertificates;
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

    private void BackupItem(object rootCertificate)
    {
        try
        {
            _rootCertificateBeforeEdit = new()
            {
                Id = ((RootCertificate)rootCertificate).Id,
                Name = ((RootCertificate)rootCertificate).Name,
                Enabled = ((RootCertificate)rootCertificate).Enabled,
                Certificate = ((RootCertificate)rootCertificate).Certificate,
                Thumbprint = ((RootCertificate)rootCertificate).Thumbprint
            };


            AddEditionEvent($"RowEditPreview event: made a backup of Community {((RootCertificate)rootCertificate).Name}");
        }
        catch (Exception e)
        {
            throw;
        }

        _rootCertificateRowIsInEditMode = true;
    }

    private void ItemHasBeenCommitted(object rootCertificate)
    {
        var rootCertificateView = (RootCertificate)rootCertificate;

        if (rootCertificateView.Id > 0)
        {
            UpdateRecord(rootCertificateView);
        }
        else
        {
            rootCertificateView.BeginDate = rootCertificateView.Certificate.NotBefore;
            rootCertificateView.EndDate = rootCertificateView.Certificate.NotAfter;
            var resultRootCertificate = ApiService.Save(rootCertificateView).GetAwaiter().GetResult();
            AddEditionEvent($"RowEditCommit event: Adding root certificate {rootCertificateView.Name} committed");
            _rootCertificateRowInEdit.Id = resultRootCertificate.Id; //bind up the new id...
        }

        _rootCertificateRowIsInEditMode = false;
        StateHasChanged();
    }

    private void UpdateRecord(RootCertificate rootCertificateView)
    {
        ApiService.Update(rootCertificateView).GetAwaiter().GetResult();
        AddEditionEvent($"RowEditCommit event: Updating root certificate {rootCertificateView.Name} committed");
    }


    private void ResetItemToOriginalValues(object rootCertificate)
    {
        try
        {
            if (((RootCertificate)rootCertificate).Id == 0)
            {
                _rootCertificates.Remove((RootCertificate)rootCertificate);
                AddEditionEvent($"RowEditCancel event: Editing of new RootCertificate cancelled");
            }

            ((RootCertificate)rootCertificate).Id = _rootCertificateBeforeEdit.Id;
            ((RootCertificate)rootCertificate).Name = _rootCertificateBeforeEdit.Name;
            ((RootCertificate)rootCertificate).Enabled = _rootCertificateBeforeEdit.Enabled;
            ((RootCertificate)rootCertificate).Certificate = _rootCertificateBeforeEdit.Certificate;
            ((RootCertificate)rootCertificate).Thumbprint = _rootCertificateBeforeEdit.Thumbprint;
            
            AddEditionEvent($"RowEditCancel event: Editing of RootCertificate {((ViewModel.RootCertificate)rootCertificate).Name} cancelled");
        }
        catch
        {
            throw;
        }

        _rootCertificateRowIsInEditMode = false;
        StateHasChanged();
    }

    private async Task AddRootCertificate()
    {
        _rootCertificateRowInEdit = new ViewModel.RootCertificate() {};

        _rootCertificates.Add(_rootCertificateRowInEdit);
        await Task.Delay(1);
        StateHasChanged();

        await Js.InvokeVoidAsync("UdapAdmin.setFocus", "RootCertificateId:0");

        StateHasChanged();
    }

    private async Task<bool> DeleteRootCertificate(RootCertificate rootCertificate)
    {
        if (await Js.InvokeAsync<bool>("confirm", $"Do you want to delete the {rootCertificate.Name} Record?"))
        {
            var result = await ApiService.DeleteRootCertificate(rootCertificate.Id);

            if (true)
            {
                _rootCertificateRowIsInEditMode = false;
                _rootCertificates.Remove(rootCertificate);
                _rootCertificateRowInEdit = null;
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

        _rootCertificateRowInEdit.Certificate = cert;

        if (_rootCertificateRowInEdit.Name == null)
        {
            _rootCertificateRowInEdit.Name = cert.GetNameInfo(X509NameType.SimpleName, false);
            _rootCertificateRowInEdit.Thumbprint = cert.Thumbprint;
        }
    }
}

