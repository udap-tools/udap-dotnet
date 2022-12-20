using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Forms;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.JSInterop;
using MudBlazor;
using Udap.CA.Services;
using Udap.CA.Services.State;
using Udap.CA.ViewModel;
using static MudBlazor.CategoryTypes;

namespace Udap.CA.Pages;

public partial class RootCertEditComponent
{
    [Inject] RootCertificateService RootCertService { get; set; }

    [Inject] CommunityState CommunityState { get; set; }

    [Inject] private IJSRuntime Js { get; set; }

    ErrorBoundary? ErrorBoundary { get; set; }

    private List<string> _editEvents = new();
    private RootCertificate _rootCertificateBeforeEdit = new RootCertificate();
    private ICollection<RootCertificate> _rootCertificates;
    public RootCertificate _rootCertificateRowInEdit { get; set; }
    private bool _rootCertificateRowIsInEditMode;
    private bool _rootFormActive;
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
        var rootCertificateViewModel = (RootCertificate)rootCertificate;

        if (rootCertificateViewModel.Id > 0)
        {
            UpdateRecord(rootCertificateViewModel);
        }
        else
        {
            rootCertificateViewModel.BeginDate = rootCertificateViewModel.Certificate.NotBefore;
            rootCertificateViewModel.EndDate = rootCertificateViewModel.Certificate.NotAfter;
            var resultRootCertificate = RootCertService.Create(rootCertificateViewModel).GetAwaiter().GetResult();
            AddEditionEvent($"RowEditCommit event: Adding root certificate {rootCertificateViewModel.Name} committed");
            _rootCertificateRowInEdit.Id = resultRootCertificate.Id; //bind up the new id...
        }

        _rootCertificateRowIsInEditMode = false;
        StateHasChanged();
    }

    private void UpdateRecord(RootCertificate rootCertificateView)
    {
        RootCertService.Update(rootCertificateView).GetAwaiter().GetResult();
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
        _rootFormActive = true;
        await Task.Delay(1);
        StateHasChanged();
    }

    private async Task<bool> DeleteRootCertificate(RootCertificate rootCertificate)
    {
        if (await Js.InvokeAsync<bool>("confirm", $"Do you want to delete the {rootCertificate.Name} Record?"))
        {
            var result = await RootCertService.Delete(rootCertificate.Id);

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

    MudForm? rootCertForm;
    
    private async Task Submit()
    {
        await rootCertForm?.Validate()!;

        if (rootCertForm.IsValid)
        {
            var generator = new CertificateUtilities();
            var rootCert = generator.GenerateRootCA(_rootCertificateRowInEdit.Name);
            _rootCertificateRowInEdit.Certificate = rootCert;
            _rootCertificateRowInEdit.Thumbprint = rootCert.Thumbprint;
            _rootCertificateRowInEdit.CommunityId = CommunityState.Community.Id;
            var cert = await RootCertService.Create(_rootCertificateRowInEdit);
            Snackbar.Add("Cert Generated!");

            _rootFormActive = false;
        }
    }
}