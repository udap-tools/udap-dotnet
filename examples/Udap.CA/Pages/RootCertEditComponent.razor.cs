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
using MudBlazor;
using Udap.CA.Services;
using Udap.CA.Services.State;
using Udap.CA.ViewModel;

namespace Udap.CA.Pages;

public partial class RootCertEditComponent
{
    [Inject] RootCertificateService RootCertService { get; set; } = null!;

    [Inject] CommunityState CommunityState { get; set; } = null!;

    [Inject] private IJSRuntime Js { get; set; } = null!;

    ErrorBoundary? ErrorBoundary { get; set; }

    private List<string> _editEvents = new();
    private RootCertificate _rootCertificateBeforeEdit = new();
    private ICollection<RootCertificate>? _rootCertificates;
    private RootCertificate? RootCertificateRowInEdit { get; set; }
    private bool _rootCertificateRowIsInEditMode;
    private bool _rootFormActive;
    

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
        catch 
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
            rootCertificateViewModel.BeginDate = rootCertificateViewModel.Certificate?.NotBefore;
            rootCertificateViewModel.EndDate = rootCertificateViewModel.Certificate?.NotAfter;
            var resultRootCertificate = RootCertService.Create(rootCertificateViewModel).GetAwaiter().GetResult();
            AddEditionEvent($"RowEditCommit event: Adding root certificate {rootCertificateViewModel.Name} committed");
            if (RootCertificateRowInEdit != null)
                RootCertificateRowInEdit.Id = resultRootCertificate.Id; //bind up the new id...
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
                _rootCertificates?.Remove((RootCertificate)rootCertificate);
                AddEditionEvent($"RowEditCancel event: Editing of new RootCertificate cancelled");
            }

            ((RootCertificate)rootCertificate).Id = _rootCertificateBeforeEdit.Id;
            ((RootCertificate)rootCertificate).Name = _rootCertificateBeforeEdit.Name;
            ((RootCertificate)rootCertificate).Enabled = _rootCertificateBeforeEdit.Enabled;
            ((RootCertificate)rootCertificate).Certificate = _rootCertificateBeforeEdit.Certificate;
            ((RootCertificate)rootCertificate).Thumbprint = _rootCertificateBeforeEdit.Thumbprint;
            
            AddEditionEvent($"RowEditCancel event: Editing of RootCertificate {((RootCertificate)rootCertificate).Name} cancelled");
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
        RootCertificateRowInEdit = new RootCertificate() {};
        _rootFormActive = true;
        await Task.Delay(1);
        StateHasChanged();
    }

    private async Task<bool> DeleteRootCertificate(RootCertificate rootCertificate)
    {
        if (await Js.InvokeAsync<bool>("confirm", $"Do you want to delete the {rootCertificate.Name} Record?"))
        {
            var result = await RootCertService.Delete(rootCertificate.Id);

            if (result)
            {
                _rootCertificateRowIsInEditMode = false;
                _rootCertificates?.Remove(rootCertificate);
                RootCertificateRowInEdit = null;
                StateHasChanged();
                return true;
            }
        }
        return false;
    }

    MudForm? _rootCertForm;
    
    private async Task Submit()
    {
        await _rootCertForm?.Validate()!;

        if (_rootCertForm.IsValid)
        {
            var generator = new CertificateUtilities();

            if (RootCertificateRowInEdit != null)
            {
                var rootCert = generator.GenerateRootCA(RootCertificateRowInEdit.Name);
                RootCertificateRowInEdit.Certificate = rootCert;
                RootCertificateRowInEdit.Thumbprint = rootCert.Thumbprint;

                if (CommunityState.Community != null)
                {
                    RootCertificateRowInEdit.CommunityId = CommunityState.Community.Id;
                }

                var cert = await RootCertService.Create(RootCertificateRowInEdit);
                Snackbar.Add($"{cert.Name} certificate generated!");

                _rootFormActive = false;
            }
        }
    }
}