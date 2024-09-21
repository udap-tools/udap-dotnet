#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Forms;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.JSInterop;
using MudBlazor;
using Udap.Auth.Server.Admin.Services;
using Udap.Auth.Server.Admin.Services.State;
using Udap.Auth.Server.Admin.ViewModel;

namespace Udap.Auth.Server.Admin.Pages;

public partial class IntermediateCertEditComponent
{
    [Inject] ApiService ApiService { get; set; } = null!;

    [Inject] CommunityState CommunityState { get; set; } = null!;

    [Inject] private IJSRuntime Js { get; set; } = null!;
    [Parameter] public long AnchorId { get; set; }
    ErrorBoundary? ErrorBoundary { get; set; }

    private List<string> _editEvents = new();
    private IntermediateCertificate? _intermediateCertificateBeforeEdit;
    private ICollection<IntermediateCertificate>? _intermediateCertificates;
    private IntermediateCertificate? _intermediateCertificateRowInEdit;
    private bool _intermediateCertificateRowIsInEditMode;
    private ElementReference? _newIntermediateCertificateRowElement;
    private MudTable<ICollection<IntermediateCertificate>>? table;

    protected override void OnInitialized()
    {
        base.OnInitialized();

        _intermediateCertificates = CommunityState.Community?.Anchors
            .SelectMany(a => a.Intermediates).ToList();
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

    private void BackupItem(object intermediateCertificate)
    {
        try
        {
            _intermediateCertificateBeforeEdit = new()
            {
                Id = ((IntermediateCertificate)intermediateCertificate).Id,
                Name = ((IntermediateCertificate)intermediateCertificate).Name,
                Enabled = ((IntermediateCertificate)intermediateCertificate).Enabled,
                Certificate = ((IntermediateCertificate)intermediateCertificate).Certificate,
                Thumbprint = ((IntermediateCertificate)intermediateCertificate).Thumbprint
            };


            AddEditionEvent($"RowEditPreview event: made a backup of Community {((IntermediateCertificate)intermediateCertificate).Name}");
        }
        catch (Exception e)
        {
            throw;
        }

        _intermediateCertificateRowIsInEditMode = true;
    }

    private void ItemHasBeenCommitted(object intermediateCertificate)
    {
        var intermediateCertificateView = (IntermediateCertificate)intermediateCertificate;

        if (intermediateCertificateView.Id > 0)
        {
            UpdateRecord(intermediateCertificateView);
        }
        else
        {
            intermediateCertificateView.BeginDate = intermediateCertificateView.Certificate?.NotBefore;
            intermediateCertificateView.EndDate = intermediateCertificateView.Certificate?.NotAfter;
            // intermediateCertificateView.Anchor = _
            var resultIntermediateCertificate = ApiService.Save(intermediateCertificateView).GetAwaiter().GetResult();
            AddEditionEvent($"RowEditCommit event: Adding intermediate certificate {intermediateCertificateView.Name} committed");
            _intermediateCertificateRowInEdit.Id = resultIntermediateCertificate.Id; //bind up the new id...
        }

        _intermediateCertificateRowIsInEditMode = false;
        StateHasChanged();
    }

    private void UpdateRecord(IntermediateCertificate intermediateCertificateView)
    {
        ApiService.Update(intermediateCertificateView).GetAwaiter().GetResult();
        AddEditionEvent($"RowEditCommit event: Updating intermediate certificate {intermediateCertificateView.Name} committed");
    }


    private void ResetItemToOriginalValues(object intermediateCertificate)
    {
        try
        {
            if (((IntermediateCertificate)intermediateCertificate).Id == 0)
            {
                _intermediateCertificates.Remove((IntermediateCertificate)intermediateCertificate);
                AddEditionEvent($"RowEditCancel event: Editing of new Intermediates cancelled");
            }

            if (_intermediateCertificateBeforeEdit != null)
            {
                ((IntermediateCertificate)intermediateCertificate).Id = _intermediateCertificateBeforeEdit.Id;
                ((IntermediateCertificate)intermediateCertificate).Name = _intermediateCertificateBeforeEdit.Name;
                ((IntermediateCertificate)intermediateCertificate).Enabled = _intermediateCertificateBeforeEdit.Enabled;
                ((IntermediateCertificate)intermediateCertificate).Certificate =
                    _intermediateCertificateBeforeEdit.Certificate;
                ((IntermediateCertificate)intermediateCertificate).Thumbprint =
                    _intermediateCertificateBeforeEdit.Thumbprint;
            }

            AddEditionEvent($"RowEditCancel event: Editing of Intermediates {((ViewModel.IntermediateCertificate)intermediateCertificate).Name} cancelled");
        }
        catch
        {
            throw;
        }

        _intermediateCertificateRowIsInEditMode = false;
        StateHasChanged();
    }

    private async Task AddIntermediateCertificate()
    {
        _intermediateCertificateRowInEdit = new ViewModel.IntermediateCertificate() {};

        _intermediateCertificates?.Add(_intermediateCertificateRowInEdit);
        await Task.Delay(1);
        StateHasChanged();

        await Js.InvokeVoidAsync("UdapAdmin.setFocus", "IntermediateCertificateId:0");

        StateHasChanged();
    }

    private async Task<bool> DeleteIntermediateCertificate(IntermediateCertificate intermediateCertificate)
    {
        if (await Js.InvokeAsync<bool>("confirm", $"Do you want to delete the {intermediateCertificate.Name} Record?"))
        {
            await ApiService.DeleteIntermediateCertificate(intermediateCertificate.Id);

            if (true)
            {
                _intermediateCertificateRowIsInEditMode = false;
                _intermediateCertificates?.Remove(intermediateCertificate);
                _intermediateCertificateRowInEdit = null;
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

        if (_intermediateCertificateRowInEdit != null)
        {
            _intermediateCertificateRowInEdit.Certificate = cert;

            if (_intermediateCertificateRowInEdit.Name == null)
            {
                _intermediateCertificateRowInEdit.Name = cert.GetNameInfo(X509NameType.SimpleName, false);
                _intermediateCertificateRowInEdit.Thumbprint = cert.Thumbprint;
            }
        }
    }
}

