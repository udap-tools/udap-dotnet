#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.AspNetCore.Components;
using Sigil.Common.Services;
using Sigil.Common.ViewModels;

namespace Sigil.UI.Components.Pages;

public partial class Import
{
    [Inject] private CertificateImportService ImportService { get; set; } = null!;

    private string certstorePath = string.Empty;
    private string pfxPassword = "udap-test";
    private bool isScanning;
    private bool isImporting;
    private List<ImportPreviewViewModel> previews = new();
    private List<(string trustDomain, int imported, List<string> errors)> importResults = new();

    protected override void OnInitialized()
    {
        // Default path to the PKI generator certstores
        var basePath = Path.GetFullPath(
            Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..",
                "_tests", "Udap.PKI.Generator", "certstores"));

        if (Directory.Exists(basePath))
        {
            certstorePath = basePath;
        }
    }

    private async Task ScanAsync()
    {
        isScanning = true;
        importResults.Clear();

        try
        {
            await Task.Run(() =>
            {
                previews = ImportService.ScanCertStore(certstorePath, pfxPassword);
            });
        }
        finally
        {
            isScanning = false;
        }
    }

    private async Task ImportSingleAsync(ImportPreviewViewModel preview)
    {
        isImporting = true;

        try
        {
            var (imported, errors) = await ImportService.ImportTrustDomainAsync(
                preview.DirectoryPath, pfxPassword);

            importResults.Add((preview.TrustDomainName, imported, errors));

            // Remove from preview list after import
            previews.Remove(preview);
        }
        finally
        {
            isImporting = false;
        }
    }

    private async Task ImportAllAsync()
    {
        isImporting = true;

        try
        {
            var toImport = previews.Where(p => p.IsValid).ToList();
            foreach (var preview in toImport)
            {
                var (imported, errors) = await ImportService.ImportTrustDomainAsync(
                    preview.DirectoryPath, pfxPassword);

                importResults.Add((preview.TrustDomainName, imported, errors));
                previews.Remove(preview);
                StateHasChanged();
            }
        }
        finally
        {
            isImporting = false;
        }
    }
}
