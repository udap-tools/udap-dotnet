#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Components;
using Microsoft.FluentUI.AspNetCore.Components;
using Sigil.Common.Data.Entities;
using Sigil.Common.Services;
using Sigil.Common.ViewModels;
using Sigil.UI.Services;

namespace Sigil.UI.Components.Pages;

public partial class Templates
{
    [Inject] private TemplateService TemplateService { get; set; } = null!;
    [Inject] private SanListService SanListService { get; set; } = null!;
    [Inject] private IDialogService DialogService { get; set; } = null!;
    [Inject] private IToastService ToastService { get; set; } = null!;

    [SupplyParameterFromQuery] public string? Action { get; set; }

    private List<CertificateTemplate> templates = new();
    private bool dialogHidden = true;
    private bool isEditing;
    private int? editingId;

    // Form fields
    private string editName = string.Empty;
    private string editDescription = string.Empty;
    private CertificateType editCertType = CertificateType.EndEntityClient;
    private int editValidityDays = 365;
    private string editKeyAlgorithm = "RSA";
    private int editKeySize = 2048;
    private string editEcdsaCurve = "nistP384";
    private string editHashAlgorithm = "SHA256";
    private int editKeyUsageFlags = (int)X509KeyUsageFlags.DigitalSignature;
    private bool editIsKeyUsageCritical = true;
    private string editEkuOids = string.Empty;
    private string editCustomEkuOids = string.Empty;
    private HashSet<string> editSelectedEkuOids = new();
    private bool editIsEkuCritical;
    private bool editIsBasicConstraintsCa;
    private bool editIsBasicConstraintsCritical = true;
    private int? editPathLengthConstraint;
    private string editSubjectTemplate = string.Empty;
    private bool editIncludeCdp;
    private string editCdpUrlTemplate = string.Empty;
    private bool editIncludeAia;
    private string editAiaUrlTemplate = string.Empty;
    private bool editSanUri;
    private bool editSanDns;
    private bool editSanEmail;
    private bool editSanIp;
    private List<SanList> availableSanLists = new();
    private HashSet<int> editSelectedSanListIds = new();

    // Options for selects
    private static readonly CertificateType[] certTypes = Enum.GetValues<CertificateType>();
    private static readonly string[] keyAlgorithms = ["RSA", "ECDSA"];
    private static readonly int[] rsaKeySizes = [2048, 3072, 4096];
    private static readonly string[] ecdsaCurves = ["nistP256", "nistP384", "nistP521"];
    private static readonly string[] hashAlgorithms = ["SHA256", "SHA384", "SHA512"];

    private static readonly (X509KeyUsageFlags Flag, string Label)[] keyUsageOptions =
    [
        (X509KeyUsageFlags.DigitalSignature, "Digital Signature"),
        (X509KeyUsageFlags.KeyCertSign, "Certificate Signing"),
        (X509KeyUsageFlags.CrlSign, "CRL Signing"),
        (X509KeyUsageFlags.KeyEncipherment, "Key Encipherment"),
        (X509KeyUsageFlags.DataEncipherment, "Data Encipherment"),
        (X509KeyUsageFlags.KeyAgreement, "Key Agreement"),
        (X509KeyUsageFlags.NonRepudiation, "Non-Repudiation"),
    ];

    private static readonly (string Oid, string Name)[] ekuOptions =
    [
        ("1.3.6.1.5.5.7.3.1", "TLS Server Authentication"),
        ("1.3.6.1.5.5.7.3.2", "TLS Client Authentication"),
        ("1.3.6.1.5.5.7.3.3", "Code Signing"),
        ("1.3.6.1.5.5.7.3.4", "Email Protection (S/MIME)"),
        ("1.3.6.1.5.5.7.3.8", "Time Stamping"),
        ("1.3.6.1.5.5.7.3.9", "OCSP Signing"),
        ("1.3.6.1.4.1.311.10.3.12", "Document Signing"),
        ("1.3.6.1.5.5.7.3.17", "IPSEC IKE Intermediate"),
        ("2.16.840.1.113730.4.1", "Netscape SGC"),
        ("1.3.6.1.4.1.311.10.3.3", "Microsoft SGC"),
    ];

    protected override async Task OnInitializedAsync()
    {
        await LoadTemplatesAsync();
        if (Action == "new")
            await ShowAddDialog();
    }

    private async Task LoadTemplatesAsync()
    {
        templates = await TemplateService.GetAllWithSanListsAsync();
    }

    private async Task ShowAddDialog()
    {
        isEditing = false;
        editingId = null;
        ResetForm();
        availableSanLists = await SanListService.GetAllAsync();
        dialogHidden = false;
    }

    private async Task ShowEditDialog(CertificateTemplate t)
    {
        isEditing = true;
        editingId = t.Id;
        PopulateForm(t);
        availableSanLists = await SanListService.GetAllAsync();
        dialogHidden = false;
    }

    private void ResetForm()
    {
        editName = string.Empty;
        editDescription = string.Empty;
        editCertType = CertificateType.EndEntityClient;
        editValidityDays = 365;
        editKeyAlgorithm = "RSA";
        editKeySize = 2048;
        editEcdsaCurve = "nistP384";
        editHashAlgorithm = "SHA256";
        editKeyUsageFlags = (int)X509KeyUsageFlags.DigitalSignature;
        editIsKeyUsageCritical = true;
        editEkuOids = string.Empty;
        editCustomEkuOids = string.Empty;
        editSelectedEkuOids.Clear();
        editIsEkuCritical = false;
        editIsBasicConstraintsCa = false;
        editIsBasicConstraintsCritical = true;
        editPathLengthConstraint = null;
        editSubjectTemplate = string.Empty;
        editIncludeCdp = false;
        editCdpUrlTemplate = string.Empty;
        editIncludeAia = false;
        editAiaUrlTemplate = string.Empty;
        editSanUri = false;
        editSanDns = false;
        editSanEmail = false;
        editSanIp = false;
        editSelectedSanListIds.Clear();
    }

    private void PopulateForm(CertificateTemplate t)
    {
        editName = t.Name;
        editDescription = t.Description ?? string.Empty;
        editCertType = t.CertificateType;
        editValidityDays = t.ValidityDays;
        editKeyAlgorithm = t.KeyAlgorithm;
        editKeySize = t.KeySize;
        editEcdsaCurve = t.EcdsaCurve ?? "nistP384";
        editHashAlgorithm = t.HashAlgorithm;
        editKeyUsageFlags = t.KeyUsageFlags;
        editIsKeyUsageCritical = t.IsKeyUsageCritical;
        editEkuOids = t.ExtendedKeyUsageOids ?? string.Empty;
        // Split stored OIDs into known (checkboxes) and custom (text field)
        editSelectedEkuOids.Clear();
        editCustomEkuOids = string.Empty;
        if (!string.IsNullOrWhiteSpace(editEkuOids))
        {
            var knownOids = ekuOptions.Select(e => e.Oid).ToHashSet();
            var customParts = new List<string>();
            foreach (var oid in editEkuOids.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (knownOids.Contains(oid))
                    editSelectedEkuOids.Add(oid);
                else
                    customParts.Add(oid);
            }
            editCustomEkuOids = string.Join(";", customParts);
        }
        editIsEkuCritical = t.IsExtendedKeyUsageCritical;
        editIsBasicConstraintsCa = t.IsBasicConstraintsCa;
        editIsBasicConstraintsCritical = t.IsBasicConstraintsCritical;
        editPathLengthConstraint = t.PathLengthConstraint;
        editSubjectTemplate = t.SubjectTemplate ?? string.Empty;
        editIncludeCdp = t.IncludeCdp;
        editCdpUrlTemplate = t.CdpUrlTemplate ?? string.Empty;
        editIncludeAia = t.IncludeAia;
        editAiaUrlTemplate = t.AiaUrlTemplate ?? string.Empty;

        var sanTypes = (t.SubjectAltNameTypes ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries);
        editSanUri = sanTypes.Contains("URI", StringComparer.OrdinalIgnoreCase);
        editSanDns = sanTypes.Contains("DNS", StringComparer.OrdinalIgnoreCase);
        editSanEmail = sanTypes.Contains("Email", StringComparer.OrdinalIgnoreCase);
        editSanIp = sanTypes.Contains("IP", StringComparer.OrdinalIgnoreCase);

        editSelectedSanListIds = new HashSet<int>(t.SanLists.Select(s => s.Id));
    }

    private CertificateTemplate BuildEntityFromForm(CertificateTemplate? existing = null)
    {
        var entity = existing ?? new CertificateTemplate();
        entity.Name = editName.Trim();
        entity.Description = string.IsNullOrWhiteSpace(editDescription) ? null : editDescription.Trim();
        entity.CertificateType = editCertType;
        entity.ValidityDays = editValidityDays;
        entity.KeyAlgorithm = editKeyAlgorithm;
        entity.KeySize = editKeyAlgorithm == "RSA" ? editKeySize : 0;
        entity.EcdsaCurve = editKeyAlgorithm == "ECDSA" ? editEcdsaCurve : null;
        entity.HashAlgorithm = editHashAlgorithm;
        entity.KeyUsageFlags = editKeyUsageFlags;
        entity.IsKeyUsageCritical = editIsKeyUsageCritical;
        entity.ExtendedKeyUsageOids = string.IsNullOrWhiteSpace(editEkuOids) ? null : editEkuOids.Trim();
        entity.IsExtendedKeyUsageCritical = editIsEkuCritical;
        entity.IsBasicConstraintsCa = editIsBasicConstraintsCa;
        entity.IsBasicConstraintsCritical = editIsBasicConstraintsCritical;
        entity.PathLengthConstraint = editIsBasicConstraintsCa ? editPathLengthConstraint : null;
        entity.SubjectTemplate = string.IsNullOrWhiteSpace(editSubjectTemplate) ? null : editSubjectTemplate.Trim();
        entity.IncludeCdp = editIncludeCdp;
        entity.CdpUrlTemplate = editIncludeCdp && !string.IsNullOrWhiteSpace(editCdpUrlTemplate) ? editCdpUrlTemplate.Trim() : null;
        entity.IncludeAia = editIncludeAia;
        entity.AiaUrlTemplate = editIncludeAia && !string.IsNullOrWhiteSpace(editAiaUrlTemplate) ? editAiaUrlTemplate.Trim() : null;

        var sanParts = new List<string>();
        if (editSanUri) sanParts.Add("URI");
        if (editSanDns) sanParts.Add("DNS");
        if (editSanEmail) sanParts.Add("Email");
        if (editSanIp) sanParts.Add("IP");
        entity.SubjectAltNameTypes = sanParts.Count > 0 ? string.Join(";", sanParts) : null;

        return entity;
    }

    private async Task SaveTemplateAsync()
    {
        if (string.IsNullOrWhiteSpace(editName)) return;

        CertificateTemplate entity;

        if (isEditing && editingId.HasValue)
        {
            entity = BuildEntityFromForm();
            entity.Id = editingId.Value;
            await TemplateService.SaveAsync(entity);
            await TemplateService.UpdateSanListsAsync(entity.Id, editSelectedSanListIds);
            ToastService.ShowCopyableSuccess($"Template '{entity.Name}' updated.");
        }
        else
        {
            entity = BuildEntityFromForm();
            entity = await TemplateService.SaveAsync(entity);
            await TemplateService.UpdateSanListsAsync(entity.Id, editSelectedSanListIds);
            ToastService.ShowCopyableSuccess($"Template '{entity.Name}' created.");
        }

        dialogHidden = true;
        await LoadTemplatesAsync();
    }

    private void CloneTemplateAsync(CertificateTemplate source)
    {
        var clone = new CertificateTemplate
        {
            Name = $"Copy of {source.Name}",
            Description = source.Description,
            CertificateType = source.CertificateType,
            KeyAlgorithm = source.KeyAlgorithm,
            KeySize = source.KeySize,
            ValidityDays = source.ValidityDays,
            KeyUsageFlags = source.KeyUsageFlags,
            IsKeyUsageCritical = source.IsKeyUsageCritical,
            ExtendedKeyUsageOids = source.ExtendedKeyUsageOids,
            IsExtendedKeyUsageCritical = source.IsExtendedKeyUsageCritical,
            IsBasicConstraintsCa = source.IsBasicConstraintsCa,
            IsBasicConstraintsCritical = source.IsBasicConstraintsCritical,
            PathLengthConstraint = source.PathLengthConstraint,
            EcdsaCurve = source.EcdsaCurve,
            HashAlgorithm = source.HashAlgorithm,
            SubjectTemplate = source.SubjectTemplate,
            IncludeCdp = source.IncludeCdp,
            CdpUrlTemplate = source.CdpUrlTemplate,
            IncludeAia = source.IncludeAia,
            AiaUrlTemplate = source.AiaUrlTemplate,
            SubjectAltNameTypes = source.SubjectAltNameTypes,
            IsPreset = false,
        };

        isEditing = false;
        editingId = null;
        PopulateForm(clone);
        dialogHidden = false;
    }

    // Impact confirmation dialog state
    private bool impactDialogHidden = true;
    private string impactDialogTitle = "Confirm";
    private string impactDialogMessage = string.Empty;
    private string impactDialogConfirmLabel = "Confirm";
    private List<ImpactItem>? impactDialogImpacts;
    private Func<Task>? impactDialogOnConfirm;
    private bool impactDialogBusy;

    private async Task DeleteTemplateAsync(CertificateTemplate template)
    {
        if (template.IsPreset) return;

        var impacts = await TemplateService.GetDeletionImpactAsync(template.Id);
        impactDialogTitle = $"Delete template '{template.Name}'?";
        impactDialogMessage = "Issued certificates that reference this template will not be deleted, but the reference will be cleared.";
        impactDialogConfirmLabel = "Delete Template";
        impactDialogImpacts = impacts;
        impactDialogOnConfirm = () => ConfirmDeleteTemplateAsync(template);
        impactDialogBusy = false;
        impactDialogHidden = false;
    }

    private async Task ConfirmDeleteTemplateAsync(CertificateTemplate template)
    {
        await TemplateService.DeleteAsync(template.Id);
        ToastService.ShowCopyableSuccess($"Template '{template.Name}' deleted.");
        await LoadTemplatesAsync();
    }

    private async Task OnImpactDialogConfirmAsync()
    {
        if (impactDialogOnConfirm == null) return;
        impactDialogBusy = true;
        StateHasChanged();
        try
        {
            await impactDialogOnConfirm();
        }
        finally
        {
            impactDialogHidden = true;
            impactDialogBusy = false;
        }
    }

    private void OnImpactDialogCancel() => impactDialogHidden = true;

    private void ToggleKeyUsageFlag(X509KeyUsageFlags flag, bool enabled)
    {
        if (enabled)
            editKeyUsageFlags |= (int)flag;
        else
            editKeyUsageFlags &= ~(int)flag;
    }

    private bool IsEkuSelected(string oid) => editSelectedEkuOids.Contains(oid);

    private void ToggleEku(string oid, bool enabled)
    {
        if (enabled)
            editSelectedEkuOids.Add(oid);
        else
            editSelectedEkuOids.Remove(oid);
        SyncEkuOids();
    }

    private void SyncEkuOids()
    {
        var all = new List<string>(editSelectedEkuOids);

        // Add any custom OIDs
        if (!string.IsNullOrWhiteSpace(editCustomEkuOids))
        {
            foreach (var oid in editCustomEkuOids.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (!all.Contains(oid))
                    all.Add(oid);
            }
        }

        editEkuOids = all.Count > 0 ? string.Join(";", all) : string.Empty;
    }

    private void OnKeyAlgorithmChanged(string algorithm)
    {
        editKeyAlgorithm = algorithm;
        if (algorithm == "ECDSA")
            OnEcdsaCurveChanged(editEcdsaCurve);
    }

    private void OnEcdsaCurveChanged(string curve)
    {
        editEcdsaCurve = curve;
        editHashAlgorithm = curve switch
        {
            "nistP256" => "SHA256",
            "nistP384" => "SHA384",
            "nistP521" => "SHA512",
            _ => "SHA384"
        };
    }

    private string GetEcdsaSigningAlgorithmLabel() => editEcdsaCurve switch
    {
        "nistP256" => "ES256 (ECDSA P-256 + SHA-256)",
        "nistP384" => "ES384 (ECDSA P-384 + SHA-384)",
        "nistP521" => "ES512 (ECDSA P-521 + SHA-512)",
        _ => $"ECDSA {editEcdsaCurve} + {editHashAlgorithm}"
    };

    private static string GetCertTypeLabel(CertificateType ct) => ct switch
    {
        CertificateType.RootCa => "Root CA",
        CertificateType.IntermediateCa => "Intermediate CA",
        CertificateType.EndEntityClient => "Client",
        CertificateType.EndEntityServer => "Server",
        _ => ct.ToString()
    };

    private static (string bg, string label) GetTypeBadge(CertificateType ct) => ct switch
    {
        CertificateType.RootCa => ("#8b5cf6", "Root CA"),
        CertificateType.IntermediateCa => ("#3b82f6", "Intermediate CA"),
        CertificateType.EndEntityClient => ("#10b981", "Client"),
        CertificateType.EndEntityServer => ("#f59e0b", "Server"),
        _ => ("#666", ct.ToString())
    };

    private static int CountSanItems(string items) =>
        string.IsNullOrWhiteSpace(items) ? 0 :
        items.Split(';', StringSplitOptions.RemoveEmptyEntries).Length;
}
