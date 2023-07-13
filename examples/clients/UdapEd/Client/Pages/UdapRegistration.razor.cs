#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.Json;
using System.Text.Json.Nodes;
using Hl7.Fhir.Rest;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;
using MudBlazor;
using Udap.Model;
using Udap.Model.Registration;
using UdapEd.Client.Services;
using UdapEd.Client.Shared;
using UdapEd.Shared;
using UdapEd.Shared.Model;
using UdapEd.Shared.Model.Registration;

namespace UdapEd.Client.Pages;

public partial class UdapRegistration
{
    [CascadingParameter]
    public CascadingAppState AppState { get; set; } = null!;

    [CascadingParameter] 
    public MainLayout Layout { get; set; } = null!;

    ErrorBoundary? ErrorBoundary { get; set; }
    [Inject] RegisterService RegisterService { get; set; } = null!;

    [Inject] NavigationManager NavigationManager { get; set; } = null!;

    private string RawSoftwareStatementError { get; set; } = string.Empty;

    private string _beforeEncodingHeader = string.Empty;
    private string SoftwareStatementBeforeEncodingHeader
    {
        get
        {
            if (!string.IsNullOrEmpty(_beforeEncodingHeader))
            {
                return _beforeEncodingHeader;
            }

            if (AppState.SoftwareStatementBeforeEncoding?.Header == null)
            {
                return _beforeEncodingHeader;
            }

            string? jsonHeader = null;

            try
            {
                jsonHeader = JsonNode.Parse(AppState.SoftwareStatementBeforeEncoding.Header)
                    ?.ToJsonString(
                        // new JsonSerializerOptions()
                        // {
                        //     WriteIndented = true
                        // }
                    ).Replace("\\u002B", "+");
            }
            catch
            {
                // ignored
            }

            return jsonHeader ?? string.Empty;
        }

        set => _beforeEncodingHeader = value;
    }

    
    private string _beforeEncodingStatement = string.Empty;
    private string SoftwareStatementBeforeEncodingSoftwareStatement
    {
        get
        {
            if (!string.IsNullOrEmpty(_beforeEncodingStatement))
            {
                return _beforeEncodingStatement;
            }

            if (AppState.SoftwareStatementBeforeEncoding?.SoftwareStatement == null)
            {
                return _beforeEncodingStatement;
            }

            string? jsonStatement = null;

            try{
                jsonStatement = JsonNode.Parse(AppState.SoftwareStatementBeforeEncoding.SoftwareStatement)
                ?.ToJsonString(new JsonSerializerOptions()
                {
                    WriteIndented = true
                });
            }
            catch
            {
                // ignored
            }

            return jsonStatement ?? string.Empty;
        }

        set
        {
            _beforeEncodingStatement = value;
        }
    }

    private const string VALID_STYLE = "pre udap-indent-1";
    private const string INVALID_STYLE = "pre udap-indent-1 jwt-invalid";
    public string ValidRawSoftwareStatementStyle { get; set; } = VALID_STYLE;

    private void PersistSoftwareStatement()
    {
        try
        {
            var statement = JsonSerializer
                .Deserialize<UdapDynamicClientRegistrationDocument>(_beforeEncodingStatement);
            var beforeEncodingScope = statement?.Scope;

            var rawStatement = new RawSoftwareStatementAndHeader
            {
                Header = SoftwareStatementBeforeEncodingHeader,
                SoftwareStatement = _beforeEncodingStatement,
                Scope = beforeEncodingScope
            };

            ValidRawSoftwareStatementStyle = VALID_STYLE;
            AppState.SetProperty(this, nameof(AppState.SoftwareStatementBeforeEncoding), rawStatement);
        }
        catch
        {
            ValidRawSoftwareStatementStyle = INVALID_STYLE;
        }
    }

    private string? _registrationResult;

    private string RegistrationResult
    {
        get
        {
            if (!string.IsNullOrEmpty(_registrationResult))
            {
                return _registrationResult;
            }

            if (AppState.RegistrationDocument == null)
            {
                return _registrationResult ?? string.Empty;
            }

            return JsonSerializer.Serialize(AppState
                .RegistrationDocument, new JsonSerializerOptions { WriteIndented = true });
        }
        set => _registrationResult = value;
    }


    private Oauth2FlowEnum Oauth2Flow
    {
        get => AppState.Oauth2Flow;
        set => AppState.SetProperty(this, nameof(AppState.Oauth2Flow), value);
    }

    private string? _subjectAltName;
    private string _signingAlgorithm = UdapConstants.SupportedAlgorithm.RS256;
    private string? _requestBody;
    private bool _missingScope;
    private bool _cancelRegistration;

    private string RequestBody
    {
        get
        {
            if (!string.IsNullOrEmpty(_requestBody))
            {
                return _requestBody;
            }

            if (AppState.UdapRegistrationRequest == null)
            {
                return _requestBody ?? string.Empty;
            }

            return JsonSerializer.Serialize(
                AppState.UdapRegistrationRequest, 
                new JsonSerializerOptions { WriteIndented = true });
        }
        set => _requestBody = value;
    }

    private async Task BuildRawSoftwareStatement()
    {
        _cancelRegistration = false;
        SetRawMessage("Loading ...");

        await Task.Delay(150);

        if (AppState.Oauth2Flow == Oauth2FlowEnum.client_credentials)
        {
            await BuildRawSoftwareStatementForClientCredentials();
        }
        else if (AppState.Oauth2Flow == Oauth2FlowEnum.authorization_code_b2b)
        {
            await BuildRawSoftwareStatementForAuthorizationCode(
                RegisterService.GetScopesForAuthorizationCodeB2B(AppState.MetadataVerificationModel?.UdapServerMetaData?.ScopesSupported));
        }
        else
        {
            await BuildRawSoftwareStatementForAuthorizationCode(
                RegisterService.GetScopesForAuthorizationCodeConsumer(AppState.MetadataVerificationModel?.UdapServerMetaData?.ScopesSupported));
        }
    }
    private async Task BuildRawCancelSoftwareStatement()
    {
        _cancelRegistration = true;
        SetRawMessage("Loading ...");

        await Task.Delay(150);

        if (AppState.Oauth2Flow == Oauth2FlowEnum.client_credentials)
        {
            await BuildRawSoftwareStatementForClientCredentials(true);
        }
        else
        {
            await BuildRawSoftwareStatementForAuthorizationCode(null, true);
        }
    }

    private async Task BuildRawSoftwareStatementForClientCredentials(bool cancelRegistration = false)
    {
        try
        {
            UdapDcrBuilderForClientCredentialsUnchecked dcrBuilder;

            if (cancelRegistration)
            {
                dcrBuilder = UdapDcrBuilderForClientCredentialsUnchecked.Cancel();
            }
            else
            {
                dcrBuilder = UdapDcrBuilderForClientCredentialsUnchecked.Create();
            }

            dcrBuilder.WithAudience(AppState.MetadataVerificationModel?.UdapServerMetaData?.RegistrationEndpoint)
                .WithExpiration(TimeSpan.FromMinutes(5))
                .WithJwtId()
                .WithClientName(UdapEdConstants.CLIENT_NAME)
                .WithContacts(new HashSet<string>
                {
                    "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
                })
                .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
                .WithScope(RegisterService.GetScopesForClientCredentials(AppState.MetadataVerificationModel?.UdapServerMetaData?.ScopesSupported));

            dcrBuilder.Document.Subject = _subjectAltName;
            dcrBuilder.Document.Issuer = _subjectAltName;
            
            var request = dcrBuilder.Build();

            if (request.Scope == null && request.GrantTypes?.Count > 0)
            {
                _missingScope = true;
            }
            
            var statement = await RegisterService
                .BuildSoftwareStatementForClientCredentials(request, _signingAlgorithm);
            if (statement != null)
            {
                SetRawStatement(statement.Header, statement.SoftwareStatement);
                await AppState.SetPropertyAsync(this, nameof(AppState.SoftwareStatementBeforeEncoding), statement);
            }
        }
        catch (Exception ex)
        {
            SetRawMessage(string.Empty);
            await ResetSoftwareStatement();
            RawSoftwareStatementError = ex.Message;
        }
    }
    
    private async Task BuildRawSoftwareStatementForAuthorizationCode(string? scope, bool cancelRegistration = false)
    {
        try
        {
            UdapDcrBuilderForAuthorizationCodeUnchecked dcrBuilder;

            if (cancelRegistration)
            {
                dcrBuilder = UdapDcrBuilderForAuthorizationCodeUnchecked.Cancel();
            }
            else
            {
                dcrBuilder = UdapDcrBuilderForAuthorizationCodeUnchecked.Create();
            }


            var redirectUrl = Oauth2Flow == Oauth2FlowEnum.authorization_code_b2b ?  "udapBusinessToBusiness" : "udapConsumer";

            dcrBuilder.WithAudience(AppState.MetadataVerificationModel?.UdapServerMetaData?.RegistrationEndpoint)
                .WithExpiration(TimeSpan.FromMinutes(5))
                .WithJwtId()
                .WithClientName(UdapEdConstants.CLIENT_NAME)
                .WithContacts(new HashSet<string>
                {
                    "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
                })
                .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
                .WithResponseTypes(new HashSet<string> { "code" })
                .WithRedirectUrls(new List<string> { $"{NavigationManager.BaseUri}{redirectUrl}" })
                .WithScope(scope);

            dcrBuilder.Document.Subject = _subjectAltName;
            dcrBuilder.Document.Issuer = _subjectAltName;

            var request = dcrBuilder.Build();

            if (request.Scope == null && request.GrantTypes?.Count > 0)
            {
                _missingScope = true;
            }

            var statement = await RegisterService.BuildSoftwareStatementForAuthorizationCode(request, _signingAlgorithm);
            if (statement?.Header != null)
            {
                SetRawStatement(statement.Header, statement.SoftwareStatement);
                statement.Scope = scope;
            }

            AppState.SetProperty(this, nameof(AppState.SoftwareStatementBeforeEncoding), statement);
        }
        catch (Exception ex)
        {
            SetRawMessage(ex.Message);
            ResetSoftwareStatement();
        }
    }


    private void SetRawMessage(string message)
    {
        RawSoftwareStatementError = string.Empty;
        SoftwareStatementBeforeEncodingHeader = message;
        SoftwareStatementBeforeEncodingSoftwareStatement = string.Empty;
    }

    private void SetRawStatement(string header, string softwareStatement = "")
    {
        
        var jsonHeader = JsonNode.Parse(header)
            ?.ToJsonString(new JsonSerializerOptions()
            {
                WriteIndented = true
            }).Replace("\\u002B", "+");
        
        var jsonStatement = JsonNode.Parse(softwareStatement)
            ?.ToJsonString(new JsonSerializerOptions()
            {
                WriteIndented = true,
                
            });
        
        SoftwareStatementBeforeEncodingHeader = jsonHeader ?? string.Empty;
        SoftwareStatementBeforeEncodingSoftwareStatement = jsonStatement ?? string.Empty;
    }

    private async Task ResetSoftwareStatement()
    {
        SetRawMessage(string.Empty);
        await AppState.SetPropertyAsync(this, nameof(AppState.SoftwareStatementBeforeEncoding), null);
        _requestBody = null;
        await AppState.SetPropertyAsync(this, nameof(AppState.UdapRegistrationRequest), null);
        _registrationResult = null;
        await AppState.SetPropertyAsync(this, nameof(AppState.RegistrationDocument), null);
    }

    private async Task BuildRequestBody()
    {
        RequestBody = "Loading ...";
        await Task.Delay(50);

        if (AppState.Oauth2Flow == Oauth2FlowEnum.client_credentials)
        {
            await BuildRequestBodyForClientCredentials();
        }
        else
        {
            await BuildRequestBodyForAuthorizationCode();
        }

        RegistrationResult = string.Empty;
        await AppState.SetPropertyAsync(this, nameof(AppState.RegistrationDocument), null);
    }

    private async Task BuildRequestBodyForClientCredentials()
    {
        var registerRequest = await RegisterService
            .BuildRequestBodyForClientCredentials(
                AppState.SoftwareStatementBeforeEncoding,
                _signingAlgorithm);

        await AppState.SetPropertyAsync(this, nameof(AppState.UdapRegistrationRequest), registerRequest);

        RequestBody = JsonSerializer.Serialize(
            registerRequest,
            new JsonSerializerOptions { WriteIndented = true });
    }

    private async Task BuildRequestBodyForAuthorizationCode()
    {
        var registerRequest = await RegisterService
            .BuildRequestBodyForAuthorizationCode(
                AppState.SoftwareStatementBeforeEncoding,
                _signingAlgorithm);

        await AppState.SetPropertyAsync(this, nameof(AppState.UdapRegistrationRequest), registerRequest);

        RequestBody = JsonSerializer.Serialize(
            registerRequest,
            new JsonSerializerOptions { WriteIndented = true });
    }


    private async Task PerformRegistration()
    {
        RegistrationResult = "Loading ...";
        await Task.Delay(50);

        var registrationRequest = new RegistrationRequest
        {
            RegistrationEndpoint = AppState.MetadataVerificationModel?.UdapServerMetaData?.RegistrationEndpoint,
            UdapRegisterRequest = AppState.UdapRegistrationRequest
        };

        var resultModel = await RegisterService.Register(registrationRequest);

        if (resultModel == null)
        {
            RegistrationResult = "Internal failure. Check the logs.";
            return;
        }

        if (resultModel.HttpStatusCode.IsSuccessful())
        {
            RegistrationResult = $"HTTP/{resultModel.Version} {(int)resultModel.HttpStatusCode} {resultModel.HttpStatusCode}" +
                                 $"{Environment.NewLine}{Environment.NewLine}"; 
            RegistrationResult += JsonSerializer.Serialize(
                resultModel.Result,
                new JsonSerializerOptions { WriteIndented = true });

            if (_cancelRegistration)
            { // cancel registration
                AppState.ClientRegistrations?.CancelRegistration(resultModel.Result);
            }
            else if (AppState.BaseUrl != null)
            {
                AppState.ClientRegistrations?.SetRegistration(resultModel.Result, Oauth2Flow, AppState.BaseUrl);
            }

            await AppState.SetPropertyAsync(this, nameof(AppState.RegistrationDocument), resultModel.Result);
        }
        else
        {
            RegistrationResult = $"HTTP/{resultModel.Version} {(int)resultModel.HttpStatusCode} {resultModel.HttpStatusCode}" +
                                 $"{Environment.NewLine}{Environment.NewLine}";
            RegistrationResult += resultModel.ErrorMessage ?? string .Empty;
            
            await AppState.SetPropertyAsync(this, nameof(AppState.RegistrationDocument), null);
        }
    }
    
    protected override void OnParametersSet()
    {
        ErrorBoundary?.Recover();
        if (AppState.ClientCertificateInfo?.SubjectAltNames != null && AppState.ClientCertificateInfo.SubjectAltNames.Any())
        {
            _subjectAltName = AppState.ClientCertificateInfo.SubjectAltNames.First();
            StateHasChanged();
            Task.Delay(50);
        }
    }

    private void ResetLocalRegisteredClients()
    {
        AppState.SetProperty(this, nameof(AppState.ClientRegistrations), null);
    }
}
