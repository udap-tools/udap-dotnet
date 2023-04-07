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
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;
using MudBlazor;
using Udap.Model;
using Udap.Model.Registration;
using UdapEd.Client.Services;
using UdapEd.Client.Shared;
using UdapEd.Shared;
using UdapEd.Shared.Model;

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

    private const string validStyle = "pre udap-indent-1";
    private const string invalidStyle = "pre udap-indent-1 jwt-invalid";
    public string ValidRawSoftwareStatementStyle { get; set; } = validStyle;

    private void PersistSoftwareStatement()
    {
        try
        {
            var statement = JsonSerializer
                .Deserialize<UdapDynamicClientRegistrationDocument>(SoftwareStatementBeforeEncodingSoftwareStatement);
            var beforeEncodingScope = statement?.Scope;

            var rawStatement = new RawSoftwareStatementAndHeader
            {
                Header = SoftwareStatementBeforeEncodingHeader,
                SoftwareStatement = SoftwareStatementBeforeEncodingSoftwareStatement,
                Scope = beforeEncodingScope
            };

            ValidRawSoftwareStatementStyle = validStyle;
            AppState.SetProperty(this, nameof(AppState.SoftwareStatementBeforeEncoding), rawStatement);
        }
        catch
        {
            ValidRawSoftwareStatementStyle = invalidStyle;
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

    private string? _requestBody;

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
        SetRawMessage("Loading ...");

        await Task.Delay(150);

        if (AppState.Oauth2Flow == Oauth2FlowEnum.client_credentials)
        {
            await BuildRawSoftwareStatementForClientCredentials();
        }
        else
        {
            await BuildRawSoftwareStatementForAuthorizationCode();
        }
    }

    private async Task BuildRawSoftwareStatementForClientCredentials()
    {
        try
        {
            var request = UdapDcrBuilderForClientCredentials.Create()
                .WithAudience(AppState.UdapMetadata?.RegistrationEndpoint)
                .WithExpiration(TimeSpan.FromMinutes(5))
                .WithJwtId()
                .WithClientName(UdapEdConstants.CLIENT_NAME)
                .WithContacts(new HashSet<string>
                {
                    "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
                })
                .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
                .WithScope(RegisterService.GetScopesForClientCredentials(AppState.UdapMetadata?.ScopesSupported))
                .Build();


            var statement = await RegisterService.BuildSoftwareStatementForClientCredentials(request);
            if (statement != null)
            {
                SetRawStatement(statement.Header, statement.SoftwareStatement);
                await AppState.SetPropertyAsync(this, nameof(AppState.SoftwareStatementBeforeEncoding), statement);
            }
        }
        catch (Exception ex)
        {
            SetRawMessage(ex.Message);
            ResetSoftwareStatement();
        }
    }
    
    private async Task BuildRawSoftwareStatementForAuthorizationCode()
    {
        try
        {
            var scope = RegisterService.GetScopesForAuthorizationCode(AppState.UdapMetadata?.ScopesSupported);

            var request = UdapDcrBuilderForAuthorizationCode.Create()
                .WithAudience(AppState.UdapMetadata?.RegistrationEndpoint)
                .WithExpiration(TimeSpan.FromMinutes(5))
                .WithJwtId()
                .WithClientName(UdapEdConstants.CLIENT_NAME)
                .WithContacts(new HashSet<string>
                {
                    "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com"
                })
                .WithTokenEndpointAuthMethod(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue)
                .WithResponseTypes(new HashSet<string> { "code" })
                .WithRedirectUrls(new List<string>{ $"{NavigationManager.BaseUri}udapBusinessToBusiness" })
                .WithScope(scope)
                .Build();


            var statement = await RegisterService.BuildSoftwareStatementForAuthorizationCode(request);
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

    private void ResetSoftwareStatement()
    {
        SetRawMessage(string.Empty);
        AppState.SetProperty(this, nameof(AppState.SoftwareStatementBeforeEncoding), string.Empty);
        _requestBody = null;
        AppState.SetProperty(this, nameof(AppState.UdapRegistrationRequest), null);
        _registrationResult = null;
        AppState.SetProperty(this, nameof(AppState.RegistrationDocument), null);
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
        var registerRequest = await RegisterService.BuildRequestBodyForClientCredentials(AppState.SoftwareStatementBeforeEncoding);
        await AppState.SetPropertyAsync(this, nameof(AppState.UdapRegistrationRequest), registerRequest);

        RequestBody = JsonSerializer.Serialize(
            registerRequest,
            new JsonSerializerOptions { WriteIndented = true });
    }

    private async Task BuildRequestBodyForAuthorizationCode()
    {
        var registerRequest = await RegisterService.BuildRequestBodyForAuthorizationCode(AppState.SoftwareStatementBeforeEncoding);
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
            RegistrationEndpoint = AppState.UdapMetadata?.RegistrationEndpoint,
            UdapRegisterRequest = AppState.UdapRegistrationRequest
        };

        var result = await RegisterService.Register(registrationRequest);
        
        if (result is { Success: true })
        {
            RegistrationResult = JsonSerializer.Serialize(
                result,
                new JsonSerializerOptions { WriteIndented = true });
            
            AppState.SetProperty(this, nameof(AppState.RegistrationDocument), result.Document);
        }
        else
        {
            RegistrationResult = result?.ErrorMessage ?? string .Empty;
            AppState.SetProperty(this, nameof(AppState.RegistrationDocument), null);
        }
    }
    
    protected override void OnParametersSet()
    {
        ErrorBoundary?.Recover();
    }
}
