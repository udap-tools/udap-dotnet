#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography;
using Duende.IdentityModel;
using Duende.IdentityServer.Configuration;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Udap.Server.Validation.Default;

namespace UdapServer.Tests.Validators;

public class UdapJwtBearerClientAssertionSecretParserTests
{
    /// <summary>
    /// Debug logging must never write the token request's credentials: the client assertion,
    /// authorization code, code_verifier or refresh token.
    /// </summary>
    [Fact]
    public async Task ParseAsync_Does_Not_Log_Credentials()
    {
        using var key = RSA.Create(2048);
        var now = DateTime.UtcNow;
        var clientAssertion = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "client-1",
            Audience = "https://server/connect/token",
            IssuedAt = now,
            NotBefore = now,
            Expires = now.AddMinutes(5),
            Claims = new Dictionary<string, object> { { JwtClaimTypes.Subject, "client-1" }, { JwtClaimTypes.JwtId, Guid.NewGuid().ToString() } },
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(key), SecurityAlgorithms.RsaSha256)
        });

        var context = new DefaultHttpContext();
        context.Request.ContentType = "application/x-www-form-urlencoded";
        context.Request.Form = new FormCollection(new Dictionary<string, StringValues>
        {
            { OidcConstants.TokenRequest.GrantType, OidcConstants.GrantTypes.AuthorizationCode },
            { OidcConstants.TokenRequest.Code, "secret-authorization-code" },
            { OidcConstants.TokenRequest.CodeVerifier, "secret-code-verifier" },
            { OidcConstants.TokenRequest.RefreshToken, "secret-refresh-token" },
            { OidcConstants.TokenRequest.ClientAssertionType, OidcConstants.ClientAssertionTypes.JwtBearer },
            { OidcConstants.TokenRequest.ClientAssertion, clientAssertion }
        });

        var logger = new CapturingLogger<UdapJwtBearerClientAssertionSecretParser>();
        var parser = new UdapJwtBearerClientAssertionSecretParser(new IdentityServerOptions(), logger);

        var parsedSecret = await parser.ParseAsync(context, CancellationToken.None);

        Assert.NotNull(parsedSecret);
        Assert.Equal("client-1", parsedSecret.Id);
        Assert.NotEmpty(logger.Messages);

        foreach (var message in logger.Messages)
        {
            Assert.DoesNotContain(clientAssertion, message);
            Assert.DoesNotContain(clientAssertion.Split('.')[1], message);
            Assert.DoesNotContain("secret-authorization-code", message);
            Assert.DoesNotContain("secret-code-verifier", message);
            Assert.DoesNotContain("secret-refresh-token", message);
        }
    }

    private sealed class CapturingLogger<T> : ILogger<T>
    {
        public List<string> Messages { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            Messages.Add(formatter(state, exception));
        }
    }
}
