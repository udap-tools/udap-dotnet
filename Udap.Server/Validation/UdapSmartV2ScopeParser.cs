#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Duende.IdentityServer.Validation;
using Microsoft.Extensions.Logging;
using Udap.Common;
using Udap.Util.Extensions;

namespace Udap.Server.Validation;

public class UdapSmartV2ScopeParser : IScopeParser

{
    private readonly IScopeExpander _scopeExpander;
    private readonly ILogger<DefaultScopeParser> _logger;

    public UdapSmartV2ScopeParser(IScopeExpander scopeExpander, ILogger<DefaultScopeParser> logger)
    {
        _scopeExpander = scopeExpander;
        _logger = logger;
    }

    /// <inheritdoc/>
    public ParsedScopesResult ParseScopeValues(IEnumerable<string> scopeValues)
    {
        using var activity = Tracing.ValidationActivitySource.StartActivity("UdapSmartV2scopeParser.ParseScopeValues");
        var scopeValuesList = scopeValues.ToList();
        activity?.SetTag(Tracing.Properties.Scope, scopeValuesList.ToSpaceSeparatedString());

        if (scopeValues == null) throw new ArgumentNullException(nameof(scopeValues));
        var expandedScopes = _scopeExpander.Expand(scopeValuesList);
        

        var result = new ParsedScopesResult();

        foreach (var scopeValue in expandedScopes)
        {
            var ctx = new ParseScopeContext(scopeValue);
            ParseScopeValue(ctx);

            if (ctx.Succeeded)
            {
                var parsedScope = ctx.ParsedName != null ?
                    new ParsedScopeValue(ctx.RawValue, ctx.ParsedName, ctx.ParsedParameter) :
                    new ParsedScopeValue(ctx.RawValue);

                result.ParsedScopes.Add(parsedScope);
            }
            else if (!ctx.Ignore)
            {
                result.Errors.Add(new ParsedScopeValidationError(scopeValue, ctx.Error));
            }
            else
            {
                _logger.LogDebug("Scope parsing ignoring scope {scope}", scopeValue);
            }
        }

        return result;
    }

    /// <summary>
    /// Parses a scope value.
    /// </summary>
    /// <param name="scopeContext"></param>
    /// <returns></returns>
    public virtual void ParseScopeValue(ParseScopeContext scopeContext)
    {
        // nop leaves the raw scope value as a success result.
    }

    /// <summary>
    /// Models the context for parsing a scope.
    /// </summary>
    public class ParseScopeContext
    {
        /// <summary>
        /// The original (raw) value of the scope.
        /// </summary>
        public string RawValue { get; }

        /// <summary>
        /// The parsed name of the scope. 
        /// </summary>
        public string ParsedName { get; private set; }

        /// <summary>
        /// The parsed parameter value of the scope. 
        /// </summary>
        public string ParsedParameter { get; private set; }

        /// <summary>
        /// The error encountered parsing the scope.
        /// </summary>
        public string Error { get; private set; }

        /// <summary>
        /// Indicates if the scope should be excluded from the parsed results.
        /// </summary>
        public bool Ignore { get; private set; }

        /// <summary>
        /// Indicates if parsing the scope was successful.
        /// </summary>
        public bool Succeeded => !Ignore && Error == null;


        /// <summary>
        /// Ctor. Indicates success, but the scope should not be included in result.
        /// </summary>
        internal ParseScopeContext(string rawScopeValue)
        {
            RawValue = rawScopeValue;
        }

        /// <summary>
        /// Sets the parsed name and parsed parameter value for the scope.
        /// </summary>
        /// <param name="parsedName"></param>
        /// <param name="parsedParameter"></param>
        public void SetParsedValues(string parsedName, string parsedParameter)
        {
            if (String.IsNullOrWhiteSpace(parsedName))
            {
                throw new ArgumentNullException(nameof(parsedName));
            }
            if (String.IsNullOrWhiteSpace(parsedParameter))
            {
                throw new ArgumentNullException(nameof(parsedParameter));
            }

            ParsedName = parsedName;
            ParsedParameter = parsedParameter;
            Error = null;
            Ignore = false;
        }

        /// <summary>
        /// Set the error encountered parsing the scope.
        /// </summary>
        /// <param name="error"></param>
        public void SetError(string error)
        {
            ParsedName = null;
            ParsedParameter = null;
            Error = error;
            Ignore = false;
        }

        /// <summary>
        /// Sets that the scope is to be ignore/excluded from the parsed results.
        /// </summary>
        public void SetIgnore()
        {
            ParsedName = null;
            ParsedParameter = null;
            Error = null;
            Ignore = true;
        }
    }
}
