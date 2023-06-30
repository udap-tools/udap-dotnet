using Microsoft.AspNetCore.Authentication;

namespace Udap.Server.Security.Authentication.TieredOAuth;

internal static class HandleRequestResults
{
    internal static HandleRequestResult InvalidState = HandleRequestResult.Fail("The oauth state was missing or invalid.");
}
