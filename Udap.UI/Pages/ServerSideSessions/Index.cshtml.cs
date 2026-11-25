using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Udap.UI.Pages.ServerSideSessions
{
    // Lists and ends every user's session, so it is limited to signed-in users on the local machine,
    // like the Diagnostics page.
    [SecurityHeaders]
    [Authorize]
    public class IndexModel : PageModel
    {
        private readonly ISessionManagementService _sessionManagementService;

        public IndexModel(ISessionManagementService sessionManagementService = null)
        {
            _sessionManagementService = sessionManagementService;
        }

        public QueryResult<UserSession> UserSessions { get; set; }

        [BindProperty(SupportsGet = true)]
        public string Filter { get; set; }

        [BindProperty(SupportsGet = true)]
        public string Token { get; set; }

        [BindProperty(SupportsGet = true)]
        public string Prev { get; set; }

        public override void OnPageHandlerExecuting(PageHandlerExecutingContext context)
        {
            // Checked here rather than in each handler so OnGet keeps its signature.
            if (!IsLocalRequest())
            {
                context.Result = NotFound();
                return;
            }

            base.OnPageHandlerExecuting(context);
        }

        public async Task OnGet()
        {
            if (_sessionManagementService != null)
            {
                UserSessions = await _sessionManagementService.QuerySessionsAsync(new SessionQuery
                {
                    ResultsToken = Token,
                    RequestPriorResults = Prev == "true",
                    DisplayName = Filter,
                    SessionId = Filter,
                    SubjectId = Filter,
                }, HttpContext.RequestAborted);
            }
        }

        [BindProperty]
        public string SessionId { get; set; }

        public async Task<IActionResult> OnPost()
        {
            if (_sessionManagementService == null)
            {
                return NotFound();
            }

            await _sessionManagementService.RemoveSessionsAsync(new RemoveSessionsContext {
                SessionId = SessionId,
            }, HttpContext.RequestAborted);
            return RedirectToPage("/ServerSideSessions/Index", new { Token, Filter, Prev });
        }

        private bool IsLocalRequest()
        {
            var remote = HttpContext.Connection.RemoteIpAddress;
            if (remote == null)
            {
                return false;
            }

            return System.Net.IPAddress.IsLoopback(remote) || remote.Equals(HttpContext.Connection.LocalIpAddress);
        }
    }
}
