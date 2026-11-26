using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Udap.Identity.Provider.Pages.ServerSideSessions
{
    public class IndexModel : PageModel
    {
        private readonly ISessionManagementService _sessionManagementService;

        public IndexModel(ISessionManagementService sessionManagementService = null)
        {
            _sessionManagementService = sessionManagementService;
        }

        public QueryResult<UserSession> UserSessions { get; set; }

        [BindProperty(SupportsGet = true)]
        public string DisplayNameFilter { get; set; }

        [BindProperty(SupportsGet = true)]
        public string SessionIdFilter { get; set; }

        [BindProperty(SupportsGet = true)]
        public string SubjectIdFilter { get; set; }

        [BindProperty(SupportsGet = true)]
        public string Token { get; set; }

        [BindProperty(SupportsGet = true)]
        public string Prev { get; set; }

        // Lists and ends every user's session, so it answers only requests from the local machine.
        public override void OnPageHandlerExecuting(PageHandlerExecutingContext context)
        {
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
                    DisplayName = DisplayNameFilter,
                    SessionId = SessionIdFilter,
                    SubjectId = SubjectIdFilter
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
            return RedirectToPage("/ServerSideSessions/Index", new { Token, DisplayNameFilter, SessionIdFilter, SubjectIdFilter, Prev });
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
