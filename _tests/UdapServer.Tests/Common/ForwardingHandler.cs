namespace UdapServer.Tests.Common;

/// <summary>
/// Sends every request to an existing handler, such as a TestServer's, so a named client can reach a test server.
/// The handler is not owned and is never disposed here.
/// </summary>
public sealed class ForwardingHandler(HttpMessageHandler target) : HttpMessageHandler
{
    private readonly HttpMessageInvoker _invoker = new(target, disposeHandler: false);

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        return _invoker.SendAsync(request, cancellationToken);
    }
}
