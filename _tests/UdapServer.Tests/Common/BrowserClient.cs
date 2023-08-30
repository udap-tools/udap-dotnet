// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.


using System.Net;

namespace UdapServer.Tests.Common;

public class BrowserClient : HttpClient
{
    public BrowserClient(BrowserHandler browserHandler)
        : base(browserHandler)
    {
        BrowserHandler = browserHandler;
    }

    public BrowserHandler BrowserHandler { get; }

    public bool AllowCookies
    {
        get => BrowserHandler.AllowCookies;
        set => BrowserHandler.AllowCookies = value;
    }
    public bool AllowAutoRedirect
    {
        get => BrowserHandler.AllowAutoRedirect;
        set => BrowserHandler.AllowAutoRedirect = value;
    }
    public int ErrorRedirectLimit
    {
        get => BrowserHandler.ErrorRedirectLimit;
        set => BrowserHandler.ErrorRedirectLimit = value;
    }
    public int StopRedirectingAfter
    {
        get => BrowserHandler.StopRedirectingAfter;
        set => BrowserHandler.StopRedirectingAfter = value;
    }

    internal void RemoveCookie(string uri, string name)
    {
        BrowserHandler.RemoveCookie(uri, name);
    }

    internal Cookie? GetCookie(string uri, string name)
    {
        return BrowserHandler.GetCookie(uri, name);
    }

    internal Cookie? GetXsrfCookie(string uri, string name)
    {
        return BrowserHandler.GetXsrfCookie(uri, name);
    }
}