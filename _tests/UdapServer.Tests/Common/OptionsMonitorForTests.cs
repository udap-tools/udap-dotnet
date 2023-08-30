using Microsoft.Extensions.Options;

namespace UdapServer.Tests.Common;
public class OptionsMonitorForTests<T> : IOptionsMonitor<T>
    where T : class, new()
{
    public OptionsMonitorForTests(T currentValue)
    {
        CurrentValue = currentValue;
    }

    public T Get(string? name)
    {
        return CurrentValue;
    }

    public IDisposable OnChange(Action<T, string> listener)
    {
        throw new NotImplementedException();
    }

    public T CurrentValue { get; }
}
