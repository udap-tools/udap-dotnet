using Blazored.LocalStorage;

namespace UdapClient.Client.Services;

public class ProfileService
{
    public event Action<UdapClientState>? OnChange;

    private readonly ILocalStorageService _localStorageService;
    private const string UdapStateKeyName = "udapClientState";

    public ProfileService(ILocalStorageService localStorageService)
    {
        _localStorageService = localStorageService;
    }

    public async Task SaveUdapClientState(UdapClientState udapClientState)
    {
        await _localStorageService.SetItemAsync(UdapStateKeyName, udapClientState);

        OnChange?.Invoke(udapClientState);
    }

    public async Task<UdapClientState> GetUdapClientState()
    {
        var state = await _localStorageService.GetItemAsync<UdapClientState>(UdapStateKeyName)
               ?? new UdapClientState();

        state.LocalStorageInit();

        return state;
    }
}
