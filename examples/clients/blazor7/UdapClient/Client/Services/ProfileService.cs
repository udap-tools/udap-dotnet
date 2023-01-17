#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

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
