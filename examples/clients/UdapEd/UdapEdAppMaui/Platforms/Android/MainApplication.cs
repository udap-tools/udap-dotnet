using Android.App;
using Android.Runtime;

namespace UdapEdAppMaui;
[Application(UsesCleartextTraffic = true)] // allows me to pull cleartext links like http://certs.emrdirect.com/certs/EMRDirectTestCA.crt.  Maybe I should just include in my published app?
public class MainApplication : MauiApplication
{
    public MainApplication(IntPtr handle, JniHandleOwnership ownership)
        : base(handle, ownership)
    {
    }

    protected override MauiApp CreateMauiApp() => MauiProgram.CreateMauiApp();
}
