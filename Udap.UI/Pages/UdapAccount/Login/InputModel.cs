using System.ComponentModel.DataAnnotations;

namespace Udap.UI.Pages.UdapAccount.Login;

public class InputModel
{
    [Required]
    public string Username { get; set; } = default!;

    [Required]
    public string Password { get; set; } = default!;

    public bool RememberLogin { get; set; }

    public string ReturnUrl { get; set; } = default!;

    public string Button { get; set; } = default!;
}