using Spectre.Console;
using Spectre.Console.Cli;

namespace Udap.Pki.Cli;

public class UpdateCrlAllCommand : AsyncCommand<UpdateCrlSettings>
{
    protected override async Task<int> ExecuteAsync(CommandContext context, UpdateCrlSettings settings, CancellationToken cancellationToken)
    {
        var password = UpdateCrlCommand.ResolvePassword(settings);

        AnsiConsole.MarkupLine("[bold]--- SureFhirLabs Community ---[/]");

        AnsiConsole.MarkupLine("[bold]Updating CA CRL...[/]");
        var caResult = await UpdateCrlCommand.UpdateCrl(CrlType.CA, password, settings.IsProduction, settings.Days, "PrivatePkiStore");
        if (caResult != 0)
        {
            AnsiConsole.MarkupLine("[red]CA CRL update failed.[/]");
            return caResult;
        }

        AnsiConsole.MarkupLine("[bold]Updating SubCA CRL...[/]");
        var subCaResult = await UpdateCrlCommand.UpdateCrl(CrlType.SubCA, password, settings.IsProduction, settings.Days, "PrivatePkiStore");
        if (subCaResult != 0)
        {
            AnsiConsole.MarkupLine("[red]SubCA CRL update failed.[/]");
            return subCaResult;
        }

        AnsiConsole.MarkupLine("[bold]--- TEFCA Community ---[/]");

        AnsiConsole.MarkupLine("[bold]Updating TEFCA CA CRL...[/]");
        var tefcaCaResult = await UpdateCrlCommand.UpdateCrl(CrlType.CA, password, settings.IsProduction, settings.Days, "TefcaPkiStore");
        if (tefcaCaResult != 0)
        {
            AnsiConsole.MarkupLine("[red]TEFCA CA CRL update failed.[/]");
            return tefcaCaResult;
        }

        AnsiConsole.MarkupLine("[bold]Updating TEFCA SubCA CRL...[/]");
        var tefcaSubCaResult = await UpdateCrlCommand.UpdateCrl(CrlType.SubCA, password, settings.IsProduction, settings.Days, "TefcaPkiStore");
        if (tefcaSubCaResult != 0)
        {
            AnsiConsole.MarkupLine("[red]TEFCA SubCA CRL update failed.[/]");
            return tefcaSubCaResult;
        }

        AnsiConsole.MarkupLine("[bold green]All CRLs updated successfully.[/]");
        return 0;
    }
}
