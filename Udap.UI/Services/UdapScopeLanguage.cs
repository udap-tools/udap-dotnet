#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.RegularExpressions;

namespace Udap.UI.Services;

/// <summary>
/// How a consent screen words one OAuth scope: in plain language for the person granting access, and in
/// technical terms for developers and testers.
/// </summary>
/// <param name="Title">Plain-language name of what is shared, e.g. "Your filled prescriptions".</param>
/// <param name="Detail">One sentence saying what the app can do with it.</param>
/// <param name="AllowsChanges">The scope lets the app add, change or delete records, not only read them.</param>
/// <param name="BeyondYou">The scope is not limited to the signed-in patient's own records (user/ or system/).</param>
/// <param name="Technical">The scope broken into its parts, for the Technical view.</param>
/// <param name="Known">False when there is no wording for this scope and the raw value is used instead.</param>
public sealed record UdapScopeWording(
    string Title,
    string Detail,
    bool AllowsChanges,
    bool BeyondYou,
    string Technical,
    bool Known = true);

/// <summary>
/// Plain-language wording for OIDC, SMART App Launch (v1 and v2) and UDAP scopes, built from the scope's
/// parts (context, FHIR resource type, permissions) so a whole SMART scope catalog reads well without
/// per-scope descriptions. Used by consent screens that offer a "Plain language" / "Technical" view.
/// </summary>
public static partial class UdapScopeLanguage
{
    private sealed record Resource(string Title, string What);

    private static readonly Dictionary<string, (string Title, string Detail, string Technical)> Special = new(StringComparer.Ordinal)
    {
        ["openid"] = ("Confirm it's you", "Tells the app who signed in.", "OpenID Connect sign-in (openid)"),
        ["profile"] = ("Your name and profile", "Your name and basic profile details.", "OpenID Connect standard claims (profile)"),
        ["email"] = ("Your email address", "The email address on your account.", "OpenID Connect email claim (email)"),
        ["fhirUser"] = ("Your patient record link", "Which person record on the network is you.", "SMART fhirUser claim: the FHIR resource for the signed-in user"),
        ["launch/patient"] = ("Your patient record", "Tells the app which patient record is yours, so it opens the right one.", "SMART launch context: patient"),
        ["launch"] = ("Open from another health app", "Lets the app start from inside another health app, picking up what you were looking at.", "SMART EHR launch context"),
        ["offline_access"] = ("Stay connected", "The app can keep getting your records after you close it, until you remove its access.", "Refresh token (offline_access)"),
        ["online_access"] = ("Stay connected while you use it", "The app can keep getting your records while you're using it.", "Refresh token for the session (online_access)"),
        ["udap"] = ("Sign in with your identity provider", "Lets this server send you to your own identity provider to sign in.", "UDAP Tiered OAuth for user authentication (udap)")
    };

    private static readonly Dictionary<string, Resource> Resources = new(StringComparer.Ordinal)
    {
        ["*"] = new("All your health records", "every kind of record"),
        ["Patient"] = new("Your basic details", "your name, date of birth, gender and contact details"),
        ["MedicationDispense"] = new("Your filled prescriptions", "the medicines pharmacies have filled for you"),
        ["MedicationRequest"] = new("Your prescriptions", "the medicines your providers have prescribed for you"),
        ["Medication"] = new("Medicine details", "the names, strengths and forms of the medicines in your records"),
        ["MedicationStatement"] = new("Medicines you take", "the medicines recorded as ones you take"),
        ["Immunization"] = new("Your vaccinations", "the vaccines you've received"),
        ["AllergyIntolerance"] = new("Your allergies", "your allergies and reactions to medicines and other things"),
        ["Condition"] = new("Your health conditions", "your diagnoses and health problems"),
        ["Observation"] = new("Your test results and measurements", "your lab results, vital signs and other measurements"),
        ["Encounter"] = new("Your visits", "your visits to clinics, pharmacies and hospitals"),
        ["Procedure"] = new("Your procedures", "the procedures and treatments you've had"),
        ["Coverage"] = new("Your insurance", "your health insurance and drug coverage"),
        ["Consent"] = new("Your sharing choices", "the permissions and sharing choices you've recorded"),
        ["List"] = new("Lists in your record", "lists in your record, such as your medication list"),
        ["Organization"] = new("Your pharmacies and clinics", "the pharmacies, clinics and other organizations in your records"),
        ["Practitioner"] = new("Your care team", "the doctors, pharmacists and other providers in your records"),
        ["PractitionerRole"] = new("Your care team's roles", "where your providers work and what they do"),
        ["Provenance"] = new("Where your records came from", "who created or changed each record, and when"),
        ["DocumentReference"] = new("Your documents", "documents such as visit summaries and notes"),
        ["Binary"] = new("Document files", "the files attached to your documents"),
        ["ServiceRequest"] = new("Orders for your care", "orders for tests, referrals and other services"),
        ["Questionnaire"] = new("Forms", "the forms you may be asked to fill in"),
        ["QuestionnaireResponse"] = new("Your form answers", "the answers you've given on forms"),
        ["Task"] = new("Care tasks", "tasks and requests between your providers"),
        ["Claim"] = new("Insurance claims", "claims sent to your insurance"),
        ["ClaimResponse"] = new("Insurance claim decisions", "your insurance's answers to claims"),
        ["CoverageEligibilityRequest"] = new("Insurance coverage checks", "checks of what your insurance covers"),
        ["Subscription"] = new("Update notifications", "notifications when your records change")
    };

    // SMART: {patient|user|system}/{Type|*}.{read|write|*|cruds subset}
    [GeneratedRegex(@"^(?<context>patient|user|system)/(?<type>\*|[A-Za-z]+)\.(?<perm>read|write|\*|[cruds]+)$")]
    private static partial Regex SmartScope();

    /// <summary>Words <paramref name="scope"/> (the raw scope value, as posted back on consent).</summary>
    public static UdapScopeWording Describe(string scope)
    {
        if (Special.TryGetValue(scope, out var special))
        {
            return new UdapScopeWording(special.Title, special.Detail, false, false, special.Technical);
        }

        var match = SmartScope().Match(scope);
        if (!match.Success)
        {
            return new UdapScopeWording(scope, "A permission this server can't describe in plain words. Switch to Technical to see it.",
                false, false, "Not a scope this server recognizes", Known: false);
        }

        var context = match.Groups["context"].Value;
        var type = match.Groups["type"].Value;
        var perm = match.Groups["perm"].Value;

        var resource = Resources.TryGetValue(type, out var known)
            ? known
            : new Resource($"Your {Words(type)} records", $"your {Words(type)} records");

        var (verbs, allowsChanges, permTechnical) = Permissions(perm);

        var detail = $"The app can {Join(verbs)} {resource.What}.";
        var beyondYou = context != "patient";
        if (context == "user")
        {
            detail += " This includes any records your account can open, not only your own.";
        }
        else if (context == "system")
        {
            detail += " This is system access: it is not limited to your records.";
        }

        var technical = $"{context} context, {(type == "*" ? "all resource types" : type)}, {permTechnical}";
        return new UdapScopeWording(resource.Title, detail, allowsChanges, beyondYou, technical);
    }

    private static (List<string> Verbs, bool AllowsChanges, string Technical) Permissions(string perm)
    {
        switch (perm)
        {
            case "read":
                return (["look at", "search"], false, "read (SMART v1 .read)");
            case "write":
                return (["add to", "change"], true, "write (SMART v1 .write)");
            case "*":
                return (["look at", "search", "add to", "change"], true, "read and write (SMART v1 .*)");
        }

        // SMART v2: any of c r u d s, in any order
        var verbs = new List<string>();
        var parts = new List<string>();
        if (perm.Contains('r')) { verbs.Add("look at"); parts.Add("read"); }
        if (perm.Contains('s')) { verbs.Add("search"); parts.Add("search"); }
        if (perm.Contains('c')) { verbs.Add("add to"); parts.Add("create"); }
        if (perm.Contains('u')) { verbs.Add("change"); parts.Add("update"); }
        if (perm.Contains('d')) { verbs.Add("delete"); parts.Add("delete"); }

        var allowsChanges = perm.IndexOfAny(['c', 'u', 'd']) >= 0;
        return (verbs, allowsChanges, $"{Join(parts)} (SMART v2 .{perm})");
    }

    private static string Join(IReadOnlyList<string> items) => items.Count switch
    {
        0 => string.Empty,
        1 => items[0],
        _ => string.Join(", ", items.Take(items.Count - 1)) + " and " + items[^1]
    };

    // "CoverageEligibilityRequest" -> "coverage eligibility request"
    private static string Words(string pascal) =>
        Regex.Replace(pascal, "(?<!^)([A-Z])", " $1").ToLowerInvariant();
}
