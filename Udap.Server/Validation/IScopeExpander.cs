#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Server.Validation;

/// <summary>
/// Implements rules to expand scopes where the scope parameter part may represent an encoded set of scopes.
///
/// From HL7 FHIR SMART v2 the parameters portion of system/Patient.crud can be expanded to discrete scopes.  For example::
///
/// </summary>
public interface IScopeExpander
{
    /// <summary>
    /// Expands scope parameters to a set of discrete scopes.
    /// Implement logic to determine if a scope represents a pattern that can be expanded.
    /// </summary>
    /// <param name="scopes">The scope parameter value.</param>
    /// <returns>A set of discrete scopes.</returns>
    IEnumerable<string> Expand(IEnumerable<string> scopes);

    /// <summary>
    /// Shrinks scope parameters.
    /// </summary>
    /// <param name="scopes"></param>
    /// <returns></returns>
    IEnumerable<string> Shrink(IEnumerable<string> scopes);
}
