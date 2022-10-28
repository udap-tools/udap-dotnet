// UdapModel is modeled after IdentityModel. See https://github.com/IdentityModel/IdentityModel
// 
// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Runtime.CompilerServices;

namespace Udap.Client.Internal;

/// <summary>
/// Helpers to deal with tasks.
/// </summary>
public static class TaskHelpers
{
	/// <summary>
	/// Gets or sets if this library's internal tasks can call ConfigureAwait(false).
	/// </summary>
	public static bool CanConfigureAwaitFalse { get; set; } = true;

	/// <summary>
	/// Gets or sets if this library's internal tasks can call <see cref="TaskFactory.StartNew(System.Action)"/>.
	/// </summary>
	public static bool CanFactoryStartNew { get; set; } = true;

	internal static ConfiguredTaskAwaitable ConfigureAwait(this Task task)
		=> task.ConfigureAwait(!CanConfigureAwaitFalse);

	internal static ConfiguredTaskAwaitable<TResult> ConfigureAwait<TResult>(this Task<TResult> task)
		=> task.ConfigureAwait(!CanConfigureAwaitFalse);
}