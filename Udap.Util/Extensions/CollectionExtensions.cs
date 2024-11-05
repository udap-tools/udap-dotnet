#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace Udap.Util.Extensions
{
    public static class CollectionExtensions
    {
        /// <summary>
        /// Tests if this collection is <c>null</c> or has 0 entries.
        /// </summary>
        /// <param name="collection">The collection to test.</param>
        /// <returns><c>true</c> if the collection is <c>null</c> or has 0 entries</returns>
        public static bool IsNullOrEmpty(this ICollection? collection)
        {
            return (collection == null || collection.Count == 0);
        }

        /// <summary>
        /// Creates a string representation of a byte array.
        /// <param name="bytes">The byte array to convert to a string representation.</param>
        /// <returns>A string representation of the byte array.</returns> 
        /// </summary>
        public static String CreateByteStringRep(this byte[] bytes)
        {
            var c = new char[bytes.Length * 2];
            for (var i = 0; i < bytes.Length; i++)
            {
                var b = bytes[i] >> 4;
                c[i * 2] = (char)(55 + b + (((b - 10) >> 31) & -7));
                b = bytes[i] & 0xF;
                c[i * 2 + 1] = (char)(55 + b + (((b - 10) >> 31) & -7));
            }
            return new string(c);

        }


        public static ICollection<string>? Clone(this ICollection<string>? source)
        {
            return source?.ToList();
        }
    }
}
