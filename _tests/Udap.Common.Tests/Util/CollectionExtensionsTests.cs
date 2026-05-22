#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Udap.Util.Extensions;
using Xunit;

namespace Udap.Common.Tests.Util;

public class CollectionExtensionsTests
{
    [Fact]
    public void IsNullOrEmpty_NullCollection_ReturnsTrue()
    {
        List<string>? collection = null;
        Assert.True(collection.IsNullOrEmpty());
    }

    [Fact]
    public void IsNullOrEmpty_EmptyCollection_ReturnsTrue()
    {
        var collection = new List<string>();
        Assert.True(collection.IsNullOrEmpty());
    }

    [Fact]
    public void IsNullOrEmpty_NonEmptyCollection_ReturnsFalse()
    {
        var collection = new List<string> { "item" };
        Assert.False(collection.IsNullOrEmpty());
    }

    [Fact]
    public void CreateByteStringRep_KnownBytes_ReturnsUppercaseHex()
    {
        var bytes = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF };
        var result = bytes.CreateByteStringRep();
        Assert.Equal("DEADBEEF", result);
    }

    [Fact]
    public void CreateByteStringRep_AllZeros_Returns0000()
    {
        var bytes = new byte[] { 0x00, 0x00 };
        var result = bytes.CreateByteStringRep();
        Assert.Equal("0000", result);
    }

    [Fact]
    public void CreateByteStringRep_EmptyArray_ReturnsEmptyString()
    {
        var bytes = Array.Empty<byte>();
        var result = bytes.CreateByteStringRep();
        Assert.Equal(string.Empty, result);
    }

    [Fact]
    public void Clone_NullSource_ReturnsNull()
    {
        ICollection<string>? source = null;
        var result = source.Clone();
        Assert.Null(result);
    }

    [Fact]
    public void Clone_WithItems_ReturnsNewListWithSameItems()
    {
        ICollection<string> source = new List<string> { "a", "b", "c" };
        var result = source.Clone();

        Assert.NotNull(result);
        Assert.Equal(source.Count, result!.Count);
        Assert.Equal(source, result);
        Assert.NotSame(source, result);
    }

    [Fact]
    public void Clone_ModifyClone_DoesNotAffectOriginal()
    {
        ICollection<string> source = new List<string> { "a", "b" };
        var clone = source.Clone()!;
        clone.Add("c");

        Assert.Equal(2, source.Count);
        Assert.Equal(3, clone.Count);
    }
}
