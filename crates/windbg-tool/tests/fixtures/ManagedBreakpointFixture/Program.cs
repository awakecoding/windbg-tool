using System.Runtime.CompilerServices;

namespace ManagedBreakpointFixture;

public static class Program
{
    public static int Main()
    {
        Console.WriteLine(ManagedTargets.PublicEntry());
        Console.WriteLine(ManagedTargets.InvokePrivateEntry());
        Console.WriteLine(ManagedTargets.Overload("selected"));
        return 0;
    }
}

public static class ManagedTargets
{
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static string PublicEntry() => "public";

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static string InvokePrivateEntry() => PrivateEntry();

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static string PrivateEntry() => "private";

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static string Overload() => "no-arguments";

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static string Overload(string value) => $"string:{value}";
}
