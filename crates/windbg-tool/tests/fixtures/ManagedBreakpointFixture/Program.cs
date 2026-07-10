using System.Runtime.CompilerServices;
using System.Globalization;

namespace ManagedBreakpointFixture;

public static class Program
{
    public static int Main(string[] args)
    {
        Console.WriteLine(ManagedTargets.PublicEntry());
        Console.WriteLine(ManagedTargets.InvokePrivateEntry());
        Console.WriteLine(ManagedTargets.Overload("selected"));
        SleepForStartupObservation(args);
        return 0;
    }

    private static void SleepForStartupObservation(string[] args)
    {
        const string delayArgument = "--startup-observation-delay-ms";
        var index = Array.IndexOf(args, delayArgument);
        if (index < 0 || index + 1 >= args.Length)
        {
            return;
        }

        if (!int.TryParse(
                args[index + 1],
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var delayMilliseconds)
            || delayMilliseconds is < 0 or > 10000)
        {
            throw new ArgumentOutOfRangeException(
                delayArgument,
                "Expected an integer delay from 0 through 10000 milliseconds.");
        }

        Thread.Sleep(delayMilliseconds);
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
