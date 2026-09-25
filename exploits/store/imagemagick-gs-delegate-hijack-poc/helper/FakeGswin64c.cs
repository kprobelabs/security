using System;
using System.IO;

class FakeGswin64c
{
    static int Main(string[] args)
    {
        string marker = Environment.GetEnvironmentVariable("IM_GS_MARKER");
        if (!String.IsNullOrEmpty(marker))
            File.WriteAllText(marker, "fake gswin64c executed\n" + String.Join("\n", args));
        return 0;
    }
}
