Set-StrictMode -Version Latest

if ($null -eq ('PrivateMarker.ProcessBoundary' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace PrivateMarker
{
    public sealed class BoundedReadResult
    {
        public byte[] Data { get; set; }
        public bool LimitExceeded { get; set; }
    }

    public static class BoundedStreamReader
    {
        public static async Task<BoundedReadResult> ReadAsync(Stream stream, int maximumBytes)
        {
            using (var output = new MemoryStream())
            {
                var buffer = new byte[8192];
                while (true)
                {
                    var read = await stream.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
                    if (read == 0)
                    {
                        return new BoundedReadResult {
                            Data = output.ToArray(),
                            LimitExceeded = false
                        };
                    }

                    if (output.Length + read > maximumBytes)
                    {
                        return new BoundedReadResult {
                            Data = output.ToArray(),
                            LimitExceeded = true
                        };
                    }
                    output.Write(buffer, 0, read);
                }
            }
        }
    }

    public static class ProcessBoundary
    {
        private const uint JobObjectExtendedLimitInformation = 9;
        private const uint JobObjectLimitKillOnJobClose = 0x00002000;
        private static int syntheticCloseFailuresRemaining;

        [StructLayout(LayoutKind.Sequential)]
        private struct IoCounters
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BasicLimitInformation
        {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ExtendedLimitInformation
        {
            public BasicLimitInformation BasicLimitInformation;
            public IoCounters IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed;
            public UIntPtr PeakJobMemoryUsed;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateJobObject(IntPtr jobAttributes, string name);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetInformationJobObject(
            IntPtr job,
            uint informationClass,
            IntPtr information,
            uint informationLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        public static IntPtr CreateKillOnCloseJob()
        {
            var job = CreateJobObject(IntPtr.Zero, null);
            if (job == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            var limits = new ExtendedLimitInformation();
            limits.BasicLimitInformation.LimitFlags = JobObjectLimitKillOnJobClose;
            var length = Marshal.SizeOf(typeof(ExtendedLimitInformation));
            var pointer = Marshal.AllocHGlobal(length);
            try
            {
                Marshal.StructureToPtr(limits, pointer, false);
                if (!SetInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    pointer,
                    (uint)length))
                {
                    var error = Marshal.GetLastWin32Error();
                    var setupFailure = new Win32Exception(
                        error,
                        "Configuring the containment job failed.");
                    if (!CloseHandle(job))
                    {
                        var closeFailure = new Win32Exception(
                            Marshal.GetLastWin32Error(),
                            "Closing the unconfigured containment job failed.");
                        throw new AggregateException(
                            setupFailure,
                            closeFailure);
                    }
                    throw setupFailure;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(pointer);
            }
            return job;
        }

        public static void Assign(IntPtr job, IntPtr process)
        {
            if (!AssignProcessToJobObject(job, process))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }

        public static void ConfigureSyntheticCloseFailures(int count)
        {
            syntheticCloseFailuresRemaining = Math.Max(0, count);
        }

        public static void Close(IntPtr handle)
        {
            if (handle == IntPtr.Zero)
            {
                return;
            }
            if (syntheticCloseFailuresRemaining > 0)
            {
                syntheticCloseFailuresRemaining--;
                throw new InvalidOperationException(
                    "Synthetic containment Job close failure.");
            }
            if (!CloseHandle(handle))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
    }

    public sealed class ContainedProcess : IDisposable
    {
        private const uint CreateSuspended = 0x00000004;
        private const uint CreateUnicodeEnvironment = 0x00000400;
        private const uint ExtendedStartupInfoPresent = 0x00080000;
        private const uint CreateNoWindow = 0x08000000;
        private const uint StartfUseStdHandles = 0x00000100;
        private const uint HandleFlagInherit = 0x00000001;
        private const uint ResumeFailed = 0xFFFFFFFF;
        private const uint WaitObject0 = 0x00000000;
        private const uint WaitFailed = 0xFFFFFFFF;
        private static readonly IntPtr ProcThreadAttributeHandleList =
            new IntPtr(0x00020002);

        private IntPtr jobHandle;
        private IntPtr processHandle;
        private bool disposed;

        public Stream StandardInput { get; private set; }
        public Stream StandardOutput { get; private set; }
        public Stream StandardError { get; private set; }
        public static int LastSyntheticFailureProcessId { get; private set; }
        public static int LastDisposedStandardStreamCount { get; private set; }
        public static int LastLaunchCleanupFailureCount { get; private set; }

        private ContainedProcess(
            IntPtr childProcess,
            Stream standardInput,
            Stream standardOutput,
            Stream standardError,
            IntPtr job)
        {
            processHandle = childProcess;
            StandardInput = standardInput;
            StandardOutput = standardOutput;
            StandardError = standardError;
            jobHandle = job;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SecurityAttributes
        {
            public int Length;
            public IntPtr SecurityDescriptor;
            [MarshalAs(UnmanagedType.Bool)]
            public bool InheritHandle;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct StartupInfo
        {
            public int Size;
            public string Reserved;
            public string Desktop;
            public string Title;
            public int X;
            public int Y;
            public int XSize;
            public int YSize;
            public int XCountChars;
            public int YCountChars;
            public int FillAttribute;
            public uint Flags;
            public short ShowWindow;
            public short Reserved2Size;
            public IntPtr Reserved2;
            public IntPtr StandardInput;
            public IntPtr StandardOutput;
            public IntPtr StandardError;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct StartupInfoEx
        {
            public StartupInfo StartupInfo;
            public IntPtr AttributeList;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ProcessInformation
        {
            public IntPtr Process;
            public IntPtr Thread;
            public int ProcessId;
            public int ThreadId;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreatePipe(
            out IntPtr readPipe,
            out IntPtr writePipe,
            ref SecurityAttributes pipeAttributes,
            int size);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetHandleInformation(
            IntPtr handle,
            uint mask,
            uint flags);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateProcessW(
            string applicationName,
            StringBuilder commandLine,
            IntPtr processAttributes,
            IntPtr threadAttributes,
            [MarshalAs(UnmanagedType.Bool)] bool inheritHandles,
            uint creationFlags,
            IntPtr environment,
            string currentDirectory,
            ref StartupInfoEx startupInfo,
            out ProcessInformation processInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool InitializeProcThreadAttributeList(
            IntPtr attributeList,
            int attributeCount,
            int flags,
            ref IntPtr size);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UpdateProcThreadAttribute(
            IntPtr attributeList,
            uint flags,
            IntPtr attribute,
            IntPtr value,
            IntPtr size,
            IntPtr previousValue,
            IntPtr returnSize);

        [DllImport("kernel32.dll")]
        private static extern void DeleteProcThreadAttributeList(
            IntPtr attributeList);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr thread);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TerminateProcess(IntPtr process, uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(
            IntPtr handle,
            uint milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetExitCodeProcess(
            IntPtr process,
            out uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);

        private static string Quote(string value)
        {
            if (String.IsNullOrEmpty(value))
            {
                return "\"\"";
            }
            if (value.IndexOfAny(new[] { ' ', '\t', '"' }) < 0)
            {
                return value;
            }

            var result = new StringBuilder("\"");
            var backslashes = 0;
            foreach (var character in value)
            {
                if (character == '\\')
                {
                    backslashes++;
                    continue;
                }
                if (character == '"')
                {
                    result.Append('\\', (backslashes * 2) + 1);
                    result.Append('"');
                    backslashes = 0;
                    continue;
                }
                result.Append('\\', backslashes);
                backslashes = 0;
                result.Append(character);
            }
            result.Append('\\', backslashes * 2);
            result.Append('"');
            return result.ToString();
        }

        private static StringBuilder BuildCommandLine(
            string filePath,
            string[] arguments)
        {
            var commandLine = new StringBuilder(Quote(filePath));
            foreach (var argument in arguments)
            {
                commandLine.Append(' ');
                commandLine.Append(Quote(argument ?? String.Empty));
            }
            return commandLine;
        }

        private static IntPtr BuildEnvironmentBlock(IDictionary environment)
        {
            var entries = new List<string>();
            foreach (DictionaryEntry entry in environment)
            {
                var name = Convert.ToString(entry.Key);
                var value = Convert.ToString(entry.Value) ?? String.Empty;
                if (String.IsNullOrEmpty(name) ||
                    name.IndexOf('=') >= 0 ||
                    name.IndexOf('\0') >= 0 ||
                    value.IndexOf('\0') >= 0)
                {
                    throw new ArgumentException("Invalid child environment entry.");
                }
                entries.Add(name + "=" + value);
            }
            entries.Sort(StringComparer.OrdinalIgnoreCase);
            var block = String.Join("\0", entries.ToArray()) + "\0\0";
            return Marshal.StringToHGlobalUni(block);
        }

        private static void CloseOwnedHandle(ref IntPtr handle)
        {
            if (handle == IntPtr.Zero)
            {
                return;
            }
            if (!CloseHandle(handle))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Closing an owned process-launch handle failed.");
            }
            handle = IntPtr.Zero;
        }

        private static void TryCloseOwnedHandle(
            ref IntPtr handle,
            List<Exception> failures)
        {
            try
            {
                CloseOwnedHandle(ref handle);
            }
            catch (Exception failure)
            {
                failures.Add(failure);
            }
        }

        private static void TryDisposeOwned<T>(
            ref T value,
            List<Exception> failures,
            bool countStandardStream)
            where T : class, IDisposable
        {
            if (value == null)
            {
                return;
            }
            try
            {
                value.Dispose();
                value = null;
                if (countStandardStream)
                {
                    LastDisposedStandardStreamCount++;
                }
            }
            catch (Exception failure)
            {
                failures.Add(failure);
            }
        }

        public static ContainedProcess Start(
            string filePath,
            string[] arguments,
            IDictionary environment,
            string workingDirectory,
            string testFailureMode)
        {
            // fault injection ごとに probe state を初期化し、直前の PID を
            // self-test が成功値として誤認しないようにする。
            if (!String.IsNullOrEmpty(testFailureMode))
            {
                LastSyntheticFailureProcessId = 0;
            }
            LastDisposedStandardStreamCount = 0;
            LastLaunchCleanupFailureCount = 0;

            IntPtr stdinRead = IntPtr.Zero;
            IntPtr stdinWrite = IntPtr.Zero;
            IntPtr stdoutRead = IntPtr.Zero;
            IntPtr stdoutWrite = IntPtr.Zero;
            IntPtr stderrRead = IntPtr.Zero;
            IntPtr stderrWrite = IntPtr.Zero;
            IntPtr environmentBlock = IntPtr.Zero;
            IntPtr attributeList = IntPtr.Zero;
            IntPtr inheritedHandleList = IntPtr.Zero;
            IntPtr job = IntPtr.Zero;
            var processInformation = new ProcessInformation();
            SafeFileHandle stdinSafeHandle = null;
            SafeFileHandle stdoutSafeHandle = null;
            SafeFileHandle stderrSafeHandle = null;
            FileStream stdin = null;
            FileStream stdout = null;
            FileStream stderr = null;
            var processCreated = false;
            var processAssigned = false;
            ContainedProcess result = null;
            var launchFailures = new List<Exception>();
            var primaryLaunchFailureCount = 0;
            var attributeListInitialized = false;
            try
            {
                var attributes = new SecurityAttributes {
                    Length = Marshal.SizeOf(typeof(SecurityAttributes)),
                    InheritHandle = true
                };
                if (!CreatePipe(out stdinRead, out stdinWrite, ref attributes, 0) ||
                    !CreatePipe(out stdoutRead, out stdoutWrite, ref attributes, 0) ||
                    !CreatePipe(out stderrRead, out stderrWrite, ref attributes, 0))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "CreatePipe failed.");
                }
                if (!SetHandleInformation(stdinWrite, HandleFlagInherit, 0) ||
                    !SetHandleInformation(stdoutRead, HandleFlagInherit, 0) ||
                    !SetHandleInformation(stderrRead, HandleFlagInherit, 0))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "SetHandleInformation failed.");
                }

                var attributeListSize = IntPtr.Zero;
                InitializeProcThreadAttributeList(
                    IntPtr.Zero,
                    1,
                    0,
                    ref attributeListSize);
                if (attributeListSize == IntPtr.Zero)
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "InitializeProcThreadAttributeList size query failed.");
                }
                attributeList = Marshal.AllocHGlobal(attributeListSize);
                if (!InitializeProcThreadAttributeList(
                    attributeList,
                    1,
                    0,
                    ref attributeListSize))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "InitializeProcThreadAttributeList failed.");
                }
                attributeListInitialized = true;

                inheritedHandleList = Marshal.AllocHGlobal(IntPtr.Size * 3);
                Marshal.WriteIntPtr(inheritedHandleList, 0, stdinRead);
                Marshal.WriteIntPtr(inheritedHandleList, IntPtr.Size, stdoutWrite);
                Marshal.WriteIntPtr(
                    inheritedHandleList,
                    IntPtr.Size * 2,
                    stderrWrite);
                if (!UpdateProcThreadAttribute(
                    attributeList,
                    0,
                    ProcThreadAttributeHandleList,
                    inheritedHandleList,
                    new IntPtr(IntPtr.Size * 3),
                    IntPtr.Zero,
                    IntPtr.Zero))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "UpdateProcThreadAttribute failed.");
                }

                var startupInfo = new StartupInfoEx();
                startupInfo.StartupInfo.Size =
                    Marshal.SizeOf(typeof(StartupInfoEx));
                startupInfo.StartupInfo.Flags = StartfUseStdHandles;
                startupInfo.StartupInfo.StandardInput = stdinRead;
                startupInfo.StartupInfo.StandardOutput = stdoutWrite;
                startupInfo.StartupInfo.StandardError = stderrWrite;
                startupInfo.AttributeList = attributeList;

                job = ProcessBoundary.CreateKillOnCloseJob();
                environmentBlock = BuildEnvironmentBlock(environment);
                if (!CreateProcessW(
                    filePath,
                    BuildCommandLine(filePath, arguments),
                    IntPtr.Zero,
                    IntPtr.Zero,
                    true,
                    CreateSuspended |
                        CreateUnicodeEnvironment |
                        CreateNoWindow |
                        ExtendedStartupInfoPresent,
                    environmentBlock,
                    String.IsNullOrWhiteSpace(workingDirectory)
                        ? null
                        : workingDirectory,
                    ref startupInfo,
                    out processInformation))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "CreateProcessW failed.");
                }
                processCreated = true;

                if (!String.IsNullOrEmpty(testFailureMode))
                {
                    LastSyntheticFailureProcessId =
                        processInformation.ProcessId;
                }

                // Job 割当前の失敗でも target は suspended のままにし、
                // catch 側の terminate/wait 契約を実測できるようにする。
                if (String.Equals(
                    testFailureMode,
                    "assign",
                    StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(
                        "Synthetic Job assignment failure.");
                }
                ProcessBoundary.Assign(job, processInformation.Process);
                processAssigned = true;

                stdinSafeHandle = new SafeFileHandle(stdinWrite, true);
                stdinWrite = IntPtr.Zero;
                stdoutSafeHandle = new SafeFileHandle(stdoutRead, true);
                stdoutRead = IntPtr.Zero;
                stderrSafeHandle = new SafeFileHandle(stderrRead, true);
                stderrRead = IntPtr.Zero;
                stdin = new FileStream(
                    stdinSafeHandle,
                    FileAccess.Write,
                    8192,
                    false);
                stdinSafeHandle = null;
                stdout = new FileStream(
                    stdoutSafeHandle,
                    FileAccess.Read,
                    8192,
                    false);
                stdoutSafeHandle = null;
                stderr = new FileStream(
                    stderrSafeHandle,
                    FileAccess.Read,
                    8192,
                    false);
                stderrSafeHandle = null;

                CloseOwnedHandle(ref stdinRead);
                CloseOwnedHandle(ref stdoutWrite);
                CloseOwnedHandle(ref stderrWrite);

                // catch と finally のJob closeを連続で失敗させても、作成済みの
                // 3 streamとsafe-handle、最後のclose retryを失わない。
                if (String.Equals(
                    testFailureMode,
                    "close",
                    StringComparison.Ordinal))
                {
                    ProcessBoundary.ConfigureSyntheticCloseFailures(2);
                    throw new InvalidOperationException(
                        "Synthetic Job close failure.");
                }

                // Job 割当後も resume 前に失敗させ、kill-on-close と bounded
                // wait が対象コードを一度も動かさず完了することを検証する。
                if (String.Equals(
                    testFailureMode,
                    "resume",
                    StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(
                        "Synthetic ResumeThread failure.");
                }
                if (ResumeThread(processInformation.Thread) == ResumeFailed)
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "ResumeThread failed.");
                }
                CloseOwnedHandle(ref processInformation.Thread);

                result = new ContainedProcess(
                    processInformation.Process,
                    stdin,
                    stdout,
                    stderr,
                    job);
                processInformation.Process = IntPtr.Zero;
                stdin = null;
                stdout = null;
                stderr = null;
                job = IntPtr.Zero;
            }
            catch (Exception launchFailure)
            {
                launchFailures.Add(launchFailure);
                primaryLaunchFailureCount = 1;
                if (processCreated)
                {
                    if (processAssigned && job != IntPtr.Zero)
                    {
                        // CloseHandle の成否を確認し、失敗時は suspended child
                        // を直接 terminate する fallback へ移る。
                        try
                        {
                            ProcessBoundary.Close(job);
                            job = IntPtr.Zero;
                        }
                        catch (Exception closeFailure)
                        {
                            launchFailures.Add(closeFailure);
                            if (!TerminateProcess(
                                processInformation.Process,
                                1))
                            {
                                var terminateFailure =
                                    new Win32Exception(
                                        Marshal.GetLastWin32Error(),
                                        "Fallback process termination failed.");
                                launchFailures.Add(terminateFailure);
                            }
                        }
                    }
                    else if (!TerminateProcess(
                        processInformation.Process,
                        1))
                    {
                        launchFailures.Add(new Win32Exception(
                            Marshal.GetLastWin32Error(),
                            "Terminating the suspended process failed."));
                    }

                    // API 呼出しだけで成功扱いにせず、kernel process object の
                    // signal を有限時間で待って cleanup 完了を確定する。
                    var waitResult = WaitForSingleObject(
                        processInformation.Process,
                        5000);
                    if (waitResult != WaitObject0)
                    {
                        Exception waitFailure = waitResult == WaitFailed
                            ? (Exception)new Win32Exception(
                                Marshal.GetLastWin32Error(),
                                "Waiting for launch-failure cleanup failed.")
                            : new TimeoutException(
                                "Launch-failure cleanup exceeded 5000 ms.");
                        launchFailures.Add(waitFailure);
                    }
                }
            }
            finally
            {
                if (environmentBlock != IntPtr.Zero)
                {
                    try
                    {
                        Marshal.FreeHGlobal(environmentBlock);
                        environmentBlock = IntPtr.Zero;
                    }
                    catch (Exception failure)
                    {
                        launchFailures.Add(failure);
                    }
                }
                if (attributeListInitialized)
                {
                    try
                    {
                        DeleteProcThreadAttributeList(attributeList);
                        attributeListInitialized = false;
                    }
                    catch (Exception failure)
                    {
                        launchFailures.Add(failure);
                    }
                }
                if (attributeList != IntPtr.Zero)
                {
                    try
                    {
                        Marshal.FreeHGlobal(attributeList);
                        attributeList = IntPtr.Zero;
                    }
                    catch (Exception failure)
                    {
                        launchFailures.Add(failure);
                    }
                }
                if (inheritedHandleList != IntPtr.Zero)
                {
                    try
                    {
                        Marshal.FreeHGlobal(inheritedHandleList);
                        inheritedHandleList = IntPtr.Zero;
                    }
                    catch (Exception failure)
                    {
                        launchFailures.Add(failure);
                    }
                }

                // cleanup failureごとに継続し、単一のclose/Dispose例外で
                // 後続ownerのreleaseを打ち切らない。
                if (job != IntPtr.Zero)
                {
                    try
                    {
                        ProcessBoundary.Close(job);
                        job = IntPtr.Zero;
                    }
                    catch (Exception failure)
                    {
                        launchFailures.Add(failure);
                    }
                }
                TryDisposeOwned(ref stdin, launchFailures, true);
                TryDisposeOwned(ref stdout, launchFailures, true);
                TryDisposeOwned(ref stderr, launchFailures, true);
                TryDisposeOwned(ref stdinSafeHandle, launchFailures, false);
                TryDisposeOwned(ref stdoutSafeHandle, launchFailures, false);
                TryDisposeOwned(ref stderrSafeHandle, launchFailures, false);

                TryCloseOwnedHandle(ref stdinRead, launchFailures);
                TryCloseOwnedHandle(ref stdinWrite, launchFailures);
                TryCloseOwnedHandle(ref stdoutRead, launchFailures);
                TryCloseOwnedHandle(ref stdoutWrite, launchFailures);
                TryCloseOwnedHandle(ref stderrRead, launchFailures);
                TryCloseOwnedHandle(ref stderrWrite, launchFailures);
                TryCloseOwnedHandle(
                    ref processInformation.Thread,
                    launchFailures);
                TryCloseOwnedHandle(
                    ref processInformation.Process,
                    launchFailures);

                // synthetic transient close failureを含め、全ownerを一度処理した
                // 後にJobを再試行してkill-on-close handleを残さない。
                if (job != IntPtr.Zero)
                {
                    try
                    {
                        ProcessBoundary.Close(job);
                        job = IntPtr.Zero;
                    }
                    catch (Exception failure)
                    {
                        launchFailures.Add(failure);
                    }
                }
            }

            if (launchFailures.Count > 0)
            {
                if (result != null)
                {
                    try
                    {
                        result.Dispose();
                    }
                    catch (Exception resultCleanupFailure)
                    {
                        launchFailures.Add(resultCleanupFailure);
                    }
                    result = null;
                }
                LastLaunchCleanupFailureCount =
                    Math.Max(
                        0,
                        launchFailures.Count - primaryLaunchFailureCount);
                throw new AggregateException(
                    "Contained child launch or setup cleanup failed.",
                    launchFailures);
            }
            return result;
        }

        public bool WaitForExit(int milliseconds)
        {
            return WaitForSingleObject(
                processHandle,
                (uint)milliseconds) == WaitObject0;
        }

        public bool HasExited
        {
            get {
                return WaitForSingleObject(processHandle, 0) == WaitObject0;
            }
        }

        public int ExitCode
        {
            get
            {
                uint exitCode;
                if (!GetExitCodeProcess(processHandle, out exitCode))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                return unchecked((int)exitCode);
            }
        }

        public void CloseJob()
        {
            if (jobHandle == IntPtr.Zero)
            {
                return;
            }
            // close が失敗した時点では ownership が残る。成功前に0化すると、
            // Dispose/retry と terminate fallback の最後の手掛かりを失う。
            ProcessBoundary.Close(jobHandle);
            jobHandle = IntPtr.Zero;
        }

        public void Dispose()
        {
            if (disposed)
            {
                return;
            }
            var failures = new List<Exception>();
            try
            {
                CloseJob();
            }
            catch (Exception closeFailure)
            {
                failures.Add(closeFailure);
            }
            foreach (var stream in new[] {
                StandardInput,
                StandardOutput,
                StandardError
            })
            {
                try
                {
                    stream.Dispose();
                    LastDisposedStandardStreamCount++;
                }
                catch (Exception streamFailure)
                {
                    failures.Add(streamFailure);
                }
            }
            try
            {
                // CloseOwnedHandle は launch setup の best-effort release 用。
                // 所有 object の Dispose では CloseHandle の失敗も握り潰さず、
                // Job/stream cleanup と同じ AggregateException へ加える。
                ProcessBoundary.Close(processHandle);
                processHandle = IntPtr.Zero;
            }
            catch (Exception processHandleFailure)
            {
                failures.Add(processHandleFailure);
            }
            if (jobHandle != IntPtr.Zero)
            {
                try
                {
                    CloseJob();
                }
                catch (Exception retryFailure)
                {
                    failures.Add(retryFailure);
                }
            }
            disposed = jobHandle == IntPtr.Zero &&
                processHandle == IntPtr.Zero;
            if (failures.Count > 0)
            {
                throw new AggregateException(
                    "Contained process disposal failed.",
                    failures);
            }
        }
    }

    public static class PosixSignal
    {
        private const int SigKill = 9;
        private const int ErrorNoSuchProcess = 3;

        [DllImport("libc", EntryPoint = "kill", SetLastError = true)]
        private static extern int KillUnix(int pid, int signal);

        [DllImport("libSystem.B.dylib", EntryPoint = "kill", SetLastError = true)]
        private static extern int KillMacOS(int pid, int signal);

        public static bool IsSuccessfulResult(int result, int error)
        {
            return result == 0 ||
                (result == -1 && error == ErrorNoSuchProcess);
        }

        public static bool KillProcessGroup(int processGroupId)
        {
            if (processGroupId <= 0)
            {
                return false;
            }

            var result = RuntimeInformation.IsOSPlatform(OSPlatform.OSX)
                ? KillMacOS(-processGroupId, SigKill)
                : KillUnix(-processGroupId, SigKill);
            var error = result == 0 ? 0 : Marshal.GetLastWin32Error();
            return IsSuccessfulResult(result, error);
        }
    }
}
'@
}

function Test-PrivateMarkerWindowsHost {
    try {
        return [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
            [System.Runtime.InteropServices.OSPlatform]::Windows
        )
    }
    catch {
        # RuntimeInformation が無い旧hostでも、ambient変数ではなくruntime特性を使う。
        return [System.IO.Path]::DirectorySeparatorChar -eq [char]92
    }
}

function ConvertTo-PrivateMarkerPosixGateFailureReason {
    param([AllowEmptyString()][string]$Status)

    # childからの任意文字列を例外へ反射しない。既知codeと有限桁errnoだけを
    # 固定diagnosticへ変換し、pathやtarget stderrは公開しない。
    if ($Status -cmatch '^setsid-error-(?<errno>[0-9]{1,5})$') {
        return "setsid-error-$($Matches['errno'])"
    }
    switch -CaseSensitive ($Status) {
        'native-library' { return 'native-library' }
        'native-entrypoint' { return 'native-entrypoint' }
        'ready-write' { return 'ready-write' }
        default { return 'unknown' }
    }
}

function Read-PrivateMarkerPosixGateStatus {
    param([AllowEmptyString()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    $statusStream = $null
    try {
        # length確認と別readを分けず、開いた同一handleから最大65 bytesだけ取る。
        # 65 bytes目が存在する、strict UTF-8でない、またはI/O失敗ならunknownへ畳む。
        $statusStream = [System.IO.File]::Open(
            $Path,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            (
                [System.IO.FileShare]::ReadWrite -bor
                [System.IO.FileShare]::Delete
            )
        )
        $statusBytes = New-Object byte[] 65
        $statusLength = 0
        while ($statusLength -lt $statusBytes.Length) {
            $readLength = $statusStream.Read(
                $statusBytes,
                $statusLength,
                $statusBytes.Length - $statusLength
            )
            if ($readLength -eq 0) {
                break
            }
            $statusLength += $readLength
        }
        if ($statusLength -eq 0 -or $statusLength -gt 64) {
            return ''
        }
        $strictUtf8 =
            New-Object System.Text.UTF8Encoding($false, $true)
        return $strictUtf8.GetString(
            $statusBytes,
            0,
            $statusLength
        )
    }
    catch {
        return ''
    }
    finally {
        if ($null -ne $statusStream) {
            $statusStream.Dispose()
        }
    }
}

function ConvertTo-PrivateMarkerProcessArgument {
    param([AllowEmptyString()][string]$Argument)

    if ([string]::IsNullOrEmpty($Argument)) {
        return '""'
    }
    if ($Argument -notmatch '[\s"]') {
        return $Argument
    }

    # PowerShell 5.1 には ArgumentList がないため、native 引数規則で引用する。
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append([char]34)
    $backslashes = 0
    foreach ($character in $Argument.ToCharArray()) {
        if ($character -eq [char]92) {
            $backslashes++
            continue
        }
        if ($character -eq [char]34) {
            [void]$builder.Append([char]92, (($backslashes * 2) + 1))
            [void]$builder.Append([char]34)
            $backslashes = 0
            continue
        }
        if ($backslashes -gt 0) {
            [void]$builder.Append([char]92, $backslashes)
            $backslashes = 0
        }
        [void]$builder.Append($character)
    }
    if ($backslashes -gt 0) {
        [void]$builder.Append([char]92, ($backslashes * 2))
    }
    [void]$builder.Append([char]34)
    return $builder.ToString()
}

function Set-PrivateMarkerHermeticGitEnvironment {
    param(
        [System.Collections.IDictionary]$Environment,
        [string]$IsolationRoot,
        [string]$ExecutablePath
    )

    # Git executable と PATH の出自をambient command lookupへ戻さない。
    if (-not [System.IO.Path]::IsPathRooted($ExecutablePath) -or
        -not (Test-Path -LiteralPath $ExecutablePath -PathType Leaf)) {
        throw 'Sanitized Git executable must be an existing absolute file.'
    }
    $executableDirectory = Split-Path -Parent (
        [System.IO.Path]::GetFullPath($ExecutablePath)
    )

    # denylistでは未知のcredential/marker変数が残る。Git子だけは親cloneを
    # 全消去し、実行に必要な固定allowlistをこの関数内で再構築する。
    $Environment.Clear()

    $homeDirectory = Join-Path $IsolationRoot 'home'
    $xdgDirectory = Join-Path $IsolationRoot 'xdg'
    $temporaryDirectory = Join-Path $IsolationRoot 'tmp'
    $hooksDirectory = Join-Path $IsolationRoot 'empty-hooks'
    $templateDirectory = Join-Path $IsolationRoot 'empty-template'
    foreach ($directory in @(
        $homeDirectory,
        $xdgDirectory,
        $temporaryDirectory,
        $hooksDirectory,
        $templateDirectory
    )) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }

    $emptyGlobalConfig = Join-Path $IsolationRoot 'empty-global.gitconfig'
    $emptySystemConfig = Join-Path $IsolationRoot 'empty-system.gitconfig'
    $emptyAttributes = Join-Path $IsolationRoot 'empty-attributes'
    $emptyExcludes = Join-Path $IsolationRoot 'empty-excludes'
    foreach ($emptyFile in @($emptyGlobalConfig, $emptySystemConfig, $emptyAttributes, $emptyExcludes)) {
        if (-not (Test-Path -LiteralPath $emptyFile -PathType Leaf)) {
            [System.IO.File]::WriteAllText($emptyFile, '', [System.Text.UTF8Encoding]::new($false))
        }
    }

    $safePathEntries = New-Object System.Collections.Generic.List[string]
    $safePathEntries.Add($executableDirectory) | Out-Null
    if (Test-PrivateMarkerWindowsHost) {
        $systemDirectory = [Environment]::SystemDirectory
        if (-not [string]::IsNullOrWhiteSpace($systemDirectory) -and
            (Test-Path -LiteralPath $systemDirectory -PathType Container)) {
            $safePathEntries.Add($systemDirectory) | Out-Null
            $windowsDirectory = Split-Path -Parent $systemDirectory
            $Environment['SystemRoot'] = $windowsDirectory
            $Environment['WINDIR'] = $windowsDirectory
            $Environment['ComSpec'] = Join-Path $systemDirectory 'cmd.exe'
        }
        $Environment['PATHEXT'] = '.COM;.EXE;.BAT;.CMD'
    } else {
        foreach ($systemPath in @('/usr/bin', '/bin')) {
            if (Test-Path -LiteralPath $systemPath -PathType Container) {
                $safePathEntries.Add($systemPath) | Out-Null
            }
        }
        $Environment['TMPDIR'] = $temporaryDirectory
    }
    $Environment['PATH'] = @($safePathEntries | Select-Object -Unique) -join (
        [System.IO.Path]::PathSeparator
    )

    $Environment['HOME'] = $homeDirectory
    $Environment['USERPROFILE'] = $homeDirectory
    $Environment['XDG_CONFIG_HOME'] = $xdgDirectory
    $Environment['TEMP'] = $temporaryDirectory
    $Environment['TMP'] = $temporaryDirectory
    $Environment['LC_ALL'] = 'C'
    $Environment['LANG'] = 'C'
    $Environment['GIT_CONFIG_NOSYSTEM'] = '1'
    $Environment['GIT_ATTR_NOSYSTEM'] = '1'
    $Environment['GIT_CONFIG_GLOBAL'] = $emptyGlobalConfig
    $Environment['GIT_CONFIG_SYSTEM'] = $emptySystemConfig
    $Environment['GIT_TERMINAL_PROMPT'] = '0'
    $Environment['GIT_OPTIONAL_LOCKS'] = '0'
    $Environment['GIT_LFS_SKIP_SMUDGE'] = '1'
    # Partial clone の不足 object を取得したり replace ref で別 blob へ差し替えたりすると、
    # local-only scan が network / repository write を起こすため、全 Git 子で明示的に無効化する。
    $Environment['GIT_NO_LAZY_FETCH'] = '1'
    $Environment['GIT_NO_REPLACE_OBJECTS'] = '1'

    $safeConfig = @(
        [pscustomobject]@{ Key = 'core.hooksPath'; Value = $hooksDirectory },
        [pscustomobject]@{ Key = 'core.attributesFile'; Value = $emptyAttributes },
        [pscustomobject]@{ Key = 'core.excludesFile'; Value = $emptyExcludes },
        [pscustomobject]@{ Key = 'core.fsmonitor'; Value = 'false' },
        [pscustomobject]@{ Key = 'init.templateDir'; Value = $templateDirectory }
    )
    $Environment['GIT_CONFIG_COUNT'] = [string]$safeConfig.Count
    for ($index = 0; $index -lt $safeConfig.Count; $index++) {
        $Environment["GIT_CONFIG_KEY_$index"] = $safeConfig[$index].Key
        $Environment["GIT_CONFIG_VALUE_$index"] = $safeConfig[$index].Value
    }
}

function Stop-PrivateMarkerPosixProcessGroup {
    param([int]$ProcessGroupId)

    # kill utility の exit 1 では ESRCH と EPERM を区別できない。
    # libc の errno を直接読み、既に消滅した group だけを成功として扱う。
    return [PrivateMarker.PosixSignal]::KillProcessGroup($ProcessGroupId)
}

function Stop-PrivateMarkerProcessTree {
    param(
        [System.Diagnostics.Process]$Process = $null,
        [PrivateMarker.ContainedProcess]$ContainedProcess = $null,
        [IntPtr]$JobHandle,
        [int]$PosixProcessGroupId = 0,
        [int]$WaitMilliseconds = 5000
    )

    if ($null -ne $ContainedProcess) {
        $jobClosed = $false
        try {
            $ContainedProcess.CloseJob()
            $jobClosed = $true
        }
        catch {
            $jobClosed = $false
        }
        if (-not $ContainedProcess.HasExited) {
            [void]$ContainedProcess.WaitForExit($WaitMilliseconds)
        }
        return [pscustomobject]@{
            JobClosed = $jobClosed
            ProcessExited = $ContainedProcess.HasExited
        }
    }

    if ($PosixProcessGroupId -gt 0) {
        $groupStopped =
            Stop-PrivateMarkerPosixProcessGroup `
                -ProcessGroupId $PosixProcessGroupId
        if (-not $Process.HasExited) {
            [void]$Process.WaitForExit($WaitMilliseconds)
        }
        return [pscustomobject]@{
            JobClosed = $false
            # 呼出側の既存契約へ group signal の成否も畳み込み、
            # EPERM 等を TreeStopped=true として誤報しない。
            ProcessExited = $groupStopped -and $Process.HasExited
        }
    }

    $jobClosed = $false
    if ($JobHandle -ne [IntPtr]::Zero) {
        try {
            # KILL_ON_JOB_CLOSE で、親が終了済みでも pipe を持つ孫を停止する。
            [PrivateMarker.ProcessBoundary]::Close($JobHandle)
            $jobClosed = $true
        }
        catch {
            $jobClosed = $false
        }
    }

    if (-not $Process.HasExited) {
        if (-not $Process.WaitForExit($WaitMilliseconds)) {
            try {
                $killTreeMethod = $Process.GetType().GetMethod('Kill', [Type[]]@([bool]))
                if ($null -ne $killTreeMethod) {
                    [void]$killTreeMethod.Invoke($Process, @($true))
                } elseif (Test-PrivateMarkerWindowsHost) {
                    $taskkillInfo = New-Object System.Diagnostics.ProcessStartInfo
                    $taskkillInfo.FileName = Join-Path $env:SystemRoot 'System32\taskkill.exe'
                    $taskkillInfo.Arguments = "/PID $($Process.Id) /T /F"
                    $taskkillInfo.UseShellExecute = $false
                    $taskkillInfo.CreateNoWindow = $true
                    $taskkill = [System.Diagnostics.Process]::Start($taskkillInfo)
                    try {
                        if (-not $taskkill.WaitForExit($WaitMilliseconds)) {
                            $taskkill.Kill()
                            [void]$taskkill.WaitForExit($WaitMilliseconds)
                        }
                    }
                    finally {
                        $taskkill.Dispose()
                    }
                } else {
                    $Process.Kill()
                }
            }
            catch {
                if (-not $Process.HasExited) {
                    try { $Process.Kill() } catch { }
                }
            }
        }
    }
    if (-not $Process.HasExited) {
        [void]$Process.WaitForExit($WaitMilliseconds)
    }

    return [pscustomobject]@{
        JobClosed = $jobClosed
        ProcessExited = $Process.HasExited
    }
}

function Wait-PrivateMarkerReadTask {
    param(
        [System.Threading.Tasks.Task]$Task,
        [int]$WaitMilliseconds
    )

    try {
        return $Task.Wait($WaitMilliseconds)
    }
    catch {
        return $false
    }
}

function Invoke-PrivateMarkerProcess {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FileName,

        [string[]]$Arguments = @(),

        [byte[]]$StandardInputBytes = $null,

        [string]$WorkingDirectory = '',

        [hashtable]$EnvironmentOverrides = @{},

        [switch]$SanitizeGitEnvironment,

        [string]$IsolationRoot = '',

        [int]$TimeoutMilliseconds = 15000,

        [int]$MaximumStandardOutputBytes = 8388608,

        [int]$MaximumStandardErrorBytes = 1048576,

        [int]$MaximumStandardInputBytes = 16777216,

        # production caller の既定猶予は維持し、synthetic pipe fixture だけが
        # 同じ状態遷移を短い期限で検証できるよう lower-only にする。
        [ValidateRange(100, 2000)]
        [int]$StreamCompletionWaitMilliseconds = 250,

        [ValidateRange(250, 5000)]
        [int]$StreamCleanupWaitMilliseconds = 5000,

        # Self-test 専用。child の正常終了を有限時間で確認してから
        # launch/setup 全体の期限を超え、終了済み成功の誤受理を測る。
        [ValidateRange(0, 2000)]
        [int]$TestOnlyPostExitDelayMilliseconds = 0,

        # Self-test 専用。最初の期限検査が未超過であることを確認してから
        # 残時間を消費し、stream回収・cleanup後の最終期限検査を測る。
        [switch]$TestOnlyExpireDeadlineAfterInitialCheck,

        # /usr/bin/setsid が無いPOSIX host向けnative gateをself-testで
        # 強制し、portable fallbackも同じcontainment契約で検証する。
        [switch]$ForceNativePosixSessionGate,

        # Self-test 専用。Job 割当前または resume 前の合成失敗でも、
        # suspended child を有限時間で確実に回収する契約を実測する。
        [ValidateSet('', 'assign', 'resume', 'close')]
        [string]$ForceWindowsLaunchFailure = ''
    )

    if ($SanitizeGitEnvironment -and [string]::IsNullOrWhiteSpace($IsolationRoot)) {
        throw 'IsolationRoot is required when SanitizeGitEnvironment is used.'
    }
    if ($null -ne $StandardInputBytes -and
        $StandardInputBytes.Length -gt $MaximumStandardInputBytes) {
        throw 'Standard input exceeds the bounded process byte limit.'
    }

    $process = $null
    $containedProcess = $null
    $processStarted = $false
    $posixProcessGroupId = 0
    $posixGateReadyPath = $null
    $posixGateReleasePath = $null
    $posixGateStatusPath = $null
    $posixSessionGate = 'not-applicable'
    $stdinStream = $null
    $stdoutStream = $null
    $stderrStream = $null
    $stdinTask = $null
    $stdinClosed = $false
    $inputWriteFailed = $false
    $stdoutTask = $null
    $stderrTask = $null
    $timedOut = $false
    $outputLimitExceeded = $false
    $pipeLeakDetected = $false
    $treeStopped = $true
    $exitCode = -1
    $stdoutBytes = New-Object byte[] 0
    $stderrBytes = New-Object byte[] 0
    # timeoutはtarget実行だけでなくprocess launch、Job/session containment、
    # POSIX gate handshakeも含む。境界確立前の待ちをdeadline外へ逃がさない。
    $clock = [System.Diagnostics.Stopwatch]::StartNew()

    try {
        # 子へ渡す environment は親 process の clone から作り、親自身は変更しない。
        $childEnvironment = @{}
        $processEnvironment = [Environment]::GetEnvironmentVariables('Process')
        foreach ($name in $processEnvironment.Keys) {
            $childEnvironment["$name"] = [string]$processEnvironment[$name]
        }
        foreach ($name in $EnvironmentOverrides.Keys) {
            # `$null` は child だけの unset を表す。ambient OS 判定などの
            # absent / present-empty / forged 値を親環境へ触れず検証できる。
            if ($null -eq $EnvironmentOverrides[$name]) {
                [void]$childEnvironment.Remove("$name")
            } else {
                $childEnvironment["$name"] =
                    [string]$EnvironmentOverrides[$name]
            }
        }
        if ($SanitizeGitEnvironment) {
            # caller overrideも含むcloneを最後に破棄し、未知のcredential名や
            # hostile PATHをGit子へ再注入できないようにする。
            Set-PrivateMarkerHermeticGitEnvironment `
                -Environment $childEnvironment `
                -IsolationRoot $IsolationRoot `
                -ExecutablePath $FileName
        }

        if (Test-PrivateMarkerWindowsHost) {
            try {
                # Direct target を suspended で作り、Job assign 後だけ resume する。
                $containedProcess = [PrivateMarker.ContainedProcess]::Start(
                    $FileName,
                    [string[]]$Arguments,
                    $childEnvironment,
                    $WorkingDirectory,
                    $ForceWindowsLaunchFailure
                )
            }
            catch {
                throw "Failed to start atomically contained child process: $($_.Exception.Message)"
            }
            $stdinStream = $containedProcess.StandardInput
            $stdoutStream = $containedProcess.StandardOutput
            $stderrStream = $containedProcess.StandardError
            $processStarted = $true
        } else {
            $effectiveFileName = $FileName
            $effectiveArguments = @($Arguments)
            $useNativePosixSessionGate = $false
            $setsidPath = @('/usr/bin/setsid', '/bin/setsid') |
                Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
                Select-Object -First 1
            if (-not $ForceNativePosixSessionGate -and
                -not [string]::IsNullOrWhiteSpace($setsidPath)) {
                # setsid自身がtargetをexecする前にsession/process groupを作る。
                # targetは親がgroup IDを記録する前に走れても境界外へは出られない。
                $posixSessionGate = 'external-setsid'
                $effectiveFileName = $setsidPath
                $effectiveArguments = @('--', $FileName) + @($Arguments)
            } else {
                # macOS等でsetsid executableが無い場合は、同じpwsh child内で
                # setsid(2)を先に実行し、親がgroup IDを記録するまでtargetを止める。
                $posixSessionGate = 'native-setsid'
                $useNativePosixSessionGate = $true
                $gateRoot = if ([string]::IsNullOrWhiteSpace($IsolationRoot)) {
                    [System.IO.Path]::GetTempPath()
                } else {
                    $IsolationRoot
                }
                if (-not (Test-Path -LiteralPath $gateRoot -PathType Container)) {
                    New-Item -ItemType Directory -Path $gateRoot -Force |
                        Out-Null
                }
                $gateId = [Guid]::NewGuid().ToString('N')
                $posixGateReadyPath =
                    Join-Path $gateRoot "private-marker-posix-ready-$gateId"
                $posixGateReleasePath =
                    Join-Path $gateRoot "private-marker-posix-release-$gateId"
                $posixGateStatusPath =
                    Join-Path $gateRoot "private-marker-posix-status-$gateId"
                $payloadJson = [pscustomobject]@{
                    FileName = $FileName
                    Arguments = @($Arguments)
                } | ConvertTo-Json -Compress -Depth 4
                $payloadBase64 = [Convert]::ToBase64String(
                    [System.Text.Encoding]::UTF8.GetBytes($payloadJson)
                )
                $readyPathBase64 = [Convert]::ToBase64String(
                    [System.Text.Encoding]::UTF8.GetBytes($posixGateReadyPath)
                )
                $releasePathBase64 = [Convert]::ToBase64String(
                    [System.Text.Encoding]::UTF8.GetBytes($posixGateReleasePath)
                )
                $statusPathBase64 = [Convert]::ToBase64String(
                    [System.Text.Encoding]::UTF8.GetBytes($posixGateStatusPath)
                )
                $posixWrapperTemplate = @'
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$statusPath = [Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String('__STATUS_PATH__')
)
function Write-NativeGateStatus([string]$Status) {
    try {
        [IO.File]::WriteAllText(
            $statusPath,
            $Status,
            [Text.UTF8Encoding]::new($false)
        )
    }
    catch {
        # status channel自体の失敗は親側のfixed unknownへ畳み込む。
    }
}
try {
    if ($null -eq ('PrivateMarker.NativePosixSession' -as [type])) {
        Add-Type -TypeDefinition @"
using System.Runtime.InteropServices;

namespace PrivateMarker
{
    public static class NativePosixSession
    {
        [DllImport("libc", EntryPoint = "setsid", SetLastError = true)]
        private static extern int CreateUnix();

        [DllImport("libSystem.B.dylib", EntryPoint = "setsid", SetLastError = true)]
        private static extern int CreateMacOS();

        public static int Create(bool isMacOS)
        {
            return isMacOS ? CreateMacOS() : CreateUnix();
        }
    }
}
"@
    }
    $isMacOS =
        [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
            [Runtime.InteropServices.OSPlatform]::OSX
        )
    $sessionResult = [PrivateMarker.NativePosixSession]::Create($isMacOS)
    if ($sessionResult -lt 0) {
        $nativeError =
            [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-NativeGateStatus "setsid-error-$nativeError"
        [Console]::Error.WriteLine('Bounded POSIX session setup failed.')
        exit 126
    }
    $readyPath = [Text.Encoding]::UTF8.GetString(
        [Convert]::FromBase64String('__READY_PATH__')
    )
    $releasePath = [Text.Encoding]::UTF8.GetString(
        [Convert]::FromBase64String('__RELEASE_PATH__')
    )
    try {
        [IO.File]::WriteAllText(
            $readyPath,
            'ready',
            [Text.UTF8Encoding]::new($false)
        )
    }
    catch {
        Write-NativeGateStatus 'ready-write'
        exit 126
    }
    $released = $false
    for ($gateAttempt = 0; $gateAttempt -lt 3000; $gateAttempt++) {
        if ([IO.File]::Exists($releasePath)) {
            $released = $true
            break
        }
        Start-Sleep -Milliseconds 10
    }
    if (-not $released) {
        exit 124
    }
    $payloadJson = [Text.Encoding]::UTF8.GetString(
        [Convert]::FromBase64String('__PAYLOAD__')
    )
    $payload = ConvertFrom-Json -InputObject $payloadJson
    $invokeArguments = @($payload.Arguments | ForEach-Object { [string]$_ })
    & ([string]$payload.FileName) @invokeArguments
    $childExitCode = $LASTEXITCODE
    if ($null -eq $childExitCode) {
        $childExitCode = 0
    }
    exit [int]$childExitCode
}
catch {
    $baseException = $_.Exception.GetBaseException()
    if ($baseException -is [System.DllNotFoundException]) {
        Write-NativeGateStatus 'native-library'
    } elseif ($baseException -is [System.EntryPointNotFoundException]) {
        Write-NativeGateStatus 'native-entrypoint'
    } else {
        Write-NativeGateStatus 'unknown'
    }
    [Console]::Error.WriteLine('Bounded child launch failed.')
    exit 127
}
'@
                $posixWrapperScript = $posixWrapperTemplate.Replace(
                    '__READY_PATH__',
                    $readyPathBase64
                ).Replace(
                    '__RELEASE_PATH__',
                    $releasePathBase64
                ).Replace(
                    '__STATUS_PATH__',
                    $statusPathBase64
                ).Replace(
                    '__PAYLOAD__',
                    $payloadBase64
                )
                $posixWrapperBase64 = [Convert]::ToBase64String(
                    [System.Text.Encoding]::Unicode.GetBytes(
                        $posixWrapperScript
                    )
                )
                $effectiveFileName = (
                    [System.Diagnostics.Process]::GetCurrentProcess()
                ).MainModule.FileName
                $effectiveArguments = @(
                    '-NoProfile',
                    '-EncodedCommand',
                    $posixWrapperBase64
                )
            }

            $startInfo = New-Object System.Diagnostics.ProcessStartInfo
            $startInfo.FileName = $effectiveFileName
            $startInfo.UseShellExecute = $false
            $startInfo.CreateNoWindow = $true
            $startInfo.RedirectStandardInput = $true
            $startInfo.RedirectStandardOutput = $true
            $startInfo.RedirectStandardError = $true
            if (-not [string]::IsNullOrWhiteSpace($WorkingDirectory)) {
                $startInfo.WorkingDirectory = $WorkingDirectory
            }
            $argumentListProperty = $startInfo.PSObject.Properties['ArgumentList']
            if ($null -ne $argumentListProperty) {
                foreach ($argument in $effectiveArguments) {
                    $startInfo.ArgumentList.Add($argument)
                }
            } else {
                $startInfo.Arguments = (
                    $effectiveArguments | ForEach-Object {
                        ConvertTo-PrivateMarkerProcessArgument -Argument $_
                    }
                ) -join ' '
            }
            $startInfo.EnvironmentVariables.Clear()
            foreach ($name in $childEnvironment.Keys) {
                $startInfo.EnvironmentVariables["$name"] =
                    [string]$childEnvironment[$name]
            }

            $process = New-Object System.Diagnostics.Process
            $process.StartInfo = $startInfo
            $processStarted = $process.Start()
            if (-not $processStarted) {
                throw "Failed to start bounded child process: $FileName"
            }
            if ($useNativePosixSessionGate) {
                $posixGateReady = $false
                for ($gateAttempt = 0;
                    $gateAttempt -lt 2000 -and
                    $clock.ElapsedMilliseconds -lt $TimeoutMilliseconds;
                    $gateAttempt++) {
                    if ([System.IO.File]::Exists($posixGateReadyPath)) {
                        $posixGateReady = $true
                        break
                    }
                    if ([System.IO.File]::Exists($posixGateStatusPath)) {
                        break
                    }
                    if ($process.HasExited) {
                        break
                    }
                    $gateWaitMilliseconds = [Math]::Min(
                        5,
                        [Math]::Max(
                            1,
                            $TimeoutMilliseconds -
                                [int]$clock.ElapsedMilliseconds
                        )
                    )
                    Start-Sleep -Milliseconds $gateWaitMilliseconds
                }
                if (-not $posixGateReady) {
                    $posixGateStatus =
                        Read-PrivateMarkerPosixGateStatus `
                            -Path $posixGateStatusPath
                    $posixGateFailureReason =
                        ConvertTo-PrivateMarkerPosixGateFailureReason `
                            -Status $posixGateStatus
                    [void](Stop-PrivateMarkerProcessTree -Process $process)
                    throw (
                        'Failed to establish the bounded POSIX session gate ' +
                        "($posixGateFailureReason)."
                    )
                }
                # readyはsetsid成功後だけ作られる。group IDを保持してから
                # releaseするため、targetの最初の命令より先にcleanup先が確定する。
                $posixProcessGroupId = $process.Id
                try {
                    [System.IO.File]::WriteAllText(
                        $posixGateReleasePath,
                        'release',
                        [System.Text.UTF8Encoding]::new($false)
                    )
                }
                catch {
                    [void](Stop-PrivateMarkerPosixProcessGroup `
                            -ProcessGroupId $posixProcessGroupId)
                    throw
                }
            } else {
                $posixProcessGroupId = $process.Id
            }
            $stdinStream = $process.StandardInput.BaseStream
            $stdoutStream = $process.StandardOutput.BaseStream
            $stderrStream = $process.StandardError.BaseStream
        }

        $stdoutTask = [PrivateMarker.BoundedStreamReader]::ReadAsync(
            $stdoutStream,
            $MaximumStandardOutputBytes
        )
        $stderrTask = [PrivateMarker.BoundedStreamReader]::ReadAsync(
            $stderrStream,
            $MaximumStandardErrorBytes
        )

        $effectiveInputBytes = if ($null -eq $StandardInputBytes) {
            New-Object byte[] 0
        } else {
            $StandardInputBytes
        }
        if ($effectiveInputBytes.Length -eq 0) {
            $stdinStream.Dispose()
            $stdinClosed = $true
        } else {
            $stdinTask = $stdinStream.WriteAsync(
                $effectiveInputBytes,
                0,
                $effectiveInputBytes.Length
            )
        }
        if ($TestOnlyPostExitDelayMilliseconds -gt 0) {
            # 固定sleepだけでは高負荷時にchildが未終了のままになり得る。
            # 別の有限時計で終了を確認し、旧「未終了かつ超過」分岐を確実に外す。
            $testOnlyExitWait = [System.Diagnostics.Stopwatch]::StartNew()
            $testOnlyProcessHasExited = if ($null -ne $containedProcess) {
                $containedProcess.HasExited
            } else {
                $process.HasExited
            }
            while (-not $testOnlyProcessHasExited -and
                $testOnlyExitWait.ElapsedMilliseconds -lt 5000) {
                if ($null -ne $containedProcess) {
                    [void]$containedProcess.WaitForExit(10)
                } else {
                    [void]$process.WaitForExit(10)
                }
                $testOnlyProcessHasExited = if ($null -ne $containedProcess) {
                    $containedProcess.HasExited
                } else {
                    $process.HasExited
                }
            }
            if (-not $testOnlyProcessHasExited) {
                throw 'Self-test child did not exit before the post-exit deadline delay.'
            }
            [System.Threading.Thread]::Sleep(
                $TestOnlyPostExitDelayMilliseconds
            )
        }
        $processHasExited = if ($null -ne $containedProcess) {
            $containedProcess.HasExited
        } else {
            $process.HasExited
        }
        while (-not $processHasExited -and
            $clock.ElapsedMilliseconds -lt $TimeoutMilliseconds) {
            if (-not $stdinClosed -and
                $null -ne $stdinTask -and
                $stdinTask.IsCompleted) {
                if ($stdinTask.IsFaulted -or $stdinTask.IsCanceled) {
                    $inputWriteFailed = $true
                } else {
                    try {
                        $stdinStream.Dispose()
                    }
                    catch {
                        $inputWriteFailed = $true
                    }
                }
                $stdinClosed = $true
            }
            if (($stdoutTask.Status -eq [System.Threading.Tasks.TaskStatus]::RanToCompletion -and
                    $stdoutTask.Result.LimitExceeded) -or
                ($stderrTask.Status -eq [System.Threading.Tasks.TaskStatus]::RanToCompletion -and
                    $stderrTask.Result.LimitExceeded) -or
                $inputWriteFailed -or
                $stdoutTask.IsFaulted -or
                $stderrTask.IsFaulted) {
                $outputLimitExceeded = $stdoutTask.Status -eq [System.Threading.Tasks.TaskStatus]::RanToCompletion -and
                    $stdoutTask.Result.LimitExceeded
                $outputLimitExceeded = $outputLimitExceeded -or (
                    $stderrTask.Status -eq [System.Threading.Tasks.TaskStatus]::RanToCompletion -and
                    $stderrTask.Result.LimitExceeded
                )
                break
            }
            if ($null -ne $containedProcess) {
                [void]$containedProcess.WaitForExit(100)
            } else {
                [void]$process.WaitForExit(100)
            }
            $processHasExited = if ($null -ne $containedProcess) {
                $containedProcess.HasExited
            } else {
                $process.HasExited
            }
        }

        if (-not $stdinClosed) {
            if ($null -ne $stdinTask -and
                $stdinTask.Status -eq [System.Threading.Tasks.TaskStatus]::RanToCompletion) {
                try {
                    $stdinStream.Dispose()
                }
                catch {
                    $inputWriteFailed = $true
                }
            } elseif ($clock.ElapsedMilliseconds -lt $TimeoutMilliseconds) {
                $inputWriteFailed = $true
            }
            $stdinClosed = $true
        }

        # 成功受理の直前では child の現在状態と独立に、launch、containment、
        # target、stdin処理を含む全経過時間だけで deadline 超過を確定する。
        if ($clock.ElapsedMilliseconds -ge $TimeoutMilliseconds) {
            $timedOut = $true
        }
        if ($TestOnlyExpireDeadlineAfterInitialCheck -and $timedOut) {
            throw 'Self-test deadline expired before the post-check delay.'
        }

        $needsTreeStop = $timedOut -or
            $outputLimitExceeded -or
            $inputWriteFailed -or
            $stdoutTask.IsFaulted -or
            $stderrTask.IsFaulted
        if ($needsTreeStop) {
            $stopResult = Stop-PrivateMarkerProcessTree `
                -Process $process `
                -ContainedProcess $containedProcess `
                -JobHandle ([IntPtr]::Zero) `
                -PosixProcessGroupId $posixProcessGroupId
            $treeStopped = $stopResult.ProcessExited -and (
                -not (Test-PrivateMarkerWindowsHost) -or $stopResult.JobClosed
            )
        }

        $processHasExited = if ($null -ne $containedProcess) {
            $containedProcess.HasExited
        } else {
            $process.HasExited
        }
        if ($processHasExited) {
            $exitCode = if ($null -ne $containedProcess) {
                $containedProcess.ExitCode
            } else {
                $process.ExitCode
            }
        }

        # 親が正常終了しても、孫が pipe handle を保持すれば read task は終わらない。
        $stdoutInitiallyComplete = Wait-PrivateMarkerReadTask `
            -Task $stdoutTask `
            -WaitMilliseconds $StreamCompletionWaitMilliseconds
        $stderrInitiallyComplete = Wait-PrivateMarkerReadTask `
            -Task $stderrTask `
            -WaitMilliseconds $StreamCompletionWaitMilliseconds
        if (-not $stdoutInitiallyComplete -or -not $stderrInitiallyComplete) {
            $pipeLeakDetected = $true
            $processHasExited = if ($null -ne $containedProcess) {
                $containedProcess.HasExited
            } else {
                $process.HasExited
            }
            if ($null -ne $containedProcess -or
                $posixProcessGroupId -gt 0 -or
                -not $processHasExited) {
                $stopResult = Stop-PrivateMarkerProcessTree `
                    -Process $process `
                    -ContainedProcess $containedProcess `
                    -JobHandle ([IntPtr]::Zero) `
                    -PosixProcessGroupId $posixProcessGroupId
                $treeStopped = $treeStopped -and
                    $stopResult.ProcessExited -and (
                        -not (Test-PrivateMarkerWindowsHost) -or $stopResult.JobClosed
                    )
            } elseif (Test-PrivateMarkerWindowsHost) {
                $treeStopped = $false
            }
            [void](Wait-PrivateMarkerReadTask `
                    -Task $stdoutTask `
                    -WaitMilliseconds $StreamCleanupWaitMilliseconds)
            [void](Wait-PrivateMarkerReadTask `
                    -Task $stderrTask `
                    -WaitMilliseconds $StreamCleanupWaitMilliseconds)
        }

        if ($stdoutTask.Status -eq [System.Threading.Tasks.TaskStatus]::RanToCompletion) {
            $stdoutBytes = $stdoutTask.Result.Data
            $outputLimitExceeded = $outputLimitExceeded -or $stdoutTask.Result.LimitExceeded
        }
        if ($stderrTask.Status -eq [System.Threading.Tasks.TaskStatus]::RanToCompletion) {
            $stderrBytes = $stderrTask.Result.Data
            $outputLimitExceeded = $outputLimitExceeded -or $stderrTask.Result.LimitExceeded
        }
        if ($TestOnlyExpireDeadlineAfterInitialCheck) {
            # 初回deadline検査を未超過で通過した後、stream回収完了時点の
            # 残時間へ固定猶予を足し、result前の最終検査だけを実測する。
            $testOnlyRemainingMilliseconds = [Math]::Max(
                1,
                $TimeoutMilliseconds -
                    [int]$clock.ElapsedMilliseconds +
                    100
            )
            [System.Threading.Thread]::Sleep(
                $testOnlyRemainingMilliseconds
            )
        }
    }
    finally {
        if ($processStarted) {
            if ($null -ne $containedProcess) {
                $stopResult = Stop-PrivateMarkerProcessTree `
                    -Process $process `
                    -ContainedProcess $containedProcess `
                    -JobHandle ([IntPtr]::Zero) `
                    -PosixProcessGroupId 0
                $treeStopped = $treeStopped -and
                    $stopResult.ProcessExited -and (
                        $stopResult.JobClosed
                    )
            } elseif ($null -ne $process -and
                $posixProcessGroupId -gt 0) {
                # direct childが先に終了してもgroupは孫を指し続ける。
                # finallyで必ずsignalし、pipeを持たない孫の副作用も止める。
                $stopResult = Stop-PrivateMarkerProcessTree `
                    -Process $process `
                    -ContainedProcess $null `
                    -JobHandle ([IntPtr]::Zero) `
                    -PosixProcessGroupId $posixProcessGroupId
                $treeStopped = $treeStopped -and
                    $stopResult.ProcessExited
            } elseif ($null -ne $process -and -not $process.HasExited) {
                $stopResult = Stop-PrivateMarkerProcessTree `
                    -Process $process `
                    -ContainedProcess $null `
                    -JobHandle ([IntPtr]::Zero) `
                    -PosixProcessGroupId 0
                $treeStopped = $treeStopped -and $stopResult.ProcessExited
            }
        }
        if (-not $stdinClosed -and $null -ne $stdinStream) {
            try {
                $stdinStream.Dispose()
            }
            catch {
                $inputWriteFailed = $true
            }
            $stdinClosed = $true
        }
        if ($null -ne $containedProcess) {
            $containedProcess.Dispose()
        }
        if ($null -ne $process) {
            $process.Dispose()
        }
        foreach ($gatePath in @(
            $posixGateReadyPath,
            $posixGateReleasePath,
            $posixGateStatusPath
        )) {
            if (-not [string]::IsNullOrWhiteSpace($gatePath)) {
                try {
                    [System.IO.File]::Delete($gatePath)
                }
                catch {
                    # cleanup artifact失敗はprocess tree判定へ影響させない。
                }
            }
        }
    }

    # stream drain、process-tree停止、handle/pipe disposalも同じtotal
    # deadlineに含める。cleanup後の成功受理直前に単調時計を再確認する。
    if ($clock.ElapsedMilliseconds -ge $TimeoutMilliseconds) {
        $timedOut = $true
    }
    $streamsCompleted = $null -ne $stdoutTask -and
        $null -ne $stderrTask -and
        $stdoutTask.Status -eq [System.Threading.Tasks.TaskStatus]::RanToCompletion -and
        $stderrTask.Status -eq [System.Threading.Tasks.TaskStatus]::RanToCompletion -and
        -not $pipeLeakDetected

    return [pscustomobject]@{
        ExitCode = $exitCode
        StandardOutputBytes = $stdoutBytes
        StandardErrorBytes = $stderrBytes
        TimedOut = $timedOut
        OutputLimitExceeded = $outputLimitExceeded
        InputWriteFailed = $inputWriteFailed
        PipeLeakDetected = $pipeLeakDetected
        StreamsCompleted = $streamsCompleted
        TreeStopped = $treeStopped
        PosixSessionGate = $posixSessionGate
    }
}

function ConvertFrom-PrivateMarkerUtf8Bytes {
    param(
        [byte[]]$Bytes,
        [string]$Context
    )

    try {
        $text = [System.Text.UTF8Encoding]::new($false, $true).GetString($Bytes)
        if ($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) {
            return $text.Substring(1)
        }
        return $text
    }
    catch [System.Text.DecoderFallbackException] {
        throw "$Context is not valid UTF-8."
    }
}
