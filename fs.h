#define FXF_READ            0x00000001
#define FXF_WRITE           0x00000002
#define FXF_APPEND          0x00000004
#define FXF_CREAT           0x00000008
#define FXF_TRUNC           0x00000010
#define FXF_EXCL            0x00000020

#define ATTR_SIZE          0x00000001
#define ATTR_UIDGID        0x00000002
#define ATTR_PERMISSIONS   0x00000004
#define ATTR_ACMODTIME     0x00000008
#define ATTR_EXTENDED      0x80000000

#define ATTR_READONLY         0x00000001
#define ATTR_SYSTEM           0x00000002
#define ATTR_HIDDEN           0x00000004
#define ATTR_CASE_INSENSITIVE 0x00000008
#define ATTR_ARCHIVE          0x00000010
#define ATTR_ENCRYPTED        0x00000020
#define ATTR_COMPRESSED       0x00000040
#define ATTR_SPARSE           0x00000080
#define ATTR_APPEND_ONLY      0x00000100
#define ATTR_IMMUTABLE        0x00000200
#define ATTR_SYNC             0x00000400
#define ATTR_TRANSLATION_ERR  0x00000800


#define FX_OK                            0
#define FX_EOF                           1
#define FX_NO_SUCH_FILE                  2
#define FX_PERMISSION_DENIED             3
#define FX_FAILURE                       4
#define FX_BAD_MESSAGE                   5
#define FX_NO_CONNECTION                 6
#define FX_CONNECTION_LOST               7
#define FX_OP_UNSUPPORTED                8
/*
#define FX_INVALID_HANDLE                9
#define FX_NO_SUCH_PATH                  10
#define FX_FILE_ALREADY_EXISTS           11
#define FX_WRITE_PROTECT                 12
#define FX_NO_MEDIA                      13
#define FX_NO_SPACE_ON_FILESYSTEM        14
#define FX_QUOTA_EXCEEDED                15
#define FX_UNKNOWN_PRINCIPAL             16
#define FX_LOCK_CONFLICT                 17
#define FX_DIR_NOT_EMPTY                 18
#define FX_NOT_A_DIRECTORY               19
#define FX_INVALID_FILENAME              20
#define FX_LINK_LOOP                     21
#define FX_CANNOT_DELETE                 22
#define FX_INVALID_PARAMETER             23
#define FX_FILE_IS_A_DIRECTORY           24
#define FX_BYTE_RANGE_LOCK_CONFLICT      25
#define FX_BYTE_RANGE_LOCK_REFUSED       26
#define FX_DELETE_PENDING                27
#define FX_FILE_CORRUPT                  28
#define FX_OWNER_INVALID                 29
#define FX_GROUP_INVALID                 30
#define FX_NO_MATCHING_BYTE_RANGE_LOCK   31
*/

/*
#define TYPE_REGULAR          1
#define TYPE_DIRECTORY        2
#define TYPE_SYMLINK          3
#define TYPE_SPECIAL          4
#define TYPE_UNKNOWN          5
#define TYPE_SOCKET           6
#define TYPE_CHAR_DEVICE      7
#define TYPE_BLOCK_DEVICE     8
#define TYPE_FIFO             9
*/

#define FX_S_IRUSR  0000400
#define FX_S_IWUSR  0000200
#define FX_S_IXUSR  0000100
#define FX_S_IRGRP  0000040
#define FX_S_IWGRP  0000020
#define FX_S_IXGRP  0000010
#define FX_S_IROTH  0000004
#define FX_S_IWOTH  0000002
#define FX_S_IXOTH  0000001
#define FX_S_ISUID  0004000
#define FX_S_ISGID  0002000
#define FX_S_ISVTX  0001000
#define FX_S_IFDIR  0040000
#define FX_S_IFREG  0100000

typedef struct {
    unsigned __int64 size;
    unsigned int uid;
    unsigned int gid;
    unsigned int perms;
    unsigned int atime;
    unsigned int mtime;
} stat_b;

#define u64_swap(a) \
    (((unsigned __int64)(a) << 56)					\
   | (((unsigned __int64)(a) << 40) & 0xFF000000000000ui64)		\
   | (((unsigned __int64)(a) << 24) & 0xFF0000000000ui64)			\
   | (((unsigned __int64)(a) << 8) & 0xFF00000000ui64)			\
   | (((unsigned __int64)(a) >> 8) & 0xFF000000ui64)			\
   | (((unsigned __int64)(a) >> 24) & 0xFF0000ui64)				\
   | (((unsigned __int64) (a) >> 40) & 0xFF00ui64)				\
   | ((unsigned __int64) (a) >> 56))
