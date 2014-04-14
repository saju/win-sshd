#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <sddl.h>
#include <lm.h>
#include <aclapi.h>
#include <userenv.h>
#include "log.h"
#include "fs.h"

typedef struct {
    PROCESS_INFORMATION pi;
    HANDLE out_rd;
    int pty_mode;
} exec_ctx;

void *thread_lock_init() {
    CRITICAL_SECTION *lock = malloc(sizeof(*lock));
    InitializeCriticalSection(lock);
    return lock;
}

void thread_lock_acquire(CRITICAL_SECTION *lock) {
    EnterCriticalSection(lock);
}

void thread_lock_release(CRITICAL_SECTION *lock) {
    LeaveCriticalSection(lock);
}

void thread_lock_free(CRITICAL_SECTION *lock) {
    DeleteCriticalSection(lock);
    free(lock);
}

wchar_t *utf8_to_wchar(char *utf8_str) {
    int len;
    wchar_t *ret;
    
    len = MultiByteToWideChar(CP_UTF8, 0, utf8_str, -1, NULL, 0);
    ret = malloc(len * 4);
    MultiByteToWideChar(CP_UTF8, 0, utf8_str, -1, ret, len);
    return ret;
}

char *wchar_to_utf8(wchar_t *ws) {
    int len;
    char *ret;

    len = WideCharToMultiByte(CP_UTF8, 0, ws, -1, NULL, 0, NULL, NULL);
    ret = malloc(len * 4);
    WideCharToMultiByte(CP_UTF8, 0, ws, -1, ret, len, NULL, NULL);
    return ret;
}

void _parse_username(wchar_t *username, wchar_t **uname, wchar_t **domain) {
    /* parse the DOMAIN\user name into DOMAIN & user */
    wchar_t *c, *temp = _wcsdup(username);
    
    c = wcschr(temp, L'\\');
    if (!c) {
        *uname = username;
        *domain = NULL;
        free(temp);
        return;
    }
    *c = L'\0';
    *domain = malloc((wcslen(temp)+1) * 2);
    wcscpy(*domain, temp);
    *uname = malloc((wcslen(c+1)+1) * 2);
    wcscpy(*uname, c+1);
    free(temp);
}

void win_free_token(HANDLE token) {
    CloseHandle(token);
}


int win_authenticate(wchar_t *username, wchar_t *password, wchar_t **odomain, void **token) {
    wchar_t *user, *domain;
    int ret;
	HANDLE ttok;
    
    _parse_username(username, &user, &domain);
    ret = LogonUserW(user, domain, password, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &ttok);
    if (!ret) {
        char *e = get_error_msg(GetLastError());
        wprintf(L"Login failed for user \"%s\" ", username);
        free(e);
    }
    *odomain = domain;
	*token = ttok;
    return ret;
}

/*
  Execute a command as a "user". The command is run as cmd.exe /c <command>
  The command is executed from the user's HOME (as determined by the user profile)
  Input, Output & Err streams are redirected. 
*/
void *win_execute_command(wchar_t *shell, wchar_t *command, wchar_t *user, wchar_t *password, wchar_t *domain, wchar_t *root, int pty_mode) {
    SECURITY_ATTRIBUTES sa;
    STARTUPINFOW si;
    HANDLE out_rd_tmp, in_wr_tmp, out_wr, in_rd, in_wr, err_wr;
    exec_ctx *ctx;
    HANDLE ttok, ntok;
	int ret;

    ZeroMemory(&sa, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    ctx = malloc(sizeof(*ctx));
    ZeroMemory(ctx, sizeof(*ctx));
    ctx->pty_mode = pty_mode;
 
    /* setup the parent child plumbing */
    if (!CreatePipe(&in_rd, &in_wr_tmp, &sa, 0)) {
        printf("Couldn't set up in pipe to child %s", get_error_msg(GetLastError()));
        free(ctx);
        return NULL;
    }

    if (!CreatePipe(&out_rd_tmp, &out_wr, &sa, 0)) {
        printf("Couldn't set up stdout pipe to child %s", get_error_msg(GetLastError()));
		free(ctx);
        return NULL;
    }

    if (!DuplicateHandle(GetCurrentProcess(), out_wr, GetCurrentProcess(), &err_wr, 0, TRUE, DUPLICATE_SAME_ACCESS)) {
		printf("Couldn't set up stderr pipe to child %s", get_error_msg(GetLastError()));
		free(ctx);
		return NULL;
    }

    if (!DuplicateHandle(GetCurrentProcess(), out_rd_tmp, GetCurrentProcess(), &ctx->out_rd, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
		return NULL;
    }
    if (!DuplicateHandle(GetCurrentProcess(), in_wr_tmp, GetCurrentProcess(), &in_wr, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
		return NULL;
    }
    CloseHandle(out_rd_tmp);
    CloseHandle(in_wr_tmp);

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    si.wShowWindow = SW_HIDE;
    si.hStdInput = in_rd;
    si.hStdOutput = out_wr; 
    si.hStdError = err_wr;
/*
    if (!CreateProcessWithLogonW(user, domain, password, LOGON_WITH_PROFILE, shell, command, 0, NULL, root, &si, &ctx->pi)) {
	*/
	ret = LogonUserW(user, domain, password, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &ttok);
	if (!ret) {
		CloseHandle(ttok);
		INFO(GetLastError(), "Login failed for user");
		return NULL;
	}
	ret = DuplicateTokenEx(ttok, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &ntok);
	if (!ret) {
		CloseHandle(ttok);
		INFO(GetLastError(), "Can't impersonate user");
		return NULL;
	}
	CloseHandle(ttok);
	if (!CreateProcessAsUserW(ntok, shell, command, NULL, NULL, TRUE, 0, NULL, root, &si, &ctx->pi)) {
		int ecode = GetLastError();
		INFO(GetLastError(), "CreateProcess failed");
        free(ctx);
		CloseHandle(ntok);
        return NULL;
    }
	CloseHandle(ntok);
    CloseHandle(out_wr);
    CloseHandle(err_wr);
    CloseHandle(in_rd);
    return ctx;
}

unsigned int win_wait_for_proc(exec_ctx *ctx) {
    DWORD exitcode;

    WaitForSingleObject(ctx->pi.hProcess, INFINITE);
    GetExitCodeProcess(ctx->pi.hProcess, &exitcode);
    CloseHandle(ctx->out_rd);
    CloseHandle(ctx->pi.hThread);
    CloseHandle(ctx->pi.hProcess);
    return exitcode;
}

unsigned int win_terminate_proc(exec_ctx *ctx) {
    TerminateProcess(ctx->pi.hProcess, 1);
    return win_wait_for_proc(ctx);
}
    
int win_read_proc_pipe(exec_ctx *ctx, void *buff, int bytes, unsigned int *ecode) {
    int status;
    int outbytes = 0;
    
    status = ReadFile(ctx->out_rd, buff, bytes, &outbytes, NULL);	
    if (!status || !outbytes) {
		int code = GetLastError();
		if (code == ERROR_BROKEN_PIPE)
			*ecode = win_wait_for_proc(ctx);
		else
			*ecode = win_terminate_proc(ctx);
		return 0;
    } 
    return outbytes;
}

int win_switch_user(HANDLE user_token) {
    if (user_token) {
		if (!ImpersonateLoggedOnUser(user_token)) {
			ERR(GetLastError(), "Could not switch error context");
			return 0;
		}
    }
    else 
		RevertToSelf();
    return 1;
}

void win_to_unix_time(FILETIME ft, unsigned int *secs) {
    /* temp is 100 nanosecond intervals from the Windows epoch Jan 1, 1601 */
    __int64 temp = ((unsigned __int64)ft.dwHighDateTime << 32) + (unsigned __int64)ft.dwLowDateTime;
    temp -= 116444736000000000i64; /* convert base to unix epoch Jan 1, 1970 */
    *secs = (unsigned int)(temp/10000000i64);  /* hopefully the 64bit -> 32bit conversion doesn't loose anything */
}

/**
   stat a file on winnt - this is *very* painful
**/
int win_filestat(stat_b *st, char *path, unsigned int want, unsigned int *give, char **err) {
    WIN32_FILE_ATTRIBUTE_DATA stat;
    SID_IDENTIFIER_AUTHORITY world_auth = SECURITY_WORLD_SID_AUTHORITY;
    PSID owner, group, world = NULL;
    PACL dacl;
    PSECURITY_DESCRIPTOR pdesc;
    int have_sec = 0;

    *give = 0;
    
    if (!GetFileAttributesEx(path, GetFileExInfoStandard, &stat)) {
		int ret, ecode = GetLastError();

		*err = get_error_msg(ecode);
		switch (ecode) {
		case ERROR_FILE_NOT_FOUND:
		case ERROR_PATH_NOT_FOUND: ret = FX_NO_SUCH_FILE; break;
		case ERROR_ACCESS_DENIED:  ret = FX_PERMISSION_DENIED; break;
		default: ret = FX_FAILURE;
		}
		return ret;
    }

    /* create a PSID for well known group "world"  - this is equivalent to "others" on POSIX */
    if (!AllocateAndInitializeSid(&world_auth, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &world)) 
		world = NULL;
    
    memset(st, 0x0, sizeof(*st));
    
    *give |= ATTR_SIZE;
    if (!(stat.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
		st->size = ((unsigned __int64)stat.nFileSizeHigh << 32) + (unsigned __int64)stat.nFileSizeLow;
    else 
		st->size = 0;

    if (GetNamedSecurityInfo(path, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION 
							 | DACL_SECURITY_INFORMATION, &owner, &group, &dacl, NULL, &pdesc) != ERROR_SUCCESS) {
		ERR(have_sec, "Could not retrieve security info");
		have_sec = 0;
    } else
		have_sec = 1;

    if (have_sec) {
		/* fake unix style uid & gid.
		   We will do this by getting the string representations of the owner & group PIDS
		   and converting them to numbers (hopefully unique)
	
		   char *temp;
		   ConvertSidToStringSid(owner, &temp);
		   st->uid = st->gid = atol(temp);
		   printf("(%s) sid = %l , %l\n", temp, st->uid, st->gid);
		   LocalFree(temp);
		*/
		st->uid = st->gid = 42;
		*give |= ATTR_UIDGID;
    }
    /*
      not applicable for v3 - the commented code is for v6

	  if ((want & ATTR_UIDGID) & have_sec){
	  wchar_t uname[UNLEN + 1], dname[DNLEN + 1], gname[1000], gname2[1000];
	  DWORD unlen = UNLEN, dnlen = DNLEN, gnlen = 1000, gnlen2 = 1000;
	  SID_NAME_USE stype;
	
	  st->owner = malloc(UNLEN + DNLEN + 2);
	  if (!LookupAccountSidW(NULL, owner, uname, &unlen, dname, &dnlen, &stype)) {
	  ERR(GetLastError(), "Could not lookup ownername");
	  free(st->owner);
	  st->owner = NULL;
	  } else 
	  swprintf(st->owner, UNLEN + DNLEN + 2, L"%s@%s", uname, dname);
	
	  st->group = malloc(UNLEN + DNLEN + 2 + 2000);
	  if (!LookupAccountSidW(NULL, group, gname, &gnlen, gname2, &gnlen2, &stype)) {
	  ERR(GetLastError(), "Could not lookup group name");
	  if (st->owner) 
	  swprintf(st->group, UNLEN + DNLEN + 2 + 2000, L"None@%", dname);
	  else {
	  free(st->group);
	  st->group = NULL;
	  }
	  } else 
	  swprintf(st->group, UNLEN + DNLEN + 2 + 2000, L"%s@%s", gname, gname2);

	  *give |= ATTR_OWNERGROUP;
	  } 
    */
    st->perms = 0;
    st->perms |= stat.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY ? FX_S_IFDIR : FX_S_IFREG;

    if (have_sec) {
		TRUSTEE_W ident = {NULL, NO_MULTIPLE_TRUSTEE, TRUSTEE_IS_SID};
		ACCESS_MASK acc;
	
		ident.TrusteeType = TRUSTEE_IS_USER;
		ident.ptstrName = owner;
		if (GetEffectiveRightsFromAclW(dacl, &ident, &acc) == ERROR_SUCCESS) {
			if (acc & FILE_EXECUTE) 
				st->perms |= FX_S_IXUSR;
			if (acc & FILE_WRITE_DATA)
				st->perms |= FX_S_IWUSR;
			if (acc & FILE_READ_DATA)
				st->perms |= FX_S_IRUSR;
		}
		ident.TrusteeType = TRUSTEE_IS_GROUP;
		ident.ptstrName = group;
		if (GetEffectiveRightsFromAclW(dacl, &ident, &acc) == ERROR_SUCCESS) {
			if (acc & FILE_EXECUTE) 
				st->perms |= FX_S_IXGRP;
			if (acc & FILE_WRITE_DATA)
				st->perms |= FX_S_IWGRP;
			if (acc & FILE_READ_DATA)
				st->perms |= FX_S_IRGRP;
		}
	
		if (world) {
			ident.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
			ident.ptstrName = world;
			if (GetEffectiveRightsFromAclW(dacl, &ident, &acc) == ERROR_SUCCESS) {
				if (acc & FILE_EXECUTE)
					st->perms |= FX_S_IROTH;
				if (acc & FILE_WRITE_DATA)
					st->perms |= FX_S_IWOTH;
				if (acc & FILE_READ_DATA)
					st->perms |= FX_S_IROTH;
			}
		}
		/* we can't do shit about the S_ISUID, S_ISGUID & S_ISVTX flags */
		*give |= ATTR_PERMISSIONS;
    }
    
    win_to_unix_time(stat.ftLastAccessTime, &st->atime);
    win_to_unix_time(stat.ftLastWriteTime, &st->mtime);
    *give |= ATTR_ACMODTIME;

    /*
	  st->acl = NULL;
	  if (want & ATTR_BITS) {
	  st->attrib_bits_valid = ATTR_ARCHIVE | ATTR_COMPRESSED | ATTR_READONLY
	  | ATTR_SYSTEM | ATTR_SPARSE | ATTR_HIDDEN | ATTR_ENCRYPTED;
	  st->attrib_bits = (stat.dwFileAttributes & FILE_ATTRIBUTE_ARCHIVE) 
	  | (stat.dwFileAttributes & FILE_ATTRIBUTE_COMPRESSED)
	  | (stat.dwFileAttributes & FILE_ATTRIBUTE_READONLY)
	  | (stat.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM)
	  | (stat.dwFileAttributes & FILE_ATTRIBUTE_SPARSE_FILE)
	  | (stat.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN)
	  | (stat.dwFileAttributes & FILE_ATTRIBUTE_ENCRYPTED);
	  *give |= ATTR_BITS;
	  }
    */

    if (world) 
		FreeSid(world);
    if (pdesc)
		LocalFree(pdesc);
    return FX_OK;
}
    
char *win_get_homedir(HANDLE user_token) {
    DWORD sz=4096;
    char *dir;

    GetUserProfileDirectory(user_token, NULL, &sz);
    dir = malloc(sz + 1);
    if (!GetUserProfileDirectory(user_token, dir, &sz)) {
		ERR(GetLastError(), "Could not get user profile directory");
		return NULL;
    }
    return dir;
}

char *win_concat_path(char *root, char *path) {
    /* 
       this is ridiculous, buggy & completely error prone 
       there is no winapi for setting a thread's current directory
       only. So we set a root context for each thread and treat
       all relative paths as under it.
    */
    int len, plen = (int)strlen(path);
    char *p;

    if (!root)
		return _strdup(path);

    if ((plen >= 3) && (path[1] == ':') && (path[2] == '\\')) {
	    /* this is an absolute path */
	    p = _strdup(path);
    } else {
		p = malloc(strlen(root) + plen + 4);
		p[0] = '\0';
		strcat(p, root);
		strcat(p, "\\");
		strcat(p, path);
    }
    plen = (int)strlen(p);
    for (len = 0; len < plen; len++) {
		if (p[len] == '/') 
			p[len] = '\\';
    }
	    
    return p;
}

int win_makedir(char *path, char **emsg) {
    if (!CreateDirectory(path, NULL)) {
		int ret, ecode = GetLastError();

		*emsg = get_error_msg(ecode);
		switch (ecode) {
		case ERROR_FILE_NOT_FOUND:
		case ERROR_PATH_NOT_FOUND: ret = FX_NO_SUCH_FILE; break;
		case ERROR_ACCESS_DENIED:  ret = FX_PERMISSION_DENIED; break;
		case ERROR_ALREADY_EXISTS: ret = FX_FAILURE; break;
		default: ret = FX_FAILURE;
		}
		return ret;
    }
    *emsg = NULL;
    return FX_OK;
}

int win_createfile(char *path, unsigned int flags, void **handle, char **emsg) {
    DWORD access = 0, shared = 0, dispo = 0;
    HANDLE fd;
    int len = (int)strlen(path);

    if (flags & FXF_READ)  {
		access |= GENERIC_READ;
    }
    if (flags & FXF_WRITE) {
		access |= GENERIC_WRITE;
    }
    if (flags & FXF_APPEND) {
		access |= FILE_APPEND_DATA;
    }
    if (flags & FXF_CREAT) {
		dispo |= CREATE_ALWAYS;
    }
    if (!(flags & FXF_CREAT) && (flags & FXF_TRUNC)) {
		dispo |= TRUNCATE_EXISTING;
    }
    if (flags & FXF_EXCL)  {
		shared = 0;
    }
    else {
		shared = FILE_SHARE_READ | FILE_SHARE_WRITE;
    }

    fd = CreateFile(path, access, shared, NULL, dispo, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fd == INVALID_HANDLE_VALUE) {
		int ret, ecode = GetLastError();

		*emsg = get_error_msg(ecode);
		switch (ecode) {
		case ERROR_FILE_NOT_FOUND:
		case ERROR_PATH_NOT_FOUND: ret = FX_NO_SUCH_FILE; break;
		case ERROR_ACCESS_DENIED:  ret = FX_PERMISSION_DENIED; break;
		case ERROR_ALREADY_EXISTS: ret = FX_FAILURE; break;
		default: ret = FX_FAILURE;
		}
		return ret;
    }
    *handle = fd;
    return FX_OK;
}

int win_writefile(HANDLE handle, unsigned char *buffer, unsigned int len, unsigned __int64 offset, char **emsg) {
    unsigned int olen = 0, bytes = 0;
    LARGE_INTEGER pos;
    
    pos.QuadPart = (__int64)offset;
    SetFilePointerEx(handle, pos, NULL, FILE_BEGIN);
    if (!WriteFile(handle, buffer, len, &olen, NULL)) {
		int ecode = GetLastError();
	    
		*emsg = get_error_msg(ecode);
		return FX_FAILURE;
    }
    return FX_OK;
}

int win_deletefile(char *path, char **emsg) {
    if (!DeleteFile(path)) {
		int ret, ecode = GetLastError();

		*emsg = get_error_msg(ecode);
		switch (ecode) {
		case ERROR_FILE_NOT_FOUND:
		case ERROR_PATH_NOT_FOUND: ret = FX_NO_SUCH_FILE; break;
		case ERROR_ACCESS_DENIED:  ret = FX_PERMISSION_DENIED; break;
		default: ret = FX_FAILURE;
		}
		return ret;
    }
    return FX_OK;
}

int win_rmdir(char *path, char **emsg) {
	if (!RemoveDirectory(path)) {
		int ret, ecode = GetLastError();
      
		*emsg = get_error_msg(ecode);
		switch (ecode) {
		case ERROR_FILE_NOT_FOUND:
		case ERROR_PATH_NOT_FOUND: ret = FX_NO_SUCH_FILE; break;
		case ERROR_ACCESS_DENIED:  ret = FX_PERMISSION_DENIED; break;
		default: ret = FX_FAILURE;
		}
		return ret;
	}
	return FX_OK;
}   

void win_disable_crash_windows() {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOALIGNMENTFAULTEXCEPT |
				 SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
}

int win_chdir(char *rdir, char **emsg) {
	if (!SetCurrentDirectory(rdir)) {
		*emsg = get_error_msg(GetLastError());
		return 0;
	}
	return 1;
}
