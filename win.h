#ifndef __ID_WIN_H__
#define __ID_WIN_H__

int win_authenticate(wchar_t *username, wchar_t *password, wchar_t **domain, void **token);
wchar_t *utf8_to_wchar(char *utf8_str);
char *wchar_to_utf8(wchar_t* wstr);
void *thread_lock_init();
void thread_lock_acquire(void *lock);
void thread_lock_release(void *lock);
void thread_lock_free(void *lock);
void *win_execute_command(wchar_t *shell, wchar_t *command, wchar_t *user, wchar_t *password, wchar_t *domain, wchar_t *root, int pty_mode);
int win_read_proc_pipe(void *ctx, void *buff, int bytes, unsigned int *ecode);
unsigned int win_wait_for_proc(void *ctx);
unsigned int win_terminate_proc(void *ctx);
int win_switch_user(void *new_user);
int win_filestat(void *st, char *path, unsigned int want, unsigned int *give, char **err);
char *win_get_homedir(void *user_token);
char *win_concat_path(char *root, char *path);
int win_makedir(char *path, char **emsg);
int win_createfile(char *path, unsigned int flags, void **handle, char **emsg);
void win_free_token(void *token);
int win_writefile(void *handle, unsigned char *buffer, unsigned int len, unsigned __int64 offset, char **emsg);
int win_deletefile(char *path, char **emsg);
int win_rmdir(char *path, char **emsg);
void win_disable_crash_windows();
int win_chdir(char *rdir, char **emsg);
int win_install_service(char *service, char *desc, char *args, char **emsg);
int win_uninstall_service(char *service, char **emsg);

int service_start(void(*f)(void *, int(*g)()), void *data, char *name, char **emsg);
int service_install(char *name, char *desc, char *args, char **emsg);
int service_uninstall(char *name, char **emsg);


#endif /* __ID_WIN_H__ */
