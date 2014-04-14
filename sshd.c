#define _CRT_SECURE_NO_WARNINGS
#include "log.h"
#include "ssh.h"
#include "network.h"
#include "crypto.h"
#include "win.h"

#define DSA_PUBKEY "dsa_key.pub"
#define DSA_PRIVKEY "dsa_key.prv"
#define RSA_PUBKEY "rsa_key.pub"
#define RSA_PRIVKEY "rsa_key.prv"

#define SERVICE_NAME "Epsilon SSH Service"
#define SERVICE_DESC "An ssh-2.0 sftp & exec service from Idea Device. Please contact support@ideadevice.com for more information"

ssh_server *srvr_ctx;
 
int generate_host_key(int algo) {
    FILE *pub_fp, *priv_fp;
    char *pub, *priv, *err;
    
    if (algo == DSS) {
        pub = DSA_PUBKEY;
        priv = DSA_PRIVKEY;
    } else if (algo == RSA) {
        pub = RSA_PUBKEY;
		priv = RSA_PRIVKEY;
    } else {
        FATAL(NOERR, "Cannot generate keys. Unknown key algo(%d) requested", algo);
        return 1;
    }
    
    pub_fp = fopen(pub, "w+b");
    if (!pub_fp) {
        FATAL(errno, "Could not open file %s", pub);
		return 1;
    }
    priv_fp = fopen(priv, "w+b");
    if (!priv_fp) {
        FATAL(errno, "Could not open file %s", priv);
        return 1;
    }
    if (crypto_write_key_pair(pub_fp, priv_fp, algo, &err)) {
        FATAL(NOERR, "Could not write keys. %s", err);
        return 1;
    }
    fclose(pub_fp);
    fclose(priv_fp);
    return 0;
}

void *load_host_key(int algo) {
    FILE *pub_fp, *priv_fp;
    void *keys;
    char *err, *pub, *priv;
    
    if (algo == DSS) {
        pub = DSA_PUBKEY;
        priv = DSA_PRIVKEY;
    } else if (algo == RSA) {
        pub = RSA_PUBKEY;
        priv = RSA_PRIVKEY;
    } else {
        FATAL(NOERR, "Cannot load keys. Unknown key algo(%d) requested", algo);
        return NULL;
    }
    pub_fp = fopen(pub, "r+b");
    if (!pub_fp) {
        FATAL(errno, "Could not open file %s", pub);
        return NULL;
    }
    priv_fp = fopen(priv, "r+b");
    if (!priv_fp) {
        FATAL(errno, "Could not open file %s", priv);
        return NULL;
    }
    keys = crypto_load_key_pair(pub_fp, priv_fp, algo, &err);
    if (!keys) {
        FATAL(NOERR, "Could not load keys. %s", err);
        return NULL;
    }
    fclose(pub_fp);
    fclose(priv_fp);
    return keys;
}

ssh_server *sshd_server_ctx() {
	return srvr_ctx;
}

int main(int argc, char **argv) {
    void *server;
    wchar_t *shell = L"C:\\WINDOWS\\system32\\cmd.exe";
    int i, want_install = 0, want_uninstall = 0, testing = 0, genkeys = 0;
    char *err, *log_level = "INFO", *tshell = NULL, *rdir = NULL, *option = NULL;
	
    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-install")) {
            want_install = 1;
        }
        else if (!strcmp(argv[i], "-log_level")) {
            log_level = argv[++i];
        } 
        else if (!strcmp(argv[i], "-shell")) {
            tshell = argv[++i];
        }
		else if (!strcmp(argv[i], "-uninstall")) {
			want_uninstall = 1;
		}
		else if (!strcmp(argv[i], "-rdir")) {
			rdir = argv[++i];
		}
		else if (!strcmp(argv[i], "-testing")) {
			testing = 1;
		}
		else if (!strcmp(argv[i], "-genkeys")) {
			genkeys = 1;
		}
		else if (!strcmp(argv[i], "-help")) {
			char *msg =
"Usage: %s -rdir <dir> [options]\n \
where -rdir <dir> is the base directory from which sshd runs\n \
\n\
options include:\n\
-testing   : Start the server bound to a console\n\
-genkeys   : (Re)Gen a new set of DSA key pair\n\
-install   : Install the server as a Win32 service\n\
-uninstall : Uninstall the Win32 sshd service\n\
-shell <path to shell> : Use this shell to execute programs. Default shell is C:\\Windows\\System32\\cmd.exe\n\
-log_level <level>  : Set logging level to DEBUG, INFO, ERR, FATAL. Default is %s\n\
\n\
To install the server first time run %s -rdir <dirname> -genkeys -install\n\
Copyright Idea Device 2011\n";
				printf(msg, argv[0], log_level, argv[0]);
				exit(0);
		}
	}
    
    /* Disable the windows modal crash windows */
    //win_disable_crash_windows();

	if (log_level) {
		option = malloc(strlen(log_level) + sizeof("-log_level ") + 1);
		sprintf(option, "-log_level %s", log_level);
	}
	if (tshell) {
		if (option) {
			char *old_option = _strdup(option);
			option = malloc(strlen(old_option) + strlen(tshell) + sizeof("-shell ") + 1);
			sprintf(option, "%s -shell %s", old_option, tshell);
		} else {
			option = malloc(strlen(tshell) + sizeof("-shell ") + 1);
			sprintf(option, "-shell %s", tshell);
		}
	}
	if (rdir) {
		if (option) {
			char *old_option = _strdup(option);
			option = malloc(strlen(old_option) + strlen(rdir) + sizeof("-rdir ") + 1);
			sprintf(option, "%s -rdir %s", old_option, rdir);
		} else {
			option = malloc(strlen(rdir) + sizeof("-rdir ") + 1);
			sprintf(option, "-rdir %s", rdir);
		}
	}

	if (!rdir) {
		fprintf(stderr, "The base directory for this sshd must be supplied using the -rdir option\n");
		exit(1);
	}
    
	if (!win_chdir(rdir, &err)) {
		fprintf(stderr, "Couldn't change to base directory %s. Error: %s", rdir, err);
		exit(1);
	}
	
    if (!log_init(DEFAULT_LOGFILE)) 
        exit(1);
    
    toggle_level(log_level);
    
    if (crypto_init())
        exit(2);

	if (genkeys) {
		printf("Generating new DSA keys...\n");
		generate_host_key(DSS);
		printf("Wrote DSA keys to disk\n");
	}
    
    if (want_install) {
		if (!service_install(SERVICE_NAME, SERVICE_DESC, option, &err)) {
			fprintf(stderr, "Could not install service. Error %s", err);
			exit(1);
		}
		printf("Installed service\n");
        exit(0);
    }

	if (want_uninstall) {
		if (!service_uninstall(SERVICE_NAME, &err)) {
			fprintf(stderr, "Could not uninstall service. Error %s", err);
			exit(1);
		}
		printf("Uninstalled service\n");
		exit(0);
	}
    
    if (tshell)
        shell = utf8_to_wchar(tshell);
    
    srvr_ctx = MALLOC(sizeof(*srvr_ctx));
    srvr_ctx->dsa_keys = load_host_key(DSS);
    srvr_ctx->shell = shell;
    srvr_ctx->lock = thread_lock_init();
    
    server = network_init(DEFAULT_PORT);
    if (!server) 
        exit(3);
    
    INFO(NOERR, "Server bound to port %d", DEFAULT_PORT);
    
    transport_init();
    kex_init();
    auth_init();
    channel_init();
	if (testing) { 
		/* we dont launch as a service if testing is ON */
		printf("starting server for testing purposes...\n");
		start_server(server, NULL);
	} else {
		/* we launch as a service */
		if (service_start(start_server, server, SERVICE_NAME, &err)) {
			fprintf(stderr, "Failed to start service. Error %s", err);
			exit(1);
		}
	}
    FREE(srvr_ctx);
	//_CrtSetDbgFlag(_CRTDBG_REPORT_FLAG|_CRTDBG_LEAK_CHECK_DF);
}
