/*
 * vault-exec.c
 * ------------
 * Tiny sgid helper: exec an allow-listed program with the vaultguard group.
 *
 * After privileged install:
 *   /usr/local/bin/vault-exec  owner root:vaultguard  mode 2755
 *
 * The login user is NEVER added to group vaultguard. Human apps get the
 * group only by being launched through this helper. Do not sgid Python.
 *
 * If this binary is not sgid (egid == rgid) it still execs, so unprivileged
 * tests work. Production relies on sgid for group access to ~/Vault.
 */

#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

extern char **environ;

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define DEFAULT_ALLOWLIST "/etc/vault-guardian/allowed-apps"

static void usage(void)
{
    fprintf(stderr,
            "Usage: vault-exec [-t|--allowlist PATH] PROGRAM [ARGS...]\n");
}

static int env_name_eq(const char *entry, const char *name)
{
    size_t n = strlen(name);
    return strncmp(entry, name, n) == 0 && entry[n] == '=';
}

static void sanitize_env(void)
{
    static const char *exact[] = {
        "IFS",
        "CDPATH",
        "ENV",
        "BASH_ENV",
        "SHELLOPTS",
        "GCONV_PATH",
        "TERMINFO",
        "TERMPATH",
        "HOSTALIASES",
        "LOCALDOMAIN",
        "RES_OPTIONS",
        "TMPDIR",
        "VAULT_EXEC_ALLOWLIST",
        NULL
    };
    size_t n = 0;
    size_t i;
    size_t k = 0;
    char **names;

    if (environ == NULL)
        return;
    for (i = 0; environ[i] != NULL; i++)
        n++;

    names = calloc(n + 1, sizeof(*names));
    if (names == NULL)
        return;

    for (i = 0; i < n; i++) {
        const char *entry = environ[i];
        const char *eq = strchr(entry, '=');
        size_t len = eq ? (size_t)(eq - entry) : strlen(entry);
        int drop = 0;
        size_t j;

        if (len >= 3 && strncmp(entry, "LD_", 3) == 0)
            drop = 1;
        else if (len >= 6 && strncmp(entry, "PYTHON", 6) == 0)
            drop = 1;
        else {
            for (j = 0; exact[j] != NULL; j++) {
                if (env_name_eq(entry, exact[j])) {
                    drop = 1;
                    break;
                }
            }
        }
        if (drop) {
            names[k] = malloc(len + 1);
            if (names[k] == NULL)
                continue;
            memcpy(names[k], entry, len);
            names[k][len] = '\0';
            k++;
        }
    }

    for (i = 0; i < k; i++) {
        unsetenv(names[i]);
        free(names[i]);
    }
    free(names);
}

static void trim(char *s)
{
    char *start = s;
    char *end;
    size_t len;

    while (*start == ' ' || *start == '\t' || *start == '\r' || *start == '\n')
        start++;
    if (start != s)
        memmove(s, start, strlen(start) + 1);

    len = strlen(s);
    end = s + len;
    while (end > s && (end[-1] == ' ' || end[-1] == '\t' ||
                       end[-1] == '\r' || end[-1] == '\n')) {
        end--;
        *end = '\0';
    }
}

static int is_allowlisted(const char *allowlist_path, const char *resolved)
{
    FILE *fp;
    char line[PATH_MAX + 32];
    int ok = 0;

    fp = fopen(allowlist_path, "r");
    if (fp == NULL)
        return 0;

    while (fgets(line, (int)sizeof(line), fp) != NULL) {
        char *hash;
        char *rp;

        hash = strchr(line, '#');
        if (hash != NULL)
            *hash = '\0';
        trim(line);
        if (line[0] == '\0')
            continue;

        rp = realpath(line, NULL);
        if (rp == NULL)
            continue;
        if (strcmp(rp, resolved) == 0)
            ok = 1;
        free(rp);
        if (ok)
            break;
    }

    fclose(fp);
    return ok;
}

int main(int argc, char **argv)
{
    const char *allowlist_path = DEFAULT_ALLOWLIST;
    int argi = 1;
    char *resolved;
    uid_t euid;

    if (argc < 2) {
        usage();
        return 2;
    }

    /* Custom allowlist is for unprivileged tests only. A sgid binary
     * (egid != rgid) must ignore -t/--allowlist or an agent could pass
     * /tmp/evil-allowlist and exec /bin/bash with group vaultguard. */
    if (strcmp(argv[1], "-t") == 0 || strcmp(argv[1], "--allowlist") == 0) {
        if (getegid() != getgid()) {
            fprintf(stderr,
                    "vault-exec: --allowlist is not permitted on the sgid helper\n");
            return 1;
        }
        if (argc < 4) {
            usage();
            return 2;
        }
        allowlist_path = argv[2];
        argi = 3;
    } else {
        euid = geteuid();
        if (euid == 0) {
            const char *env = getenv("VAULT_EXEC_ALLOWLIST");
            if (env != NULL && env[0] != '\0')
                allowlist_path = env;
        }
    }

    if (argi >= argc) {
        usage();
        return 2;
    }

    sanitize_env();
    (void)umask(0007);

    resolved = realpath(argv[argi], NULL);
    if (resolved == NULL) {
        fprintf(stderr, "vault-exec: cannot resolve '%s': %s\n",
                argv[argi], strerror(errno));
        return 1;
    }

    if (!is_allowlisted(allowlist_path, resolved)) {
        fprintf(stderr, "vault-exec: '%s' is not an allowed app\n", resolved);
        free(resolved);
        return 1;
    }

    /* Not sgid (egid == rgid) is fine: tests run this way. Production
     * installs mode 2755 root:vaultguard so the child inherits egid. */
    argv[argi] = resolved;
    execve(resolved, argv + argi, environ);
    fprintf(stderr, "vault-exec: execve '%s': %s\n", resolved, strerror(errno));
    free(resolved);
    return 127;
}
