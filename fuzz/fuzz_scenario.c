/* The scenario file reader: host_scenario_load() over any bytes, with $NAME substitution, then
   host_scenario_free(). Properties: no crash, and a load that answers a count leaves exactly that many lines,
   each with a command and a reply. A load answers the lines of the input that are neither blank nor a comment,
   with the command and the reply it holds for each line (-1 when a line has no "=>", a guard has no command, or
   there are more lines than the list holds). Only the `make fuzz` build checks for leaks: its LeakSanitizer
   reports one at exit. */
#include "fuzz.h"
#include "../src/host-scenario.h"
#include <stdio.h>

static const char g_path[] = "fuzz-scenario.txt";

static const char *skip_blanks(const char *p, const char *end)
{
    while (p < end && (*p == ' ' || *p == '\t'))
        p++;
    return p;
}

/* [from, to) without the blanks at both ends, with $URI, $PORT_A and $EMPTY replaced, as a new string */
static char *expand(const char *from, const char *to)
{
    static const char *const names[] = { "URI", "PORT_A", "EMPTY" };
    static const char *const values[] = { "http://example.org/plugin", "system:capture_1", "" };
    while (from < to && (*from == ' ' || *from == '\t'))
        from++;
    while (to > from && (to[-1] == ' ' || to[-1] == '\t' || to[-1] == '\n' || to[-1] == '\r'))
        to--;
    char *out = malloc((size_t)(to - from) * 7 + 1);
    /* not a property: the harness's own allocation failed */
    if (!out)
        abort();
    size_t len = 0;
    while (from < to)
    {
        int hit = 0;
        if (*from == '$')
            for (int k = 0; k < 3 && !hit; k++)
            {
                size_t n = strlen(names[k]);
                if ((size_t)(to - from) > n && strncmp(from + 1, names[k], n) == 0)
                {
                    strcpy(out + len, values[k]);
                    len += strlen(values[k]);
                    from += 1 + n;
                    hit = 1;
                }
            }
        if (!hit)
            out[len++] = *from++;
    }
    out[len] = '\0';
    return out;
}

static const char *find(const char *from, const char *to, const char *what)
{
    size_t n = strlen(what);
    for (; (size_t)(to - from) >= n; from++)
        if (memcmp(from, what, n) == 0)
            return from;
    return NULL;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const host_scenario_var_t vars[] = {
        { "URI", "http://example.org/plugin" }, { "PORT_A", "system:capture_1" }, { "EMPTY", "" },
    };
    host_scenario_list_t list;
    FILE *fp;

    if (size > FUZZ_MAX_INPUT)
        return 0;
    fp = fopen(g_path, "w");
    /* not a property: the harness could not write its scratch file */
    if (!fp)
        abort();
    fwrite(data, 1, size, fp);
    fclose(fp);

    /* What the load must keep, from the input alone. Outside this domain only the properties below the count hold:
       a NUL byte ends a line early, and a line of 1,023 bytes or more is read in pieces. */
    char *want_command[HOST_SCENARIO_MAX_LINES], *want_reply[HOST_SCENARIO_MAX_LINES];
    int kept = 0, bad = 0, in_domain = memchr(data, '\0', size) == NULL;
    for (const char *p = (const char *)data, *end = p + size; p < end && in_domain;)
    {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        const char *le = nl ? nl : end;
        const char *t = skip_blanks(p, le);
        if (le - p >= 1023)
            in_domain = 0;
        p = nl ? nl + 1 : end;
        while (le > t && (le[-1] == ' ' || le[-1] == '\t' || le[-1] == '\r'))
            le--;
        if (t >= le || *t == '#')
            continue;
        const char *arrow = find(t, le, "=>");
        if (!arrow || kept >= HOST_SCENARIO_MAX_LINES)
        {
            bad = 1;
            continue;
        }
        const char *from = t;
        if (*t == '@')
        {
            const char *space = memchr(t, ' ', (size_t)(arrow - t));
            if (!space)
            {
                bad = 1;
                continue;
            }
            from = space + 1;
        }
        want_command[kept] = expand(from, arrow);
        want_reply[kept] = expand(arrow + 2, le);
        kept++;
    }
    int want = bad ? -1 : kept;

    int n = host_scenario_load(g_path, vars, 3, &list);
    /* A load keeps the lines that are neither blank nor a comment, and answers -1 for a line it cannot read.
       mutant: src/host-scenario.c:207 `*text == '#'` -> `*text == '#' || *text == '@'`
       input: guarded */
    if (in_domain && n != want)
        abort();
    if (n >= 0)
    {
        /* A load answers the number of lines it kept, and never keeps more than the list holds.
           mutant: src/host-scenario.c:242 `return list->count;` -> `return list->count + 1;`
           input: nul */
        if (n != list.count || n > HOST_SCENARIO_MAX_LINES)
            abort();
        int whole = 0;
        for (int i = 0; i < n; i++)
            whole += list.lines[i].command != NULL && list.lines[i].reply != NULL;
        /* Each line kept has its command and its reply.
           mutant: src/host-scenario.c:238 `sc->reply = substitute(trim(arrow + 2), vars, var_count);` -> `sc->reply = NULL;`
           input: host-scenarios */
        if (whole != n)
            abort();
        for (int i = 0; i < n && in_domain; i++)
        {
            /* The command is the text before the first "=>" (after a guard word) and the reply the text after it, each
               trimmed, with $URI, $PORT_A and $EMPTY replaced.
               mutant: src/host-scenario.c:238 `trim(arrow + 2)` -> `trim(text)`
               input: guarded */
            if (strcmp(list.lines[i].command, want_command[i]) != 0 || strcmp(list.lines[i].reply, want_reply[i]) != 0)
                abort();
        }
        host_scenario_free(&list);
    }
    for (int i = 0; i < kept; i++)
    {
        free(want_command[i]);
        free(want_reply[i]);
    }
    return 0;
}
