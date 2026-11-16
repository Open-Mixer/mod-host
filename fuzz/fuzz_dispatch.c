/* The whole command dispatcher: host_dispatch_register() and its monitor_output, plugin-info and
   unsupported tables over a backend whose answers depend on the input, then protocol_parse(). The backend
   answers every error code the host defines, so each verb's mapping of a return value to a reply is reached.
   Properties: no crash, and every reply is one NUL-terminated string: "resp <int>", alone or followed by the
   values of the verb, or one of the four protocol error messages. Only the `make fuzz` build checks for leaks:
   its LeakSanitizer reports one at exit. */
#include "fuzz.h"
#include <stdio.h>
#include "../src/host-backend.h"
#include "../src/host-dispatch.h"
#include "../src/host-errors.h"

static unsigned g_salt;

/* "resp", a space and an integer, then the end or a space and the verb's values */
static int is_resp_line(const char *reply)
{
    const char *p = reply + 5;
    if (strncmp(reply, "resp ", 5) != 0)
        return 0;
    if (*p == '-')
        p++;
    if (*p < '0' || *p > '9')
        return 0;
    while (*p >= '0' && *p <= '9')
        p++;
    return *p == '\0' || *p == ' ';
}

static int answer(int instance)
{
    static const int codes[] = {
        SUCCESS, ERR_INSTANCE_INVALID, ERR_INSTANCE_ALREADY_EXISTS, ERR_INSTANCE_NON_EXISTS,
        ERR_INSTANCE_UNLICENSED, ERR_LV2_INVALID_URI, ERR_INVALID_OPERATION, ERR_JACK_PORT_CONNECTION,
        ERR_LV2_CANT_LOAD_STATE,
    };
    return codes[((unsigned)instance + g_salt) % (sizeof(codes) / sizeof(codes[0]))];
}

static int f_add(const char *uri, int instance, const char *client) { (void)uri; (void)client; return instance >= 0 ? instance : answer(instance); }
static int f_remove(int instance) { return answer(instance); }
static int f_bypass(int instance, int value) { (void)value; return answer(instance); }
static int f_param_set(int instance, const char *symbol, float value) { (void)symbol; (void)value; return answer(instance); }
static int f_param_get(int instance, const char *symbol, float *value) { (void)symbol; *value = (float)instance; return answer(instance); }
static int f_preset_load(int instance, const char *uri) { (void)uri; return answer(instance); }
static int f_state_save(const char *dir) { return answer((int)strlen(dir)); }
static int f_state_load(const char *dir) { return answer((int)strlen(dir)); }
static int f_connect(const char *a, const char *b) { return answer((int)(strlen(a) + strlen(b))); }
static int f_disconnect(const char *a, const char *b) { return answer((int)(strlen(a) + strlen(b))); }
static int f_monitor_output(int instance, const char *symbol) { (void)symbol; return answer(instance); }
static int f_track_info(int instance, const char *name, const char *color, const char *kind)
{ (void)name; (void)color; (void)kind; return answer(instance); }
static int f_remote_pages(int instance) { return instance < 0 ? answer(instance) : instance % 4; }
static int f_remote_page_get(int instance, int page, host_remote_page_t *out)
{
    if (instance < 0 || page < 0)
        return answer(instance);
    memset(out, 0, sizeof(*out));
    out->id = (uint32_t)page;
    strcpy(out->section, "Main \"A\"\\");
    strcpy(out->name, "Page");
    strcpy(out->slots[0], "gain");
    return SUCCESS;
}
static int f_param_info(int instance, const char *symbol, host_param_info_t *info)
{
    (void)symbol;
    if (instance < 0)
        return answer(instance);
    info->unit = "hz"; info->scale = "log";
    info->min = 20; info->max = 20000; info->def = 440; info->step = (double)(instance % 3);
    info->stable_symbol = "stable";
    return SUCCESS;
}

static const host_backend_t g_backend = {
    f_add, f_remove, f_bypass, f_param_set, f_param_get, f_preset_load,
    f_state_save, f_state_load, f_connect, f_disconnect,
};
static const host_plugin_info_t g_info = { f_track_info, f_remote_pages, f_remote_page_get, f_param_info };

/* The whole reply the dispatcher must give for a verb whose answer comes from the backend above alone: the words of the
   command and the salt decide it. Answers 0 for a verb or a word count this does not cover. */
static int expected_reply(char *out, size_t size, char *const *w, unsigned n)
{
    if (n == 0)
        return 0;
    int instance = n > 1 ? atoi(w[1]) : 0;
    if (strcmp(w[0], "remove") == 0 && n == 2)
        snprintf(out, size, "resp %i", answer(instance));
    else if (strcmp(w[0], "bypass") == 0 && n == 3)
        snprintf(out, size, "resp %i", answer(instance));
    else if (strcmp(w[0], "param_set") == 0 && n == 4)
        snprintf(out, size, "resp %i", answer(instance));
    else if (strcmp(w[0], "preset_load") == 0 && n == 3)
        snprintf(out, size, "resp %i", answer(instance));
    else if (strcmp(w[0], "state_save") == 0 && n == 2)
        snprintf(out, size, "resp %i", answer((int)strlen(w[1])));
    else if (strcmp(w[0], "state_load") == 0 && n == 2)
        snprintf(out, size, "resp %i", answer((int)strlen(w[1])));
    else if ((strcmp(w[0], "connect") == 0 || strcmp(w[0], "disconnect") == 0) && n == 3)
        snprintf(out, size, "resp %i", answer((int)(strlen(w[1]) + strlen(w[2]))));
    else if (strcmp(w[0], "monitor_output") == 0 && n == 3)
        snprintf(out, size, "resp %i", !answer(instance));
    else if (strcmp(w[0], "remote_pages") == 0 && n == 2)
        snprintf(out, size, "resp %i", instance < 0 ? answer(instance) : instance % 4);
    else if (strcmp(w[0], "add") == 0 && n >= 3)
    {
        int added = atoi(w[2]);
        snprintf(out, size, "resp %i", added >= 0 ? added : answer(added));
    }
    else if (strcmp(w[0], "track_info") == 0 && n >= 4)
    {
        /* a name of printable ASCII below 256 bytes, a colour "-" or "#" and six hex digits, a kind of bus, return or
           master, and at most one word after the colour; a name with a byte of 0x80 or more is left to the shape checks */
        const char *name = w[2], *color = w[3], *kind = n > 4 ? w[4] : NULL;
        int valid = strlen(name) < 256 && n <= 5;
        for (const char *c = name; *c; c++)
        {
            if ((unsigned char)*c >= 0x80)
                return 0;
            if ((unsigned char)*c < 0x20 || *c == 0x7f)
                valid = 0;
        }
        valid = valid && (strcmp(color, "-") == 0 ||
                          (strlen(color) == 7 && color[0] == '#' && strspn(color + 1, "0123456789abcdefABCDEF") == 6));
        valid = valid && (!kind || strcmp(kind, "bus") == 0 || strcmp(kind, "return") == 0 || strcmp(kind, "master") == 0);
        snprintf(out, size, "resp %i", valid ? answer(instance) : ERR_INVALID_OPERATION);
    }
    else if (strcmp(w[0], "remote_page_get") == 0 && n == 3)
    {
        int page = atoi(w[2]);
        /* a refusal that is a success (answer() can be SUCCESS) leaves the page as the dispatcher zeroed it */
        if (instance < 0 || page < 0)
        {
            if (answer(instance) < 0)
                snprintf(out, size, "resp %i", answer(instance));
            else
                snprintf(out, size, "resp 0 0 \"\" \"\" - - - - - - - -");
        }
        else
            snprintf(out, size, "resp 0 %i \"Main \\\"A\\\"\\\" \"Page\" gain - - - - - - -", page);
    }
    else if (strcmp(w[0], "param_info") == 0 && n == 3)
    {
        /* a refusal that is a success would print the strings the backend never set: not modeled */
        if (instance < 0 && answer(instance) >= 0)
            return 0;
        if (instance < 0)
            snprintf(out, size, "resp %i", answer(instance));
        else
            snprintf(out, size, "resp 0 hz log 20 20000 440 %i stable", instance % 3);
    }
    else if (strcmp(w[0], "param_get") == 0 && n == 3)
    {
        /* the backend hands back the instance as the value, and only a success carries it */
        int resp = answer(instance);
        if (resp >= 0)
            snprintf(out, size, "resp %i %.04f", resp, (double)(float)instance);
        else
            snprintf(out, size, "resp %i", resp);
    }
    else
        return 0;
    return 1;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    host_dispatch_register(&g_backend);
    host_dispatch_register_monitor_output(f_monitor_output);
    host_dispatch_register_plugin_info(&g_info);
    host_dispatch_register_unsupported();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1 || size > FUZZ_MAX_INPUT)
        return 0;

    g_salt = data[0];
    fuzz_reply_clear();
    msg_t msg;
    msg.data = fuzz_message(data + 1, size - 1);
    msg.data_size = strlen(msg.data);
    msg.sender_id = FUZZ_SENDER;

    /* the words of the command, split on spaces (a message with a quote, a backslash, a "%" or a "..." in it is left
       to the shape checks below: quotes join and cut words, and the parser takes a pattern's own wildcard for a match) */
    char *copy = strdup(msg.data);
    char *words[8];
    unsigned count = 0;
    char expect[256];
    int modeled = 0;
    /* not a property: the harness's own allocation failed */
    if (!copy)
        abort();
    if (strpbrk(copy, "%\"\\") == NULL && strstr(copy, "...") == NULL)
    {
        size_t len = strlen(copy);
        while (len > 0 && (copy[len - 1] == ' ' || copy[len - 1] == '\t' || copy[len - 1] == '\r' || copy[len - 1] == '\n'))
            copy[--len] = '\0';
        for (char *p = copy; count < 8;)
        {
            words[count++] = p;
            p = strchr(p, ' ');
            if (!p)
                break;
            *p++ = '\0';
            while (*p == ' ')
                p++;
        }
        modeled = count < 8 && expected_reply(expect, sizeof(expect), words, count);
    }

    protocol_parse(&msg);
    free(msg.data);

    /* Each command gets a reply: the callback's, or a protocol error message.
       mutant: src/host-dispatch.c:69 `protocol_response_int(resp, proto);` -> ``
       input: scenario-1 */
    if (fuzz_reply_len == 0)
        abort();
    const char *reply = fuzz_reply;
    size_t n = fuzz_reply_len;
    /* One answer per command, sent with its NUL: the NUL is the last byte and the only one.
       mutant: src/protocol.c:224 `proto.response_size+1` -> `proto.response_size`
       input: scenario-1 */
    if (memchr(reply, '\0', n) != reply + n - 1)
        abort();
    /* The reply to a command of the verbs above is the whole text the backend's answer makes, value included.
       mutant: src/host-dispatch.c:143 `resp, value);` -> `resp, 0.0);`
       input: param-get
       mutant: src/host-dispatch.c:376 `info.max` -> `info.min`
       input: extra-8 */
    if (modeled && strcmp(reply, expect) != 0)
        abort();
    free(copy);
    static const char *const texts[] = { "not found", "many arguments", "few arguments", "invalid argument" };
    int known = 0;
    for (int i = 0; i < 4 && !known; i++)
        known = strcmp(reply, texts[i]) == 0;
    /* The answer is one of the four protocol error messages, written out here, or "resp" and an integer, then the end
       or a space.
       mutant: src/protocol.c:302 `g_error_messages[-code-1]` -> `g_error_messages[-code-1] + 1`
       input: extra-17
       mutant: src/protocol.c:278 `"resp %i"` -> `"rsp %i"`
       input: scenario-1 */
    if (!known && !is_resp_line(reply))
        abort();
    return 0;
}
