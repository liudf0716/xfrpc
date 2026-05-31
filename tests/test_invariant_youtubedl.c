#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>

/* Include the production code under test */
#include "../plugins/youtubedl.c"

#define ACTION_BUF_SIZE 64
#define PROFILE_BUF_SIZE 64

static char *make_repeated(char c, int n) {
    char *s = malloc(n + 1);
    memset(s, c, n);
    s[n] = '\0';
    return s;
}

START_TEST(test_no_buffer_overflow_on_oversized_params)
{
    /* Invariant: action and profile fields must never exceed their declared buffer sizes */
    struct {
        const char *action;
        const char *profile;
    } cases[] = {
        /* exact exploit: 10x oversized strings */
        { "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" },
        /* boundary: exactly one byte over assumed 64-byte field */
        { "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",  /* 65 chars */
          "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" },   /* 65 chars */
        /* valid input: well within bounds */
        { "download", "default" },
    };

    int num_cases = sizeof(cases) / sizeof(cases[0]);

    for (int i = 0; i < num_cases; i++) {
        json_object *jobj = json_object_new_object();
        json_object_object_add(jobj, "action",  json_object_new_string(cases[i].action));
        json_object_object_add(jobj, "profile", json_object_new_string(cases[i].profile));

        const char *json_str = json_object_to_json_string(jobj);

        /* Call the real production parse function; it must not crash or overflow */
        youtubedl_param_t param;
        memset(&param, 0, sizeof(param));

        int ret = youtubedl_parse_param(json_str, &param);

        /* After parsing, the fields must be within their declared sizes */
        ck_assert_msg(strlen(param.action)  < ACTION_BUF_SIZE,
                      "action field overflows its buffer (case %d)", i);
        ck_assert_msg(strlen(param.profile) < PROFILE_BUF_SIZE,
                      "profile field overflows its buffer (case %d)", i);

        json_object_put(jobj);
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_no_buffer_overflow_on_oversized_params);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}