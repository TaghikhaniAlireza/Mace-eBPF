/**
 * Mace-eBPF SDK — C Smoke Test
 *
 * Verifies that the C API is callable and behaves correctly.
 * Compile with:
 *   cc -o target/debug/c_smoke_test examples/c_smoke_test.c \
 *      -L target/debug -lmace_ebpf \
 *      -I include \
 *      -Wl,-rpath,target/debug
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mace.h"

/* ── Test 1: Arena lifecycle ─────────────────────────────── */
static void test_arena_lifecycle(void) {
    MaceArenaHandle *arena = mace_arena_new(16);
    assert(arena != NULL && "mace_arena_new should return non-null");

    mace_arena_free(arena);
    printf("[PASS] test_arena_lifecycle\n");
}

/* ── Test 2: Arena push/pop round-trip ───────────────────── */
static void test_arena_push_pop(void) {
    MaceArenaHandle *arena = mace_arena_new(16);
    assert(arena != NULL);

    RawMemoryEvent event;
    memset(&event, 0, sizeof(event));
    event.tgid = 1234;
    event.timestamp_ns = 9999;
    event.args[0] = 0xDEADBEEF;
    event.args[1] = 64;
    event.syscall_id = 1;

    int push_result = mace_arena_try_push(arena, &event);
    assert(push_result == 0 && "push should succeed");

    RawMemoryEvent out;
    memset(&out, 0, sizeof(out));
    int pop_result = mace_arena_try_pop(arena, &out);
    assert(pop_result == 0 && "pop should succeed");

    assert(out.tgid == 1234);
    assert(out.timestamp_ns == 9999);
    assert(out.args[0] == 0xDEADBEEF);
    assert(out.args[1] == 64);

    mace_arena_free(arena);
    printf("[PASS] test_arena_push_pop\n");
}

/* ── Test 3: Arena pop from empty ────────────────────────── */
static void test_arena_pop_empty(void) {
    MaceArenaHandle *arena = mace_arena_new(4);
    assert(arena != NULL);

    RawMemoryEvent out;
    memset(&out, 0, sizeof(out));
    int result = mace_arena_try_pop(arena, &out);
    assert(result < 0 && "pop from empty should return negative error");

    mace_arena_free(arena);
    printf("[PASS] test_arena_pop_empty\n");
}

/* ── Test 4: Alert channel lifecycle ─────────────────────── */
static void test_alert_channel_lifecycle(void) {
    MaceAlertChannelHandle *ch = mace_alert_channel_new(32);
    assert(ch != NULL && "mace_alert_channel_new should return non-null");

    mace_alert_channel_free(ch);
    printf("[PASS] test_alert_channel_lifecycle\n");
}

/* ── Test 5: Alert channel recv from empty ───────────────── */
static void test_alert_channel_recv_empty(void) {
    MaceAlertChannelHandle *ch = mace_alert_channel_new(32);
    assert(ch != NULL);

    uint8_t buffer[4096];
    int result = mace_alert_channel_try_recv(ch, buffer, sizeof(buffer));
    assert(result == 0 && "recv from empty channel should return 0");

    mace_alert_channel_free(ch);
    printf("[PASS] test_alert_channel_recv_empty\n");
}

/* ── Test 6: Null pointer safety ─────────────────────────── */
static void test_null_safety(void) {
    /* These should not crash */
    mace_arena_free(NULL);
    mace_alert_channel_free(NULL);

    RawMemoryEvent event;
    memset(&event, 0, sizeof(event));
    int r1 = mace_arena_try_push(NULL, &event);
    assert(r1 < 0 && "null handle should return error");

    uint8_t buf[64];
    int r2 = mace_alert_channel_try_recv(NULL, buf, sizeof(buf));
    assert(r2 < 0 && "null handle should return error");

    printf("[PASS] test_null_safety\n");
}

/* ── Main ────────────────────────────────────────────────── */
int main(void) {
    printf("=== Mace-eBPF C Smoke Test ===\n\n");

    test_arena_lifecycle();
    test_arena_push_pop();
    test_arena_pop_empty();
    test_alert_channel_lifecycle();
    test_alert_channel_recv_empty();
    test_null_safety();

    printf("\n[ALL TESTS PASSED]\n");
    return 0;
}
