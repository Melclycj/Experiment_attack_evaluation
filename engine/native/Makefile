# All outputs must be directed to a fresh Linux-native directory by the runner.
CC = gcc
CFLAGS = -std=c17 -O2 -g -Wall -Wextra -Werror -Wpedantic -fstack-protector-strong -D_FORTIFY_SOURCE=3
CPPFLAGS = -Isandbox
LDFLAGS = -Wl,-z,relro,-z,now

ifndef BUILD_DIR
$(error Set BUILD_DIR to a fresh Linux-native build directory)
endif

.PHONY: all check sandbox
SANDBOX_SRC = sandbox/contract.c sandbox/support.c sandbox/policy.c sandbox/catalog.c sandbox/transport.c sandbox/child.c sandbox/storage.c sandbox/spawner.c
SANDBOX_LIBS = -ljansson -lmd -lseccomp -lcap
all: $(BUILD_DIR)/check-contract $(BUILD_DIR)/probe-handoff
sandbox: $(BUILD_DIR)/w2-cell $(BUILD_DIR)/w2-cell-test $(BUILD_DIR)/w2-catalog $(BUILD_DIR)/w2-recover $(BUILD_DIR)/libw2sandbox.so $(BUILD_DIR)/agent-fixture $(BUILD_DIR)/w2-connector-stub $(BUILD_DIR)/w2-relay $(BUILD_DIR)/w2-frontend-stub $(BUILD_DIR)/check-transport $(BUILD_DIR)/check-kill $(BUILD_DIR)/check-storage $(BUILD_DIR)/check-spawner-state $(BUILD_DIR)/check-recovery $(BUILD_DIR)/check-workspace $(BUILD_DIR)/check-create-cancel $(BUILD_DIR)/check-open-beneath

$(BUILD_DIR)/check-open-beneath: checks/check_open_beneath.c sandbox/support.c sandbox/contract.c $(wildcard sandbox/*.h) | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) checks/check_open_beneath.c sandbox/support.c sandbox/contract.c $(LDFLAGS) -ljansson -lmd -lcap -o "$@"

$(BUILD_DIR)/check-create-cancel: checks/check_create_cancel.c $(SANDBOX_SRC) $(wildcard sandbox/*.h) | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) checks/check_create_cancel.c $(filter-out sandbox/storage.c,$(SANDBOX_SRC)) $(LDFLAGS) -Wl,--wrap=syscall,--wrap=w2_now,--wrap=close,--wrap=fstat $(SANDBOX_LIBS) -o "$@"

$(BUILD_DIR)/check-workspace: checks/check_workspace.c $(SANDBOX_SRC) $(wildcard sandbox/*.h) | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) checks/check_workspace.c $(SANDBOX_SRC) $(LDFLAGS) $(SANDBOX_LIBS) -o "$@"

$(BUILD_DIR)/check-recovery: checks/check_recovery.c $(SANDBOX_SRC) $(wildcard sandbox/*.h) | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) checks/check_recovery.c $(SANDBOX_SRC) $(LDFLAGS) -Wl,--wrap=w2_now,--wrap=fsync,--wrap=fstatvfs $(SANDBOX_LIBS) -o "$@"

$(BUILD_DIR)/check-spawner-state: checks/check_spawner_state.c $(SANDBOX_SRC) $(wildcard sandbox/*.h) | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DW2_TESTING checks/check_spawner_state.c $(filter-out sandbox/spawner.c,$(SANDBOX_SRC)) $(LDFLAGS) $(SANDBOX_LIBS) -o "$@"

$(BUILD_DIR)/check-storage: checks/check_storage.c $(SANDBOX_SRC) $(wildcard sandbox/*.h) | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DW2_TESTING checks/check_storage.c $(SANDBOX_SRC) $(LDFLAGS) $(SANDBOX_LIBS) -o "$@"

$(BUILD_DIR)/w2-recover: sandbox/recover.c $(SANDBOX_SRC) $(wildcard sandbox/*.h) | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) sandbox/recover.c $(SANDBOX_SRC) $(LDFLAGS) $(SANDBOX_LIBS) -o "$@"

$(BUILD_DIR)/w2-catalog: sandbox/catalog_tool.c $(SANDBOX_SRC) $(wildcard sandbox/*.h) | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) sandbox/catalog_tool.c $(SANDBOX_SRC) $(LDFLAGS) $(SANDBOX_LIBS) -o "$@"

$(BUILD_DIR)/check-transport: checks/check_transport.c sandbox/transport.c sandbox/support.c sandbox/contract.c $(wildcard sandbox/*.h) | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) checks/check_transport.c sandbox/transport.c sandbox/support.c sandbox/contract.c $(LDFLAGS) -Wl,--wrap=recvmsg,--wrap=w2_now -ljansson -lmd -lcap -o "$@"

$(BUILD_DIR)/check-kill: checks/check_kill.c sandbox/support.c sandbox/contract.c $(wildcard sandbox/*.h) | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) checks/check_kill.c sandbox/support.c sandbox/contract.c $(LDFLAGS) -ljansson -lmd -lcap -o "$@"

$(BUILD_DIR)/w2-cell: sandbox/cell.c $(SANDBOX_SRC) $(wildcard sandbox/*.h) | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) sandbox/cell.c $(SANDBOX_SRC) $(LDFLAGS) $(SANDBOX_LIBS) -o "$@"

$(BUILD_DIR)/w2-cell-test: sandbox/cell.c $(SANDBOX_SRC) $(wildcard sandbox/*.h) | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DW2_TESTING sandbox/cell.c $(SANDBOX_SRC) $(LDFLAGS) $(SANDBOX_LIBS) -o "$@"

$(BUILD_DIR)/libw2sandbox.so: $(SANDBOX_SRC) $(wildcard sandbox/*.h) | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -fPIC -shared $(SANDBOX_SRC) $(LDFLAGS) $(SANDBOX_LIBS) -o "$@"

$(BUILD_DIR)/agent-fixture: checks/agent_fixture.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -static checks/agent_fixture.c -pthread -o "$@"

$(BUILD_DIR)/w2-connector-stub: checks/connector_stub.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -static checks/connector_stub.c -o "$@"

$(BUILD_DIR)/w2-relay: ../relay/relay.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -static ../relay/relay.c -o "$@"

$(BUILD_DIR)/w2-frontend-stub: checks/frontend_stub.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -static checks/frontend_stub.c -o "$@"

$(BUILD_DIR):
	mkdir -p "$(BUILD_DIR)"

$(BUILD_DIR)/check-contract: checks/check_contract.c sandbox/contract.c sandbox/contract.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) checks/check_contract.c sandbox/contract.c $(LDFLAGS) -o "$@"

$(BUILD_DIR)/probe-handoff: checks/probe_handoff.c sandbox/contract.c sandbox/contract.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) checks/probe_handoff.c sandbox/contract.c $(LDFLAGS) -o "$@"

check: all
	"$(BUILD_DIR)/check-contract"
	/usr/bin/python3 checks/check_sources.py "$(BUILD_DIR)/check-contract"
	"$(BUILD_DIR)/probe-handoff"
