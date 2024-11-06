CC = gcc

CFLAGS = -Wall -Wextra -I./tools -I./src

SRC_DIR = src
TEST_DIR = test
TOOLS_DIR = tools
ROOT_DIR = .

SRC_FILES = $(SRC_DIR)/aes-128_enc.c $(SRC_DIR)/aes-128_attack.c $(TOOLS_DIR)/tools.c
OBJ_FILES = $(SRC_FILES:.c=.o)

TEST_FILES = $(wildcard $(TEST_DIR)/*.c)
TEST_EXEC = $(patsubst $(TEST_DIR)/%.c, $(ROOT_DIR)/%, $(TEST_FILES))

all: $(TEST_EXEC)

$(TEST_EXEC): $(OBJ_FILES) $(TEST_FILES)
	@for test_file in $(TEST_FILES); do \
		test_exec=$(ROOT_DIR)/$$(basename $$test_file .c); \
		$(CC) $(CFLAGS) -o $$test_exec $(OBJ_FILES) $$test_file; \
	done

clean:
	rm -f $(OBJ_FILES) $(TEST_EXEC)

run: $(TEST_EXEC)
	@for exec in $(TEST_EXEC); do \
		echo "Running $$exec..."; \
		./$$exec; \
	done

.PHONY: all clean run
