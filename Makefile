CWD = $(shell pwd)
YASM_DIR = $(CWD)/../yasm

main: main.o $(YASM_DIR)/libyasmstd.a $(YASM_DIR)/libyasm.a
	${CXX} -o $@ $^

main-shared: main.o $(YASM_DIR)/build/libyasm.so $(YASM_DIR)/build/libyasmstd.so
	${CXX} -o $@ $< -lyasm -lyasmstd -L$(YASM_DIR)/build/

%.o: %.cpp
	${CXX} -o $@ $< -c -Wall -Wextra -Wpedantic -I$(YASM_DIR) -I$(YASM_DIR)/build

%.o: %.c $(YASM_DIR)/libyasm.a
	${CC} -o $@ $^ -Wall -Wextra -Wpedantic -I$(YASM_DIR)

assembled.o: main
	./$<

assembled: assembled.o
	ld $< -o $@
