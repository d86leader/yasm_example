CWD = $(shell pwd)
YASM_DIR = $(CWD)/../yasm

main: main.o $(YASM_DIR)/libyasm.a
	${CXX} -o $@ $^

main-shared: main.o
	${CXX} -o $@ $< -lyasm -L$(YASM_DIR)/build/

%.o: %.cpp
	${CXX} -o $@ $< -c -Wall -Wextra -Wpedantic -I$(YASM_DIR)

%.o: %.c $(YASM_DIR)/libyasm.a
	${CC} -o $@ $^ -Wall -Wextra -Wpedantic -I$(YASM_DIR)
