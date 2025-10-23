.PHONY: all build run clean format

# Build directory
BUILDDIR := build

# Clang-format configuration
CLANG_FORMAT := clang-format
FORMAT_DIRS := src include app
FORMAT_FILES := $(shell find $(FORMAT_DIRS) -type f \( -name "*.c" -o -name "*.h" \))

# Default target
all: build

# Build target
build:
	cmake -B $(BUILDDIR) -S .
	cmake --build $(BUILDDIR)

run:
	sudo ./build/web_server

# Clean target
clean:
	rm -rf $(BUILDDIR)

# Format target
format:
ifndef CLANG_FORMAT
	$(error "clang-format is not installed. Please install it and try again.")
endif
	@echo "Formatting source files in directories: $(FORMAT_DIRS)"
	$(CLANG_FORMAT) -style=file -i $(FORMAT_FILES)
	@echo "All source files have been formatted."
