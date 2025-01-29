## C Basics
### Variables & Pointers
```C
// Macro variables - aliases for constant values
#define MACRO_SIZE 50
#define PI 3.14159
#define MY_FILE "test.txt"

// Global variables - Accessible everywhere in the current file, stored on heap
static double pi = 3.14;
static int x = 5;

int main(){
    // Variables inside functions are local, stored on stack
    // Native Types
    char a = 'a';       // 1 Byte    %c  (They map to integers from 0 to 256 - ASCII Table)
    int c = 0;          // 4 Bytes   %d
    double pi = 3.14;   // 8 Bytes   %f
    size_t x = 40;      // 8 Bytes   %zu (Used for allocation sizes and array indexes)

    // "unsigned" modifier - shifts a variable to positive-only values
    unsigned int x = 5;          // 4 Bytes   %ud
    unsigned double pi = 3.14;   // 8 Bytes   %ug

    // "long" modifier - doubles the size of a variable
    long int x = 1;      // 8 Bytes
    long double = 3.14;  // 16 Bytes

    // "const" modifier - makes a variable read-only
    const double multiply = 1.51;

    // Pointers - memory addresses of variables, global and stored on heap
    int* p = NULL;   // Integer Pointer is initialized to NULL

    *p = 0;          // Pointer holds the value "0"
    p = &x;          // Pointer points to the address of "x"

    p++              // Pointer is first considered, then incremented by 1
    ++p              // Pointer is first incremented by 1, then considered
}
```

### Functions
```C
// Value arguments (modify local copies of variables)
int sum_val(int x, int y){
    int z = x + y;
    return z;
}

// Reference arguments (modify variables outside the function call, due to pointers being global)
void sum_p(int* x, int* y, int* result){
    *result = *x + *y;
}
```

### Arrays
```C
// Static arrays - Constant size - On Stack
char chache[26] = {0};

// Dynamic arrays - Variable size - On Heap
int* arr = malloc([INIT_SIZE] * sizeof(*arr));        // Initial Allocation
int* arr = realloc(arr, [NEW_SIZE] * sizeof(*arr));   // Re-Allocation to extend space forward
free(arr)                                             // Free after usage is completed
```


### Loops
```C
// For
for(var_init; condition; var_update){
}

// Do-While
do {
  // Code executing Once
} while(condition);
```

### Conditions
```C
// Ternary assignment
x = (condition) ? value_if_true : value_if_false;

// If-Else
if(condition){
} else if(condition_2) {
} else {
}

// Switch (When checking a single variable for more values)
switch(variable){
  case value_1:
  case value_2:
  default:
}

```

### Strings
- Arrays of chars terminated with `'\0'`
- Full UTF-32 support with `uchar.h` + "char32_t" type
- Library: `<string.h>`
```C
void main(){
    // Fixed, On Stack
    char* str = "Hello world!";
    while(*str){
	printf("%c", *str++);
    }

    // Dynamic, On Heap
    size_t len = get_length();
    char* dynamic = malloc(len);

    for(size_t i = 0; i < len; i++){
        dynamic[i] = 'b';
    }
    dynamic[len] = '\0';

   // Convert character to uppercase / lowercase
   myChar &= '_';
   myChar |= ' ';

   // Get length of a string
   size_t len = strlen(myString);

   // Check if two strings are equal
   if(!strcmp(str1, str2));

   // Slice portion of a string
   char* sliced = malloc(chars_number);
   strncpy(sliced, &myString[start_index], chars_number);

   // Create writable copy of a constant string
   const char* input = "hello";
   char* cp_input = strdup(input);

   // Find char/charset/substring occurrences
   if(strchr(input, 'a'));
   if(strpbrk(input, "0123456789"));
   if(strstr(input, "substring"));

   // Concatenate N chars of string B with string A
   char* A = "hello";
   char* B = " world";
   strncat(a, b, N);

   // Convert digit string to integer
   const char* test = "1234";
   int conv_test = atoi(test);

   // Generate a sub-string by iteration
   for(char* q = subString; *myString; myString++){
      ...
      q++;
   }

   // Create a formatted string
   char* format_string;
   asprintf(&format_string, "%d %d", x, y);

   // Parse a formatted string (integers)
   const char* format = "1_2_4";
   while(*format){
       int next, parsed;
       sscanf(strnum, "%d_%n", &parsed, &n);
       printf("%d\n", parsed);
       strnum += next;
   }

  // Parse a formatted string (strings)
  const char* format = "I_Love_C_Programming";
  for(char* substr = strtok(strdup(format), "_"); substr; substr=strtok(NULL, "_")){
    printf("%s\n", substr);
  }
}
```
### File Handling
File can be handled in C using the `FILE` pointer handler
```C
// Open/Create a local File
FILE* fptr = fopen("path/to/file.txt", "a+");

// Write to file
fprintf(fptr, "Some text");

// Read file line-by-line
char* line = NULL;
size_t len = 0;
while((getline(&line, &len, fptr) != -1)) {
    printf("%s", line);
}

// Close a file
fclose(fptr);
```

### Structs
Structs can be used to build complex data structures, like heaps, trees, lists, queues, stacks, graphs, tries
```C
// Declaration
typedef struct _mystruct {
    int ID;
    int age;
} mystruct, *p_mystruct;

// Accessing an element of a struct
mystruct str = { 0 };
str.ID = 15;
str.age = 77;

// Accessing an element of a struct pointer
p_mystruct p_struct = NULL;
p_struct -> ID = 66;
p_struct -> age = 62;
```

## Algorithms
 
### Sorting

Sorting integers/strings arrays in C is done using `qsort()`, with `O(n*log(n))` average time complexity, this is the fastest algorithm in practice for most real-world data, and it contains numerous optimization that makes it faster than most manual implementations
```C
// Sorting integers (similar for doubles)
int compare_int(const void * a, const void * b){
    return ( *(int*)a - *(int*)b );
}
qsort(int_array, length, sizeof(int), compare_int);

// Sorting strings
// - By Alphabet
qsort(str_array, length, sizeof(char*), strcmp);

// - By Length
int compare_len(const void* a, const void* b){
    return strcmp(*(const char**)a, *(const char**)b); 
}
qsort(str_array, length, sizeof(char*), compare_len);

```

### Hash Lookups

Allows to cache data in an array while iterating over some structure, saving time complexity. Useful to solve unique property lookups, or frequency counting problems, simple examples are shown
```C
// Hashing chars
[TYPE] cache[256] = { 0 };

// Hashing integers (<sys/mman.h>)
uint32_t HASH_SZ = [SOME_SIZE_HERE];
[TYPE]* cache_space = mmap(NULL, HASH_SZ, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
[TYPE]* cache = &cache_space[STARTING_INDEX];

// Hashing strings - No Collisions Assumed (<sys/mman.h> + "murmurhash.h")
uint32_t hash(char* input){
    uint32_t seed = 1406483717;
    uint32_t hash_val = murmurhash(input, (uint32_t)strlen(input), seed);
    return hash_val;
}

int main(){
    char* myString = "Hello World!";

    uint32_t HASH_SZ = [SOME_SIZE_HERE];
    [TYPE]* cache_space = mmap(NULL, HASH_SZ, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    [TYPE]* cache = &cache_space[0];

    uint32_t key = hash(myString) % HASH_SZ;
}
```

## C Projects

- Directory tree
    - `src/`
        - `main.c` -> Contains the `main()` function, libraries & headers inclusions
        - `func.c` -> Contains user and non-standard library functions used in `main.c`, always includes its own header `func.h`.
        
    - `include/`
        - `func.h` -> Contains function prototypes of `func.c` and an include guard
        
    - `lib/`
        - `user_lib.c` -> Contains user-library functions
        - `user_lib.so` -> Corresponding SO file -> Generate with `gcc -shared -o user_lib.so -fPIC user_lib.c`
     

        #### **`main.c`**
        ```C
        // Library inclusions
        #include <stdio.h>
        #include <stdlib.h>
        #include <my_user_lib.h>
        
        // Header Files
        #include "func.h"
        
        int main(int argc, char** argv){
            return 0;
        }
        ```

        #### **`func.c`**
        ```C
        #include "func.h"
        
        int sum(int x, int y){
            return x + y;
        }
        ```
        
        #### **`func.h`**
        ```C
        #ifndef FUNC_H
        #define FUNC_H
        
        int sum(int x, int y);
        #endif
        ```

- Makefile Compilation
```Makefile
# Binary output settings
TARGET_EXEC := binary
BUILD_DIR := ./build

# Source & Header Inclusions Directories
SRC_DIRS := ./src
INCLUDE_FLAGS := -I ./include

# External Libraries
# LD_FLAGS := -L ./lib -l[lib_name] -pg -fopenmp

# C99 Standard Flags
CC= gcc
STDFLAGS := -Wall -Wextra -Wpedantic -Wformat -Wformat-security -Werror -std=c99 -fsanitize=leak

#GCC Extra Flags (Profiling / Optimizations / Security)
#DBGLAGS := -pg -Og
#OPTFLAGS := -O3 -fno-math-errno -fno-trapping-math -flto -mtune=native -fopenmp
#SECFLAGS := -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wl,-z,separate-code -fPIE -pie -fstack-protector-strong

# --- BUILD PROCESS --- #
SRCS := $(shell find $(SRC_DIRS) -name '*.c')
OBJS := $(SRCS:%=$(BUILD_DIR)/%.o)
DEPS := $(OBJS:.o=.d)

$(BUILD_DIR)/$(TARGET_EXEC): $(OBJS); $(CC) $(OBJS) -o $@ $(LD_FLAGS)

$(BUILD_DIR)/%.c.o: %.c; mkdir -p $(dir $@); $(CC) $(CFLAGS) $(STDFLAGS) $(OPTFLAGS) $(SECFLAGS) $(INCLUDE_FLAGS) -c $< -o $@

-include $(DEPS)
# --------------------- #
```
