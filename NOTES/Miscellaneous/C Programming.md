## C Basics
### Variables
```C
// Macro variables - aliases for constant values
#define MACRO_SIZE 50
#define PI 3.14159
#define MY_FILE "test.txt"

// Global variables - Accessible everywhere in the current file, stored on heap, static is recommended
static double pi = 3.14;
static int x = 5;

int main(int argc, char** argv){
    // Variables inside functions are local, stored on stack
    // Native Types
    char a = 'a';       // 1 Byte    %c - Integers from 0 to 256 - ASCII Hex Table
    int c = 0;          // 4 Bytes   %d
    float d = 2.22      // 4 Bytes   %f
    double pi = 3.14;   // 8 Bytes   %lf

    // Sizes
    size_t x = 40;                    // 8 Bytes   %zu - Used for allocation sizes and array indexes
    printf("%zu", sizeof(var_here));  // "sizeof()" is used to compute the size of an object

    // Pointers
    int* p = NULL;   // Integer Pointer is initialized to NULL

    *p = 0;          // Pointer holds the value "0"
    p = &x;          // Pointer points to the address of "x"

    p++              // Pointer is first considered, then incremented by 1
    ++p              // Pointer is first incremented by 1, then considered

    // "unsigned" modifier - shifts a variable to positive-only values
    unsigned int x = 5;          // 4 Bytes   %ud
    unsigned double pi = 3.14;   // 8 Bytes   %ug

    // "long" modifier - doubles the size of a variable
    long int x = 1;      // 8 Bytes   %Ld
    long double = 3.14;  // 16 Bytes  %Lf

    // "const" modifier - makes a variable read-only
    const double multiply = 1.51;

    // Type casting - Change variable type at runtime
    double frac = (double)1/2;  // Produces 0.5 instead of 0
}
```

### Arrays
```C
int main(){
    // Static arrays - Constant size - On Stack
    char chache[26] = {0};

    // Dynamic arrays - Variable size - On Heap
    int* arr = malloc([INIT_SIZE] * sizeof(*arr));        // Initial Allocation
    int* arr = realloc(arr, [NEW_SIZE] * sizeof(*arr));   // Re-Allocation to extend space forward, try to avoid if possible by choosing a better initial allocation
    free(arr)                                             // Free after usage is completed
}
```

### Functions
```C
// Value arguments - Modify local copies of variables)
int sum_val(int x, int y){
    int z = x + y;
    return z;
}

// Pointer arguments - Modify variables outside the function call, due to pointers being global
void sum_p(int* x, int* y, int* result){
    *result = *x + *y;
}
```

### User Input
```C
int main(){
    // Numbers
    double a;                                         
    if(!scanf("%lf",&a)) return -1;                    // Read Check

    // Strings - 
    char input[257];                                   
    if(!fgets(buf, sizeof(buf), stdin)) return -1;     // Read Check
    if(strlen(input) >= sizeof(input) - 1) return -1;  // Length Check
    input[strcspn(input, "\r\n")] = 0;                 // Strip "\r" and "\n" bytes
}
```


### CLI Arguments
```C
// Argument style: ./binary --arg1 value1 --arg2 value2
int main(int argc, char** argv){

    // "argc" stores the number of arguments, print usage if it's less than the number of required arguments + 1
    if(argc < 2) printf("Usage: %s --arg1 val1", argv[0]);

    // Iterate over the arguments array "argv", store each value in the corresponding string
    for(int i = 1; i < argc - 1; i++){
        if(!strcmp("--arg1", argv[i]) && !strpbrk(argv[i+1], "--")) printf("%s", argv[i+1]);
        if(!strcmp("--arg2", argv[i]) && !strpbrk(argv[i+1], "--")) printf("%s", argv[i+1]);
    }
    return 0;
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

// Switch - When checking a single variable for more values
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
    char* dynamic = malloc(INIT_LENGTH * sizeof(*dynamic));

    size_t len = get_length();
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

   // Remove a charset from a string
   myString[strcspn(myString, "0123456789")] = 0;

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
   char* out = strncat(A, B, N);

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

## Data Structures
### Structs
Structs are foundational objects to build [data structures](https://en.wikipedia.org/wiki/List_of_data_structures): Tuples, Lists, Trees, Heaps, Queues, Stacks, Graphs, Tries
```C
// Declaration
typedef struct _myStruct {
    int ID;
    int age;
} myStruct, *p_myStruct;

// Access a Struct
myStruct x = { 0 };
x.ID = 15;
x.age = 77;

// Access a Struct Pointer
p_myStruct x = malloc(sizeof(p_myStruct));
x -> ID = 66;
x -> age = 62;
```

## Algorithms
 
### Array Sorting

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
# LD_FLAGS := -L ./lib -l[lib_name]

# GCC Essential Flags
CC= gcc
STDFLAGS := -std=c99 -Wall -Wextra -Wpedantic -Werror -Wmissing-prototypes -Wfloat-equal -Wconversion -fsanitize=address,undefined -Wformat=2 -Wformat-security -O2 -g -march=native

# GCC Floating Optimization Flags
#OPTLAGS := -Ofast -ffloat-store -fexcess-precision=style -ffast-math -fno-rounding-math -fno-signaling-nans -fcx-limited-range -fno-math-errno -funsafe-math-optimizations -fassociative-math -freciprocal-math -ffinite-math-only -fno-signed-zeros -fno-trapping-math -frounding-math -fsingle-precision-constant

# GCC Security Flags (FULL RERLO + NX + PIE + CANARY)
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
