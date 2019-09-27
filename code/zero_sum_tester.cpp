// Compile with:
// g++ -std=c++0x -g -O2 -funroll-loops -march=native -mtune=native zero_sum_tester.cpp -o zero_sum_tester -lcrypto -lm
#include <cmath> // log2(.)
#include <cstring> // memcpy
#include <iostream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <algorithm>
#include <set>
#include <openssl/rand.h> // For RAND_bytes(.)

#define WORDSIZE 64

#define VERBOSE

#define deg(x) (uint32)floor(log2((double)x))
#define SBOX_DEGREE 3
#define SBOX_DEGREE_NUM_SQUARINGS (uint32)(log2(SBOX_DEGREE))
//#define REDUCE_DEGREE_TWICE // Used for degrees 2^n - 1 (e.g., goes from x^9 to x^7)

typedef unsigned short uint16;
typedef unsigned int uint32;
typedef unsigned long uint64;
typedef __uint128_t uint128;
typedef unsigned char uchar;
typedef uint64 word;
typedef uint128 doubleword;

// Globals
void (*bf_add)(word* c, word* a, word* b);
void (*bf_mul)(word* c, word* a, word* b);
//void (*bf_sbox)(word* c, word* a);
void (*cipher)(word* in, word* out, word* round_keys, word* round_constants, uint32 num_rounds, uint32 n, uint32 t, uchar* data);
doubleword irred_poly = 0;

void print_hex(void* source, uint32 num_bytes) {
  // TEMP
  uchar* pointer = (uchar*)source;
  for(uint32 i = 0; i < num_bytes; i++) {
    std::cout << std::setfill('0') << std::setw(2) << std::hex << (uint32)(pointer[num_bytes - i - 1]);
  }
  std::cout << std::dec << std::endl;
}

std::string to_string_hex(void* source, uint32 num_bytes) {
  uchar* pointer = (uchar*)source;
  std::ostringstream string_stream;
  for(uint32 i = 0; i < num_bytes; i++) {
    string_stream << std::setfill('0') << std::setw(2) << std::hex << (uint32)(pointer[num_bytes - i - 1]);
  }
  std::string ret_string = string_stream.str();
  return ret_string;
}

std::string to_string_binary(void* source, uint32 num_bytes) {
  uchar* pointer = (uchar*)source;
  std::ostringstream string_stream;
  for(uint32 i = 0; i < num_bytes; i++) {
    for(uint32 j = 0; j < 8; j++) {
      string_stream << (((uint32)(pointer[num_bytes - i - 1]) >> (7 - j)) & 0x1);
    }
  }
  std::string ret_string = string_stream.str();
  return ret_string;
}

void bf_add_generic(word* c, word* a, word* b) {
  c[0] = a[0] ^ b[0];
}

void bf_inverse(word* c_inv, word* c) {
  doubleword u = *c;
  doubleword v = irred_poly;
  doubleword g1 = 1;
  doubleword g2 = 0;
  int j = 0;
  doubleword tmp = 0;
  if(*c == 0) {
    *c_inv = 0;
    return;
  }
  while(deg(u) != 0) {
  //while(u != 1) {
    j = deg(u) - deg(v);
    if(j < 0) {
      tmp = u;
      u = v;
      v = tmp;
      tmp = g1;
      g1 = g2;
      g2 = tmp;
      j = -j;
    }
    u = u ^ (v << j);
    g1 = g1 ^ (g2 << j);
  }
  *c_inv = (word)(g1);
}

void bf_3_add(word* c, word* a, word* b) {
  c[0] = a[0] ^ b[0];
}

inline void bf_3_mul(word* c, word* a, word* b) {
  doubleword r = 0;
  asm("pclmulqdq %2, %1, %0;"
    : "=x"(r)
    : "x"(a[0]), "i"(0), "0"(b[0])
    );
  
  // Irred poly: x^3 + x + 1
  word c0 = r & 0x7; // LS 3 bits
  word c1 = (r & 0x18) >> 3; // MS 2 bits

  // Add c1 to bits 1 and 0 of c0 (c1 doesn't neet to be done first, because it's not affected)
  *c = c0 ^ (c1 << 1) ^ c1;

  //std::cout << "a * b = " << *a << " * " << *b << " = " << *c << std::endl;
}

inline void bf_3_cube(word* c, word* a) {
  word t1 = 0;
  word t2 = 0;
  bf_3_mul(&t1, a, a);
  bf_3_mul(&t2, &t1, a);
  *c = t2;
}

void bf_5_add(word* c, word* a, word* b) {
  c[0] = a[0] ^ b[0];
}

inline void bf_5_mul(word* c, word* a, word* b) {
  doubleword r = 0;
  asm("pclmulqdq %2, %1, %0;"
    : "=x"(r)
    : "x"(a[0]), "i"(0), "0"(b[0])
    );
  
  // Irred poly: x^5 + x^2 + 1
  word c0 = r & 0x1F; // LS 5 bits
  word c1 = r >> 5; // MS 4 bits

  c1 = c1 ^ (c1 >> 3);
  c0 = c0 ^ (c1 << 2) ^ c1;

  // Build result
  *c = c0 & 0x1F;
}

inline void bf_5_cube(word* c, word* a) {
  word t1 = 0;
  word t2 = 0;
  bf_5_mul(&t1, a, a);
  bf_5_mul(&t2, &t1, a);
  *c = t2;
}

void bf_7_add(word* c, word* a, word* b) {
  c[0] = a[0] ^ b[0];
}

inline void bf_7_mul(word* c, word* a, word* b) {
  doubleword r = 0;
  asm("pclmulqdq %2, %1, %0;"
    : "=x"(r)
    : "x"(a[0]), "i"(0), "0"(b[0])
    );
  
  // Irred poly: x^7 + x + 1
  word c0 = r & 0x7F; // LS 7 bits
  word c1 = r >> 7; // MS 6 bits

  c1 = c1 ^ (c1 >> 6);
  c0 = c0 ^ (c1 << 1) ^ c1;

  // Build result
  *c = c0 & 0x7F;
}

inline void bf_7_cube(word* c, word* a) {
  word t1 = 0;
  word t2 = 0;
  bf_7_mul(&t1, a, a);
  bf_7_mul(&t2, &t1, a);
  *c = t2;
}

void bf_9_add(word* c, word* a, word* b) {
  c[0] = a[0] ^ b[0];
}

inline void bf_9_mul(word* c, word* a, word* b) {
  doubleword r = 0;
  asm("pclmulqdq %2, %1, %0;"
    : "=x"(r)
    : "x"(a[0]), "i"(0), "0"(b[0])
    );
  
  // Irred poly: x^9 + x + 1
  word c0 = r & 0x1FF; // LS 9 bits
  word c1 = r >> 9; // MS 8 bits

  c1 = c1 ^ (c1 >> 8);
  c0 = c0 ^ (c1 << 1) ^ c1;

  // Build result
  *c = c0 & 0x1FF;
}

inline void bf_9_cube(word* c, word* a) {
  word t1 = 0;
  word t2 = 0;
  bf_9_mul(&t1, a, a);
  bf_9_mul(&t2, &t1, a);
  *c = t2;
}

void bf_11_add(word* c, word* a, word* b) {
  c[0] = a[0] ^ b[0];
}

inline void bf_11_mul(word* c, word* a, word* b) {
  doubleword r = 0;
  asm("pclmulqdq %2, %1, %0;"
    : "=x"(r)
    : "x"(a[0]), "i"(0), "0"(b[0])
    );

  // Irred poly: x^11 + x^2 + 1
  word c0 = r & 0x7FF; // LS 11 bits
  word c1 = r >> 11; // MS 10 bits

  c1 = c1 ^ (c1 >> 9);
  c0 = c0 ^ (c1 << 2) ^ c1;

  // Build result
  *c = c0 & 0x7FF;
}

inline void bf_11_cube(word* c, word* a) {
  word t1 = 0;
  word t2 = 0;
  bf_11_mul(&t1, a, a);
  bf_11_mul(&t2, &t1, a);
  *c = t2;
}

void bf_13_add(word* c, word* a, word* b) {
  c[0] = a[0] ^ b[0];
}

inline void bf_13_mul(word* c, word* a, word* b) {
  doubleword r = 0;
  asm("pclmulqdq %2, %1, %0;"
    : "=x"(r)
    : "x"(a[0]), "i"(0), "0"(b[0])
    );

  // Irred poly: x^13 + x^4 + x^3 + x + 1
  word c0 = r & 0x1FFF; // LS 13 bits
  word c1 = r >> 13; // MS 12 bits

  c1 = c1 ^ (c1 >> 9) ^ (c1 >> 10) ^ (c1 >> 12);
  c0 = c0 ^ (c1 << 4) ^ (c1 << 3) ^ (c1 << 1) ^ c1;

  // Build result
  *c = c0 & 0x1FFF;
}

inline void bf_13_cube(word* c, word* a) {
  word t1 = 0;
  word t2 = 0;
  bf_13_mul(&t1, a, a);
  bf_13_mul(&t2, &t1, a);
  *c = t2;
}

void bf_15_add(word* c, word* a, word* b) {
  c[0] = a[0] ^ b[0];
}

inline void bf_15_mul(word* c, word* a, word* b) {
  doubleword r = 0;
  asm("pclmulqdq %2, %1, %0;"
    : "=x"(r)
    : "x"(a[0]), "i"(0), "0"(b[0])
    );

  // Irred poly: x^15 + x + 1
  word c0 = r & 0x7FFF; // LS 15 bits
  word c1 = r >> 15; // MS 14 bits

  c1 = c1 ^ (c1 >> 14);
  c0 = c0 ^ (c1 << 1) ^ c1;

  // Build result
  *c = c0 & 0x7FFF;
}

inline void bf_15_cube(word* c, word* a) {
  word t1 = 0;
  word t2 = 0;
  bf_15_mul(&t1, a, a);
  bf_15_mul(&t2, &t1, a);
  *c = t2;
}

void bf_17_add(word* c, word* a, word* b) {
  c[0] = a[0] ^ b[0];
}

inline void bf_17_mul(word* c, word* a, word* b) {
  doubleword r = 0;
  asm("pclmulqdq %2, %1, %0;"
    : "=x"(r)
    : "x"(a[0]), "i"(0), "0"(b[0])
    );

  // Irred poly: x^17 + x^3 + 1
  word c0 = r & 0x1FFFF; // LS 17 bits
  word c1 = r >> 17; // MS 16 bits
  
  c1 = c1 ^ (c1 >> 14);
  c0 = c0 ^ (c1 << 3) ^ c1;
  
  // Build result
  *c = c0 & 0x1FFFF;
}

inline void bf_17_cube(word* c, word* a) {
  word t1 = 0;
  word t2 = 0;
  bf_17_mul(&t1, a, a);
  bf_17_mul(&t2, &t1, a);
  *c = t2;
}

void bf_19_add(word* c, word* a, word* b) {
  c[0] = a[0] ^ b[0];
}

inline void bf_19_mul(word* c, word* a, word* b) {
  doubleword r = 0;
  asm("pclmulqdq %2, %1, %0;"
    : "=x"(r)
    : "x"(a[0]), "i"(0), "0"(b[0])
    );

  // Irred poly: x^19 + x^5 + x^2 + x + 1
  word c0 = r & 0x7FFFF; // LS 19 bits
  word c1 = r >> 19; // MS 18 bits
  
  c1 = c1 ^ (c1 >> 14) ^ (c1 >> 17) ^ (c1 >> 18);
  c0 = c0 ^ (c1 << 5) ^ (c1 << 2) ^ (c1 << 1) ^ c1;
  
  // Build result
  *c = c0 & 0x7FFFF;
}

inline void bf_19_cube(word* c, word* a) {
  word t1 = 0;
  word t2 = 0;
  bf_19_mul(&t1, a, a);
  bf_19_mul(&t2, &t1, a);
  *c = t2;
}

void bf_32_add(word* c, word* a, word* b) {
  c[0] = a[0] ^ b[0];
}

inline void bf_32_mul(word* c, word* a, word* b) {
  doubleword r = 0;
  asm("pclmulqdq %2, %1, %0;"
    : "=x"(r)
    : "x"(a[0]), "i"(0), "0"(b[0])
    );
  
  // Irred poly: x^32 + x^7 + x^3 + x^2 + 1
  word c0 = r & 0xFFFFFFFF; // LS 32 bits
  word c1 = r >> 32; // MS 31 bits

  word T = c1;
  c1 = c1 ^ (T >> 25) ^ (T >> 29) ^ (T >> 30); // 25 = 32 - 7, 29 = 32 - 3, 30 = 32 - 2, x^0 does not affect c1
  T = c1;
  *c = c0 ^ ((T << 7) & 0xFFFFFFFF) ^ ((T << 3) & 0xFFFFFFFF) ^ ((T << 2) & 0xFFFFFFFF) ^ T; // = c0, for x^6, x^3, x^1, x^0
}

inline void bf_32_cube(word* c, word* a) {
  word t1 = 0;
  word t2 = 0;
  bf_32_mul(&t1, a, a);
  bf_32_mul(&t2, &t1, a);
  *c = t2;
}

void bf_33_add(word* c, word* a, word* b) {
  c[0] = a[0] ^ b[0];
}

inline void bf_33_mul(word* c, word* a, word* b) {
  doubleword r = 0;
  asm("pclmulqdq %2, %1, %0;"
    : "=x"(r)
    : "x"(a[0]), "i"(0), "0"(b[0])
    );

  // Irred poly: x^33 + x^6 + x^3 + x + 1
  word c0 = r & 0x1FFFFFFFF; // LS 33 bits
  word c1 = r >> 33; // MS 32 bits

  word T = c1;
  c1 = c1 ^ (T >> 27) ^ (T >> 30); // 27 = 33 - 6, 30 = 33 - 3, 32 = 33 - 1 (omitted, all zeros), x^0 does not affect c1
  T = c1;
  *c = c0 ^ ((T << 6) & 0x1FFFFFFFF) ^ ((T << 3) & 0x1FFFFFFFF) ^ ((T << 1) & 0x1FFFFFFFF) ^ T; // = c0, for x^6, x^3, x^1, x^0
}

inline void bf_33_cube(word* c, word* a) {
  word t1 = 0;
  word t2 = 0;
  bf_33_mul(&t1, a, a);
  bf_33_mul(&t2, &t1, a);
  *c = t2;
}

inline void bf_sbox(word* c, word* a) {
  word t1 = 0;
  // word tmp = 0;
  // bf_mul(&tmp, a, a);
  // bf_mul(&tmp, &tmp, a);
  // bf_mul(&tmp, &tmp, a);
  // bf_mul(&tmp, &tmp, a);
  // bf_mul(&tmp, &tmp, a);
  // bf_mul(&tmp, &tmp, a);
  // std::cout << "T1: " << to_string_hex(&tmp, 4) << std::endl;
  //*c = tmp;
  //return;
  // Squarings
  //std::cout << "number of squarings: " << SBOX_DEGREE_NUM_SQUARINGS << std::endl;
  //std::cout << "a: " << *a << std::endl;
  bf_mul(&t1, a, a);
  for(uint32 i = 0; i < SBOX_DEGREE_NUM_SQUARINGS - 1; i++) {
    bf_mul(&t1, &t1, &t1);
  }
  // Final multiplication with original a
  bf_mul(&t1, &t1, a);
  //std::cout << "c: " << *c << std::endl;

  #ifndef REDUCE_DEGREE_TWICE
  *c = t1;
  #endif
  #ifdef REDUCE_DEGREE_TWICE
  // Goes from degree 2^n + 1 to degree 2^n - 1
  // Calculate inverse of original a
  word temp = 0;
  bf_inverse(&temp, a);
  // Square inverse
  bf_mul(&temp, &temp, &temp);
  // Multiply previous result with square of the inverse
  bf_mul(&temp, &t1, &temp);
  *c = temp;
  #endif
  //std::cout << "T2: " << to_string_hex(c, 4) << std::endl;
}

inline void bf_sbox_test(word* c, word* a) {

  word temp;
  bf_sbox(&temp, a);

  word t1 = 0;
  bf_mul(&t1, a, a);
  bf_mul(&t1, &t1, a);
  bf_mul(&t1, &t1, a);
  bf_mul(&t1, &t1, a);
  bf_mul(&t1, &t1, a);
  bf_mul(&t1, &t1, a);
  bf_mul(&t1, &t1, a);
  bf_mul(&t1, &t1, a);
  bf_mul(&t1, &t1, a);
  bf_mul(&t1, &t1, a);
  bf_mul(&t1, &t1, a);
  bf_mul(&t1, &t1, a);
  bf_mul(&t1, &t1, a);
  bf_mul(&t1, &t1, a);
  *c = t1;

  std::cout << "Test 1: " << to_string_hex(&temp, 4) << std::endl;
  std::cout << "Test 2: " << to_string_hex(c, 4) << std::endl;
}

void get_cofactor(void* matrix, void* temp, int p, int q, uint32 t, uint32 t_orig) { 
  word (*matrix_ptr)[t_orig] = (word (*)[t_orig]) matrix;
  word (*temp_ptr)[t_orig] = (word (*)[t_orig]) temp;
  uint32 i = 0;
  uint32 j = 0;

  // Looping for each element of the matrix
  for(uint32 row = 0; row < t; row++) {
    for(uint32 col = 0; col < t; col++) {
      // Copying into temporary matrix only those element
      // which are not in given row and column
      if(row != p && col != q) {
        temp_ptr[i][j++] = matrix_ptr[row][col];

        // Row is filled, so increase row index and reset col index
        if(j == t - 1) {
          i++;
          j = 0;
        }
      }
    }
  }
}

int matrix_determinant(void* matrix, uint32 t, uint32 t_orig) {
  word (*matrix_ptr)[t_orig] = (word (*)[t_orig]) matrix;
  int D = 0;

  // Catch if single argument
  if(t == 1) {
    return matrix_ptr[0][0];
  }

  word temp[t_orig][t_orig]; // To store cofactors 
  memset(temp, 0x0, sizeof(word) * t_orig * t_orig);

  int sign = 1; // To store sign multiplier 

  // Iterate for each element of first row 
  for(uint32 i = 0; i < t; i++) { 
    // Getting Cofactor of mat[0][i] 
    get_cofactor(matrix, (void*)temp, 0, i, t, t_orig); 
    D += sign * matrix_ptr[0][i] * matrix_determinant((void*)temp, t - 1, t_orig); 

    // Alternate sign 
    sign = -sign; 
  } 

  return D; 
} 
  
bool is_matrix_invertible(void* matrix, uint32 t) { 
    if(matrix_determinant(matrix, t, t) != 0) 
      return true; 
    else
      return false; 
}

void print_matrix(void* matrix, uint32 n, uint32 t) {
  word (*matrix_ptr)[t] = (word (*)[t]) matrix;
  for(uint32 i = 0; i < t; i++) {
    for(uint32 j = 0; j < t; j++) {
      std::cout << "0x" << to_string_hex(&(matrix_ptr[i][j]), ceil(((float)n / WORDSIZE) * 8)) << "   ";
    }
    std::cout << std::endl;
  }
}

void init_2x2_mds_matrix(void* matrix, uint32 add) {
  uint32 t = 2;
  word (*matrix_ptr)[t] = (word (*)[t]) matrix;
  for(uint32 i = 0; i < t; i++) {
    for(uint32 j = 0; j < t; j++) {
      if(i == j) {
        matrix_ptr[i][j] = 0x1 + add;
      }
      else {
        matrix_ptr[i][j] = 0x2 + add;
      }
    }
  }
}

void init_mds_matrix(void* matrix, uint32 n, uint32 t, uint32 start) {

  word (*matrix_ptr)[t] = (word (*)[t]) matrix;

  if(t == 2) {
    init_2x2_mds_matrix(matrix, start);
  }
  else {
    // This algorithm builds a Cauchy matrix, which is MDS (and every submatrix of it is also MDS)
    // Notes: To adjust this algorithm to different field sizes (in particular field sizes with more than 64 bits), some things have to be changed
    bool hilbert = false;

    // Condition: x_i + y_j != 0 for all i = 1 .. t and j = 1 .. t
    // Create pairwise distinct elements x_1, ..., x_t and y_1, ..., y_t
    word xs[t];
    word ys[t];
    memset(xs, 0x0, t * sizeof(word));
    memset(ys, 0x0, t * sizeof(word));
    for(uint32 i = 0; i < t; i++) {
      xs[i] = start + i;
      ys[i] = start + t + i;
    }

    // Create matrix by building field inverses a_ij = 1 / x_i + y_j
    word tmp = 0;
    for(uint32 i = 0; i < t; i++) {
      for(uint32 j = 0; j < t; j++) {
        //bf_add(&tmp, &(xs[i]), &(ys[j]));
        if(hilbert == true) {
          tmp = (i + 1) ^ (j + 1) ^ 1;
        }
        else {
          bf_add_generic(&tmp, &(xs[i]), &(ys[j]));
        }
        bf_inverse(&tmp, &tmp);
        matrix_ptr[i][j] = tmp;
      }
    }
  }

  // Print out matrix
  #ifdef VERBOSE
  std::cout << "MDS matrix:" << std::endl;
  for(uint32 i = 0; i < t; i++) {
    for(uint32 j = 0; j < t; j++) {
      std::cout << "0x" << to_string_hex(&(matrix_ptr[i][j]), ceil(((float)n / WORDSIZE) * 8)) << "   ";
    }
    std::cout << std::endl;
  }
  #endif
  
}

void init_random_invertible_matrix(void* matrix, uint32 n, uint32 t) {
  word (*matrix_ptr)[t] = (word (*)[t]) matrix;
  uint32 branch_size = ceil(((float)n / WORDSIZE) * 8);
  uint32 word_unused_bits = (WORDSIZE - (n % WORDSIZE)) % WORDSIZE;
  uint64 used_mask = 0xFFFFFFFFFFFFFFFF >> word_unused_bits;

  bool invertible = false;
  while(invertible == false) {
    for(uint32 i = 0; i < t; i++) {
      for(uint32 j = 0; j < t; j++) {
        RAND_bytes((uchar*)&(matrix_ptr[i][j]), branch_size);
        matrix_ptr[i][j] = matrix_ptr[i][j] & used_mask;
      }
    }
    invertible = is_matrix_invertible(matrix, t);
  }

  // Print out matrix
  #ifdef VERBOSE
  std::cout << "Random matrix:" << std::endl;
  for(uint32 i = 0; i < t; i++) {
    for(uint32 j = 0; j < t; j++) {
      std::cout << "0x" << to_string_hex(&(matrix_ptr[i][j]), ceil(((float)n / WORDSIZE) * 8)) << "   ";
    }
    std::cout << std::endl;
  }
  #endif

}

void init_weak_invertible_matrix(void* matrix, uint32 n, uint32 t) {
  word (*matrix_ptr)[t] = (word (*)[t]) matrix;

  for(uint32 i = 0; i < t; i++) {
    for(uint32 j = 0; j < t; j++) {
      if((j == ((i + 1) % t)) || ((i > 0) && (j == ((i + 2) % t)))) {
        matrix_ptr[i][j] = 0x1;
      }
      else {
        matrix_ptr[i][j] = 0x0;
      }
    }
  }

  // Print out matrix
  #ifdef VERBOSE
  std::cout << "Random matrix:" << std::endl;
  for(uint32 i = 0; i < t; i++) {
    for(uint32 j = 0; j < t; j++) {
      std::cout << "0x" << to_string_hex(&(matrix_ptr[i][j]), ceil(((float)n / WORDSIZE) * 8)) << "   ";
    }
    std::cout << std::endl;
  }
  #endif

}

void init_very_weak_invertible_matrix(void* matrix, uint32 n, uint32 t) {
  word (*matrix_ptr)[t] = (word (*)[t]) matrix;

  for(uint32 i = 0; i < t; i++) {
    for(uint32 j = 0; j < t; j++) {
      if((i == 0) || (j == ((i + 1) % t))) {
        matrix_ptr[i][j] = 0x1;
      }
      else {
        matrix_ptr[i][j] = 0x0;
      }
    }
  }

  // Print out matrix
  #ifdef VERBOSE
  std::cout << "Random matrix:" << std::endl;
  for(uint32 i = 0; i < t; i++) {
    for(uint32 j = 0; j < t; j++) {
      std::cout << "0x" << to_string_hex(&(matrix_ptr[i][j]), ceil(((float)n / WORDSIZE) * 8)) << "   ";
    }
    std::cout << std::endl;
  }
  #endif

}

void init_cheap_invertible_matrix(void* matrix, uint32 t) {
  word (*matrix_ptr)[t] = (word (*)[t]) matrix;
  for(uint32 i = 0; i < t; i++) {
    for(uint32 j = 0; j < t; j++) {
      if(i == j) {
        matrix_ptr[i][j] = 0x4; // x^2
      }
      else {
        matrix_ptr[i][j] = 0x2; // x^1
      }
    }
  }
}

void pspn_specific_input(word* input_words, word* mults, uint64 fix_val, uint64 n, uint64 t) {
  memset(input_words, 0x0, sizeof(word) * t);

  // First and last
  input_words[0] = 0x0;
  input_words[t - 1] = fix_val;

  // Middle values
  for(uint32 i = 1; i < (t - 1); i++) {
    bf_mul(&(input_words[i]), &(mults[i - 1]), &fix_val);
  }
}

void pspn_specific_input_5_7(word* input_words, uint64 fix_val, uint64 n, uint64 t) {
  memset(input_words, 0x0, sizeof(word) * t);
  word mults[t - 2] = {0xd, 0x1f, 0x7, 0x14, 0x5};
  word temp;

  /*
  x1 = 0xd * x6
  x2 = 0x1f * x6
  x3 = 0x7 * x6
  x4 = 0x14 * x6
  x5 = 0x5 * x6
  */

  // First and last
  input_words[0] = 0x0;
  input_words[t - 1] = fix_val;

  // Middle values
  for(uint32 i = 1; i < (t - 1); i++) {
    bf_mul(&(input_words[i]), &(mults[i - 1]), &fix_val);
  }
}

void pspn_specific_input_7_5(word* input_words, uint64 fix_val, uint64 n, uint64 t) {
  memset(input_words, 0x0, sizeof(word) * t);
  word mults[t - 2] = {0x38, 0x79, 0x29};
  word temp;

  /*
  x1 = 0x38 * x4
  x2 = 0x79 * x4
  x3 = 0x29 * x4
  */

  // First and last
  input_words[0] = 0x0;
  input_words[t - 1] = fix_val;

  // Middle values
  for(uint32 i = 1; i < (t - 1); i++) {
    bf_mul(&(input_words[i]), &(mults[i - 1]), &fix_val);
  }
}

void pspn_specific_input_11_3(word* input_words, uint64 fix_val, uint64 n, uint64 t) {
  memset(input_words, 0x0, sizeof(word) * t);
  word mults[t - 2] = {0x556};
  word temp;

  /*
  x1 = 0x556 * x2
  */

  // First and last
  input_words[0] = 0x0;
  input_words[t - 1] = fix_val;

  // Middle values
  for(uint32 i = 1; i < (t - 1); i++) {
    bf_mul(&(input_words[i]), &(mults[i - 1]), &fix_val);
  }
}

void pspn_specific_input_13_3(word* input_words, uint64 fix_val, uint64 n, uint64 t) {
  memset(input_words, 0x0, sizeof(word) * t);
  word mults[t - 2] = {0x155a};
  word temp;

  /*
  x1 = 0x155a * x2
  */

  // First and last
  input_words[0] = 0x0;
  input_words[t - 1] = fix_val;

  // Middle values
  for(uint32 i = 1; i < (t - 1); i++) {
    bf_mul(&(input_words[i]), &(mults[i - 1]), &fix_val);
  }
}

void pspn_specific_input_17_2(word* input_words, uint64 fix_val, uint64 n, uint64 t) {
  // First and last
  input_words[0] = 0x0;
  input_words[t - 1] = fix_val;
}

void pspn_specific_input_17_4(word* input_words, uint64 fix_val, uint64 n, uint64 t) {
  memset(input_words, 0x0, sizeof(word) * t);

  // First and last
  input_words[0] = 0x0;
  input_words[3] = fix_val;

  word b = 0x16db2;
  word tmp = 0x10005;
  bf_mul(&(input_words[1]), &(input_words[3]), &tmp);
  bf_inverse(&tmp, &tmp);
  bf_mul(&(input_words[2]), &b, &fix_val);
  bf_add(&(input_words[2]), &(input_words[2]), &(input_words[1]));
  bf_mul(&(input_words[2]), &(input_words[2]), &tmp);
}

void matrix_vec_mul(word* vec_c, word* vec_a, uchar* matrix, uint32 t) {
  word (*matrix_ptr)[t] = (word (*)[t]) matrix;

  word tmp[t];
  word tmp_word = 0;
  memcpy(tmp, vec_a, t * sizeof(word));
  memset(vec_c, 0x0, t * sizeof(word));
  for(uint32 i = 0; i < t; i++) {
    for(uint32 j = 0; j < t; j++) {
      //std::cout << "a: " << to_string_hex(&(matrix_ptr[i][j]), ceil(((float)3 / WORDSIZE) * 8)) << std::endl;
      //std::cout << "b: " << to_string_hex(&(tmp[j]), ceil(((float)3 / WORDSIZE) * 8)) << std::endl;
      bf_mul(&tmp_word, &(matrix_ptr[i][j]), &(tmp[j]));
      //std::cout << "a * b = c: " << to_string_hex(&tmp_word, ceil(((float)3 / WORDSIZE) * 8)) << std::endl;
      bf_add(&(vec_c[i]), &(vec_c[i]), &tmp_word);
    }
  }
}

void gmimc_crf(word* in, word* out, word* round_keys, word* round_constants, uint32 num_rounds, uint32 n, uint32 t, uchar* data) {

  uchar* matrix_ptr_1 = data;
  
  // Values to work with
  word value_branch[t];
  word value_branch_temp_1 = 0;
  memset(value_branch, 0, t * sizeof(word));
  word value_key[t];
  memcpy(value_key, round_keys, t * sizeof(word));

  // Assign values
  std::vector<word> branch_order;
  for(uint32 i = 0; i < t; i++) {
    value_branch[i] = in[i];
    branch_order.push_back(i);
  }

  // Cipher implementation
  uint32 constant_index = 0;
  for(uint32 i = 0; i < num_rounds; i++) {
    // Sum of (t-1) least significant branches
    memcpy(&value_branch_temp_1, &(value_branch[branch_order.at(0)]), sizeof(word));
    for(uint32 j = 0; j < t - 1; j++) {
      bf_add(&value_branch_temp_1, &value_branch_temp_1, &(value_branch[branch_order.at(j)]));
    }

    // Add constant, add round key
    bf_add(&value_branch_temp_1, &value_branch_temp_1, &(round_constants[constant_index++]));
    bf_add(&value_branch_temp_1, &value_branch_temp_1, &(value_key[i % t]));
    // Cube
    bf_sbox(&value_branch_temp_1, &value_branch_temp_1);
    // Update single branch at position (t-1)
    bf_add(&(value_branch[branch_order.at(t - 1)]), &(value_branch[branch_order.at(t - 1)]), &value_branch_temp_1);

    // Final rotation
    std::rotate(branch_order.rbegin(), branch_order.rbegin() + 1, branch_order.rend());

    // Get new round keys if necessary
    if((i + 1) % t == 0) {
      matrix_vec_mul(value_key, value_key, matrix_ptr_1, t);
    }
  }

  // Write to out
  for(uint32 i = 0; i < t; i++) {
    out[i] = value_branch[branch_order.at(i)];
  }
}

void gmimc_erf(word* in, word* out, word* round_keys, word* round_constants, uint32 num_rounds, uint32 n, uint32 t, uchar* data) {

  uchar* matrix_ptr_1 = data;
  
  // Values to work with
  word value_branch[t];
  word value_branch_temp_1 = 0;
  memset(value_branch, 0, t * sizeof(word));
  word value_key[t];
  memcpy(value_key, round_keys, t * sizeof(word));

  // Assign values
  std::vector<uint32> branch_order;
  for(uint32 i = 0; i < t; i++) {
    value_branch[i] = in[i];
    branch_order.push_back(i);
  }

  // Cipher implementation
  uint32 constant_index = 0;
  for(uint32 i = 0; i < num_rounds; i++) {
    // Add constant, add round key
    bf_add(&(value_branch[branch_order.at(t - 1)]), &(value_branch[branch_order.at(t - 1)]), &(round_constants[constant_index++]));
    bf_add(&(value_branch[branch_order.at(t - 1)]), &(value_branch[branch_order.at(t - 1)]), &(value_key[i % t]));
    bf_sbox(&value_branch_temp_1, &(value_branch[branch_order.at(t - 1)]));
    for(uint32 j = 0; j < t - 1; j++) {
      bf_add(&(value_branch[branch_order.at(j)]), &(value_branch[branch_order.at(j)]), &value_branch_temp_1);
    }

    // Final rotation
    std::rotate(branch_order.rbegin(), branch_order.rbegin() + 1, branch_order.rend());

    // Get new round keys if necessary
    if((i + 1) % t == 0) {
      matrix_vec_mul(value_key, value_key, matrix_ptr_1, t);
    }
  }

  // Write to out
  for(uint32 i = 0; i < t; i++) {
    out[i] = value_branch[branch_order.at(i)];
  }
}

void gmimc_nyb(word* in, word* out, word* round_keys, word* round_constants, uint32 num_rounds, uint32 n, uint32 t, uchar* data) {
  
  // Values to work with
  word value_branch[t];
  word value_branch_temp[t];
  word value_branch_temp_1 = 0;
  memset(value_branch, 0, t * sizeof(word));
  memset(value_branch_temp, 0, t * sizeof(word));

  // Assign values
  std::vector<uint32> branch_order;
  for(uint32 i = 0; i < t; i++) {
    value_branch[i] = in[i];
    branch_order.push_back(i);
  }

  // Cipher implementation
  uint32 num_branches_half = (uint32)(t / 2);
  for(uint32 i = 0; i < num_rounds; i++) {

    // Add S-box output of every 1st branch to every 2nd branch
    for(uint32 j = 0; j < t; j += 2) {
      bf_sbox(&value_branch_temp_1, &(value_branch[branch_order.at(j + 1)]));
      bf_add(&(value_branch[branch_order.at(j)]), &(value_branch[branch_order.at(j)]), &value_branch_temp_1);
    }

    // Copy and shuffle
    // memcpy(value_branch_temp, value_branch, t * sizeof(word));
    // for(uint32 j = 0; j < t; j++) {
    //   value_branch[j] = value_branch_temp[(j + 1) % t];
    // }

    // Final rotation
    std::rotate(branch_order.rbegin(), branch_order.rbegin() + 1, branch_order.rend());
  }

  // Write to out
  for(uint32 i = 0; i < t; i++) {
    // out[i] = value_branch[i];
    out[i] = value_branch[branch_order.at(i)];
  }
}

void gmimc_mrf(word* in, word* out, word* round_keys, word* round_constants, uint32 num_rounds, uint32 n, uint32 t, uchar* data) {

  uchar* matrix_ptr_1 = data;
  
  // Values to work with
  word value_branch[t];
  word value_branch_temp_1 = 0;
  memset(value_branch, 0, t * sizeof(word));
  word value_key[t];
  memcpy(value_key, round_keys, t * sizeof(word));

  // Assign values
  std::vector<uint32> branch_order;
  for(uint32 i = 0; i < t; i++) {
    value_branch[i] = in[i];
    branch_order.push_back(i);
  }

  // Cipher implementation
  uint32 num_branches_half = (uint32)(t / 2);
  uint32 s_i_length = (uint32)(log2(num_branches_half)) * 2;
  uint32 s_i[s_i_length]; // rotation sequence
  for(uint32 i = 0; i < (uint32)(s_i_length / 2); i++) {
    s_i[(i * 2)] = 0;
    s_i[(i * 2) + 1] = 0x1 << (i % (uint32)(ceil(log2(num_branches_half))));
    //std::cout << "s_i[" << (i * 2) << "]: " << s_i[(i * 2)] << std::endl;
    //std::cout << "s_i[" << ((i * 2) + 1) << "]: " << s_i[((i * 2) + 1)] << std::endl;
  }

  uint32 s = 0;
  uint32 in_index = 0;
  uint32 add_index = 0;
  uint32 key_index = 0;
  uint32 constant_index = 0;
  uint32 key_counter = 0;
  //std::cout << "START ROUNDS" << std::endl;
  for(uint32 i = 0; i < num_rounds; i++) {
    s = s_i[i % s_i_length];
    //std::cout << "s: " << s << std::endl;
    //s = i % (t / 2);
    // Add round key, add round constant, apply S-box and XOR
    //std::cout << "--- NEW ROUND ---" << std::endl;
    for(uint32 j = t - 1; j > (num_branches_half - 1); j--) {
      in_index = (t - 1) - ((s + (t - 1 - j)) % num_branches_half);
      add_index = j - num_branches_half;
      //std::cout << "in_index: " << in_index << std::endl;
      //std::cout << "add_index: " << add_index << std::endl;
      bf_add(&value_branch_temp_1, &(value_branch[branch_order.at(in_index)]), &(round_constants[constant_index++]));
      key_index = ((t - 1 - j) + ((i % 2) * num_branches_half));
      //std::cout << "key_index: " << key_index << std::endl;
      //bf_add(&value_branch_temp_1, &value_branch_temp_1, &(value_key[key_index]));
      bf_add(&value_branch_temp_1, &value_branch_temp_1, &(round_keys[key_counter++]));
      bf_sbox(&value_branch_temp_1, &value_branch_temp_1);
      bf_add(&(value_branch[branch_order.at(add_index)]), &(value_branch[branch_order.at(add_index)]), &value_branch_temp_1);
    }

    // Copy and shuffle
    // memcpy(value_branch_temp, value_branch, t * sizeof(word));
    // for(uint32 j = 0; j < t; j++) {
    //   value_branch[j] = value_branch_temp[(num_branches_half + j) % t];
    // }

    // Get new round keys if necessary
    if((i + 1) % 2 == 0) {
      matrix_vec_mul(value_key, value_key, matrix_ptr_1, t);
    }

    // Final rotation (t / 2 branches for MRF)
    //for(uint32 j = 0; j < t; j++) std::cout << branch_order.at(j) << ",";
    //std::cout << std::endl;
    std::rotate(branch_order.begin(), branch_order.begin() + num_branches_half, branch_order.end());
    //for(uint32 j = 0; j < t; j++) std::cout << branch_order.at(j) << ",";
    //std::cout << std::endl;
  }
  //std::cout << "END ROUNDS" << std::endl;

  // Write to out
  for(uint32 i = 0; i < t; i++) {
    // out[i] = value_branch[i];
    out[i] = value_branch[branch_order.at(i)];
  }
}

void mimc(word* in, word* out, word* round_keys, word* round_constants, uint32 num_rounds, uint32 n, uint32 t, uchar* data) {

  // Values to work with
  word value_branch = 0;
  word key = round_keys[0];

  // Assign values
  value_branch = in[0];

  // Set first round constant to zero
  round_constants[0] = 0;

  // Cipher implementation
  for(uint32 i = 0; i < num_rounds; i++) {
    value_branch ^= key;
    value_branch ^= round_constants[i];
    bf_sbox(&value_branch, &value_branch);
    //std::cout << "Round " << (i + 1) << " finished." << std::endl;
  }
  value_branch ^= key;

  // Write to out
  out[0] = value_branch;
}

void mimc_feistel(word* in, word* out, word* round_keys, word* round_constants, uint32 num_rounds, uint32 n, uint32 t, uchar* data) {

  uchar* matrix_ptr_1 = data;
  
  // Values to work with
  word value_branch[t];
  word value_branch_temp_1 = 0;
  memset(value_branch, 0, t * sizeof(word));
  word value_key[t];
  memcpy(value_key, round_keys, t * sizeof(word));

  // Assign values
  std::vector<uint32> branch_order;
  for(uint32 i = 0; i < t; i++) {
    value_branch[i] = in[i];
    branch_order.push_back(i);
  }

  // Cipher implementation
  uint32 constant_index = 0;
  for(uint32 i = 0; i < num_rounds; i++) {
    // Add constant, add round key
    bf_add(&(value_branch[branch_order.at(t - 1)]), &(value_branch[branch_order.at(t - 1)]), &(round_constants[constant_index++]));
    bf_add(&(value_branch[branch_order.at(t - 1)]), &(value_branch[branch_order.at(t - 1)]), &(value_key[0])); // Use always the same value_key[0] for MiMC_Feistel
    bf_sbox(&value_branch_temp_1, &(value_branch[branch_order.at(t - 1)]));
    for(uint32 j = 0; j < t - 1; j++) {
      bf_add(&(value_branch[branch_order.at(j)]), &(value_branch[branch_order.at(j)]), &value_branch_temp_1);
    }

    // Final rotation
    std::rotate(branch_order.rbegin(), branch_order.rbegin() + 1, branch_order.rend());
  }

  // Write to out
  for(uint32 i = 0; i < t; i++) {
    out[i] = value_branch[branch_order.at(i)];
  }
}

void hadesmimc_fpf(word* in, word* out, word* round_keys, word* round_constants, uint32 num_rounds, uint32 n, uint32 t, uchar* data) {
  // Does R_f rounds with full S-box layers, num_rounds rounds with partial S-box layers, and R_f rounds full S-box layers (specify R_f in this function)
  //word (*matrix_ptr_1)[t] = (word (*)[t]) data;
  //word (*matrix_ptr_2)[t] = (word (*)[t]) (data + (sizeof(word) * t * t));
  uchar* matrix_ptr_1 = data;
  uchar* matrix_ptr_2 = (data + (sizeof(word) * t * t));

  uint32 R_f = 3; // R_F = 2 * R_f

  // Values to work with
  word value_branch[t];
  memset(value_branch, 0, t * sizeof(word));
  word value_key[t];
  memcpy(value_key, round_keys, t * sizeof(word));

  // Assign values
  for(uint32 i = 0; i < t; i++) {
    value_branch[i] = in[i];
  }

  uint32 constant_index = 0;
  uint32 num_middle_rounds = num_rounds - 2;

  for(uint32 k = 0; k < R_f; k++) {
    // First rounds with full S-box layer
    for(uint32 i = 0; i < t; i++) {
      // Constant to key, ARK, Cubing
      bf_add(&(value_key[i]), &(value_key[i]), &(round_constants[constant_index++]));
      bf_add(&(value_branch[i]), &(value_branch[i]), &(value_key[i]));
      bf_sbox(&(value_branch[i]), &(value_branch[i]));
    }
    // Linear layer
    matrix_vec_mul(value_branch, value_branch, matrix_ptr_1, t);
    // Renew round keys
    matrix_vec_mul(value_key, value_key, matrix_ptr_2, t);
  }

  // Middle rounds
  for(uint32 k = 0; k < num_middle_rounds; k++) {
    for(uint32 i = 0; i < t; i++) {
      // Constant to key, ARK
      bf_add(&(value_key[i]), &(value_key[i]), &(round_constants[constant_index++]));
      bf_add(&(value_branch[i]), &(value_branch[i]), &(value_key[i]));
    }
    // Cubing for first branch
    bf_sbox(&(value_branch[0]), &(value_branch[0]));
    // Linear layer
    matrix_vec_mul(value_branch, value_branch, matrix_ptr_1, t);
    // Renew round keys
    matrix_vec_mul(value_key, value_key, matrix_ptr_2, t);
  }

  for(uint32 k = 0; k < R_f - 1; k++) {
    // Last R_f - 1 rounds with full S-box layer
    for(uint32 i = 0; i < t; i++) {
      // Constant to key, ARK, Cubing
      bf_add(&(value_key[i]), &(value_key[i]), &(round_constants[constant_index++]));
      bf_add(&(value_branch[i]), &(value_branch[i]), &(value_key[i]));
      bf_sbox(&(value_branch[i]), &(value_branch[i]));
    }
    // Linear layer
    matrix_vec_mul(value_branch, value_branch, matrix_ptr_1, t);
    // Renew round keys
    matrix_vec_mul(value_key, value_key, matrix_ptr_2, t);
  }

  // Last round (without linear layer) and last key addition
  for(uint32 i = 0; i < t; i++) {
    // Constant to key, ARK, Cubing
    bf_add(&(value_key[i]), &(value_key[i]), &(round_constants[constant_index++]));
    bf_add(&(value_branch[i]), &(value_branch[i]), &(value_key[i]));
    bf_sbox(&(value_branch[i]), &(value_branch[i]));
  }
  // Renew round keys
  matrix_vec_mul(value_key, value_key, matrix_ptr_2, t);
  for(uint32 i = 0; i < t; i++) {
    bf_add(&(value_key[i]), &(value_key[i]), &(round_constants[constant_index++]));
    bf_add(&(value_branch[i]), &(value_branch[i]), &(value_key[i]));
  }

  // Write to out
  for(uint32 i = 0; i < t; i++) {
    // out[i] = value_branch[i];
    out[i] = value_branch[i];
  }
}

void hadesmimc_f(word* in, word* out, word* round_keys, word* round_constants, uint32 num_rounds, uint32 n, uint32 t, uchar* data) {
  // Does num_rounds with full S-box layer (basically the same as the fpf version, but rounds with partial layers are replaced by rounds with full layers)
  uchar* matrix_ptr_1 = data;
  uchar* matrix_ptr_2 = (data + (sizeof(word) * t * t));

  // Values to work with
  word value_branch[t];
  memset(value_branch, 0, t * sizeof(word));
  word value_key[t];
  memcpy(value_key, round_keys, t * sizeof(word));

  // Assign values
  for(uint32 i = 0; i < t; i++) {
    value_branch[i] = in[i];
  }

  uint32 constant_index = 0;

  // All rounds with full S-box layers
  for(uint32 k = 0; k < num_rounds; k++) {
    for(uint32 i = 0; i < t; i++) {
      // Constant to key, ARK, Cubing
      bf_add(&(value_key[i]), &(value_key[i]), &(round_constants[constant_index++]));
      bf_add(&(value_branch[i]), &(value_branch[i]), &(value_key[i]));
      bf_sbox(&(value_branch[i]), &(value_branch[i]));
    }
    // Linear layer
    matrix_vec_mul(value_branch, value_branch, matrix_ptr_1, t);
    // Renew round keys
    matrix_vec_mul(value_key, value_key, matrix_ptr_2, t);
    //for(uint32 i = 0; i < t; i++) {
    //  std::cout << "RK_" << k << "_" << i << ": " << std::hex << round_keys[i] << std::dec << std::endl;
    //}
  }

  // Write to out
  for(uint32 i = 0; i < t; i++) {
    // out[i] = value_branch[i];
    out[i] = value_branch[i];
  }
}

void hadesmimc_p(word* in, word* out, word* round_keys, word* round_constants, uint32 num_rounds, uint32 n, uint32 t, uchar* data) {
  // Does only rounds with partial S-box layers
  //word (*matrix_ptr_1)[t] = (word (*)[t]) data;
  //word (*matrix_ptr_2)[t] = (word (*)[t]) (data + (sizeof(word) * t * t));
  uchar* matrix_ptr_1 = data;
  uchar* matrix_ptr_2 = (data + (sizeof(word) * t * t));

  // Values to work with
  word value_branch[t];
  memset(value_branch, 0, t * sizeof(word));
  word value_key[t];
  memcpy(value_key, round_keys, t * sizeof(word));

  // Assign values
  for(uint32 i = 0; i < t; i++) {
    value_branch[i] = in[i];
  }

  uint32 constant_index = 0;
  // Only Middle rounds
  for(uint32 k = 0; k < num_rounds; k++) {
    for(uint32 i = 0; i < t; i++) {
      // Constant to key, ARK
      bf_add(&(value_key[i]), &(value_key[i]), &(round_constants[constant_index++]));
      bf_add(&(value_branch[i]), &(value_branch[i]), &(value_key[i]));
    }
    // Round function for first branch
    bf_sbox(&(value_branch[0]), &(value_branch[0]));
    //bf_inverse(&(value_branch[0]), &(value_branch[0]));
    // Linear layer
    //if(k < (num_rounds - 1))
    matrix_vec_mul(value_branch, value_branch, matrix_ptr_1, t);
    // Renew round keys
    matrix_vec_mul(value_key, value_key, matrix_ptr_2, t);
  }

  // Write to out
  for(uint32 i = 0; i < t; i++) {
    // out[i] = value_branch[i];
    out[i] = value_branch[i];
  }
}

void shark(word* in, word* out, word* round_keys, word* round_constants, uint32 num_rounds, uint32 n, uint32 t, uchar* data) {
  // Does num_rounds with full S-box layer (basically the same as the fpf version, but rounds with partial layers are replaced by rounds with full layers)
  uchar* matrix_ptr_1 = data;
  uchar* matrix_ptr_2 = (data + (sizeof(word) * t * t));

  // Values to work with
  word value_branch[t];
  memset(value_branch, 0, t * sizeof(word));
  word value_key[t];
  memcpy(value_key, round_keys, t * sizeof(word));

  // Assign values
  for(uint32 i = 0; i < t; i++) {
    value_branch[i] = in[i];
  }
  uint32 branch_size = ceil(((float)n / WORDSIZE) * 8);

  uint32 constant_index = 0;

  // All rounds with full S-box layers
  for(uint32 k = 0; k < num_rounds; k++) {
    for(uint32 i = 0; i < t; i++) { // Temp: Fix to one S-box per round
      // Constant to key, ARK, Cubing
      bf_add(&(value_key[k % 2]), &(value_key[k % 2]), &(round_constants[constant_index++]));
      bf_add(&(value_branch[i]), &(value_branch[i]), &(value_key[k % 2]));
      bf_sbox(&(value_branch[i]), &(value_branch[i]));
    }
    // Linear layer
    //std::cout << "[BEFORE] Branch 0: " << to_string_hex(&(value_branch[0]), branch_size) << std::endl;
    //std::cout << "[BEFORE] Branch 0: " << to_string_hex(&(value_branch[1]), branch_size) << std::endl;
    matrix_vec_mul(value_branch, value_branch, matrix_ptr_1, t);
    //std::cout << "[AFTER] Branch 0: " << to_string_hex(&(value_branch[0]), branch_size) << std::endl;
    //std::cout << "[AFTER] Branch 0: " << to_string_hex(&(value_branch[1]), branch_size) << std::endl;
    // Renew round keys
    //matrix_vec_mul(value_key, value_key, matrix_ptr_2, t);
    
    //for(uint32 i = 0; i < t; i++) {
    //  std::cout << "RK_" << k << "_" << i << ": " << std::hex << round_keys[i] << std::dec << std::endl;
    //}
  }

  // Write to out
  for(uint32 i = 0; i < t; i++) {
    // out[i] = value_branch[i];
    out[i] = value_branch[i];
  }
}

int main(int argc, char** argv) {

  std::cout << "Starting..." << std::endl;

  if(argc != 4) {
    std::cout << "Usage: <program> <n> <t> <num_rounds>" << std::endl;
    return 1;
  }

  // Fetch from command line parameters
  uint64 n = std::stoi(argv[1]);
  uint64 t = std::stoi(argv[2]);
  uint64 N = n * t;
  uint64 num_rounds = std::stoi(argv[3]);

  // Settings
  uint64 num_bits_active = N - 1; // N - 1
  uint64 bit_inactive = num_bits_active;
  uint64 begin_at_branch = 0;
  uint64 cipher_case = 0; // 0 .. MiMC, 1 .. CRF/ERF/MiMC_Feistel, 2 .. Nyb/MRF, 3 .. HadesMiMC, 4.. Shark-like
  cipher = &mimc;
  bool rand_input = true;
  bool rand_round_keys = true;
  bool rand_constants = true;
  bool binary_output = true;
  bool test_matrix_invertible = false;
  uint32 matrix_mode = 0; // 0 .. MDS, 1 .. random invertible from K, 2 .. "weak" invertible matrix with many zeros, 3 .. "very weak" invertible matrix (slow diffusion)

  word in[t];
  word in_copy[t];
  word out[t];

  if(n == 3) {
    bf_add = &bf_add_generic;
    bf_mul = &bf_3_mul;
    //bf_sbox = &bf_3_cube;
    irred_poly = 0xb;
  }
  else if(n == 5) {
    bf_add = &bf_add_generic;
    bf_mul = &bf_5_mul;
    //bf_sbox = &bf_5_cube;
    irred_poly = 0x25;
  }
  else if(n == 7) {
    bf_add = &bf_add_generic;
    bf_mul = &bf_7_mul;
    //bf_sbox = &bf_7_cube;
    irred_poly = 0x83;
  }
  else if(n == 9) {
    bf_add = &bf_add_generic;
    bf_mul = &bf_9_mul;
    //bf_sbox = &bf_9_cube;
    irred_poly = 0x203;
  }
  else if(n == 11) {
    bf_add = &bf_add_generic;
    bf_mul = &bf_11_mul;
    //bf_sbox = &bf_11_cube;
    irred_poly = 0x805;
  }
  else if(n == 13) {
    bf_add = &bf_add_generic;
    bf_mul = &bf_13_mul;
    //bf_sbox = &bf_13_cube;
    irred_poly = 0x201b;
  }
  else if(n == 15) {
    bf_add = &bf_add_generic;
    bf_mul = &bf_15_mul;
    //bf_sbox = &bf_15_cube;
    irred_poly = 0x8003;
  }
  else if(n == 17) {
    bf_add = &bf_add_generic;
    bf_mul = &bf_17_mul;
    //bf_sbox = &bf_17_cube;
    irred_poly = 0x20009;
  }
  else if(n == 19) {
    bf_add = &bf_add_generic;
    bf_mul = &bf_19_mul;
    //bf_sbox = &bf_19_cube;
    irred_poly = 0x80027;
  }
  else if(n == 32) {
    bf_add = &bf_add_generic;
    bf_mul = &bf_32_mul;
    //bf_sbox = &bf_32_cube;
    irred_poly = 0x10000008d;
  }
  else if(n == 33) {
    bf_add = &bf_add_generic;
    bf_mul = &bf_33_mul;
    //bf_sbox = &bf_33_cube;
    irred_poly = 0x20000004b;
  }
  else {
    std::cout << "[ERROR] Undefined field size " << n << "." << std::endl;
    exit(1);
  }

  std::cout << "[INFO] Irred poly: " << to_string_hex(&irred_poly, 16) << std::endl;

  //word matrix[8][8];
  //init_mds_matrix((void*)matrix, n, 8, 1);

  uint64 branch_size = ceil(((float)n / WORDSIZE) * 8);
  uint64 word_unused_bits = (WORDSIZE - (n % WORDSIZE)) % WORDSIZE;
  uint64 used_mask = 0xFFFFFFFFFFFFFFFF >> word_unused_bits;

  memset(in, 0x0, t * sizeof(word));

  // Randomize input
  for(uint32 i = 0; i < t; i++) {
    if(rand_input == true)
      RAND_bytes((uchar*)&(in[i]), branch_size);
    else
      memset(&(in[i]), 0x0, branch_size);
      //memset(&(in[i]), 0x0, branch_size);
      //memset(&(in[i]), 0x03, branch_size);
    in[i] = in[i] & used_mask;
    std::cout << "Input (Branch " << i << "): " << std::hex << in[i] << std::dec << std::endl;
  }

  memcpy(in_copy, in, t * sizeof(word));
  memset(out, 0x0, t * sizeof(word));

  // Zero Sum test
  uint32 num_round_constants = 0;
  uint32 num_round_keys = 0;
  word* data = NULL; // Storage for matrices, and so on...
  if(cipher_case == 0) {
    num_round_constants = num_rounds;
    num_round_keys = 1;
  }
  else if(cipher_case == 1) {
    num_round_constants = num_rounds;
    num_round_keys = t;
    data = new word[t * t];
    memset(data, 0x0, sizeof(word) * t * t);
    init_cheap_invertible_matrix((uchar*)data, t);
  }
  else if(cipher_case == 2) {
    num_round_constants = num_rounds * (uint32)(t / 2);
    num_round_keys = num_rounds * (uint32)(t / 2);
    data = new word[t * t];
    memset(data, 0x0, sizeof(word) * t * t);
    init_cheap_invertible_matrix((uchar*)data, t);
  }
  else if(cipher_case == 3) {
    num_round_constants = (num_rounds + 8) * t; // R_F = 8
    num_round_keys = t;
    data = new word[t * t * 2]; // First MDS matrix for linear layer, second MDS matrix for key schedule
    memset(data, 0x0, sizeof(word) * t * t * 2);
    if(matrix_mode == 0) {
      init_mds_matrix((uchar*)data, n, t, 1);
      init_mds_matrix((uchar*)((uchar*)data + (sizeof(word) * t * t)), n, t, 2);
    }
    else if(matrix_mode == 1) {
      init_random_invertible_matrix((uchar*)data, n, t);
      init_random_invertible_matrix((uchar*)((uchar*)data + (sizeof(word) * t * t)), n, t);
    }
    else if(matrix_mode == 2) {
      init_weak_invertible_matrix((uchar*)data, n, t);
      init_weak_invertible_matrix((uchar*)((uchar*)data + (sizeof(word) * t * t)), n, t);
    }
    else if(matrix_mode == 3) {
      init_very_weak_invertible_matrix((uchar*)data, n, t);
      init_very_weak_invertible_matrix((uchar*)((uchar*)data + (sizeof(word) * t * t)), n, t);
    }
    if(test_matrix_invertible == true) {
      std::cout << "Matrix invertible [1]: " << is_matrix_invertible((uchar*)data, t) << std::endl;
      std::cout << "Matrix invertible [2]: " << is_matrix_invertible((uchar*)((uchar*)data + (sizeof(word) * t * t)), t) << std::endl;
    }
  }
  else if(cipher_case == 4) {
    num_round_constants = num_rounds * t;
    num_round_keys = num_rounds * t;
    data = new word[t * t]; // MDS matrix for linear layer
    memset(data, 0x0, sizeof(word) * t * t);
    if(matrix_mode == 0) {
      init_mds_matrix((uchar*)data, n, t, 0);
    }
    else if(matrix_mode == 1) {
      init_random_invertible_matrix((uchar*)data, n, t);
    }
    else if(matrix_mode == 2) {
      init_weak_invertible_matrix((uchar*)data, n, t);
    }
    else if(matrix_mode == 3) {
      init_very_weak_invertible_matrix((uchar*)data, n, t);
    }
    if(test_matrix_invertible == true) {
      std::cout << "Matrix invertible [1]: " << is_matrix_invertible((uchar*)data, t) << std::endl;
    }
  }
  else {
    std::cout << "[ERROR] Undefined cipher type " << cipher_case << "." << std::endl;
    exit(1);
  }

  word round_constants[num_round_constants];
  word round_keys[num_round_keys];

  // Randomize key and constants
  /*
  RAND_bytes((uchar*)&(key), branch_size);
  key = key & used_mask;
  std::cout << "Key: " << to_string_hex(&key, branch_size) << std::endl;
  for(uint32 i = 0; i < num_rounds; i++) {
    RAND_bytes((uchar*)&(round_constants[i]), branch_size);
    round_constants[i] = round_constants[i] & used_mask;
    std::cout << "RC " << i << ": " << to_string_hex(&(round_constants[i]), branch_size) << std::endl;
  }
  */
  for(uint32 i = 0; i < num_round_constants; i++) {
    if(rand_constants == true)
      RAND_bytes((uchar*)&(round_constants[i]), branch_size);
    else
      memset(&(round_constants[i]), 0x0, branch_size);
    round_constants[i] = round_constants[i] & used_mask;
    //round_constants[i] = 0;
    std::cout << "RC " << i << ": " << to_string_hex(&(round_constants[i]), branch_size) << std::endl;
  }

  for(uint32 i = 0; i < num_round_keys; i++) {
    if(rand_round_keys == true)
      RAND_bytes((uchar*)&(round_keys[i]), branch_size);
    else
      memset(&(round_keys[i]), 0x0, branch_size);
    round_keys[i] = round_keys[i] & used_mask;
    //round_keys[i] = 0;
    std::cout << "RK " << i << ": " << to_string_hex(&(round_keys[i]), branch_size) << std::endl;
  }

  uint64 num_texts = (uint64)0x1 << num_bits_active;
  word in_sum[t];
  word out_sum[t];
  memset(in_sum, 0x0, t * sizeof(word));
  memset(out_sum, 0x0, t * sizeof(word));

  // Print settings
  uint32 sbox_degree = SBOX_DEGREE;
  #ifdef REDUCE_DEGREE_TWICE
  sbox_degree -= 2;
  #endif
  std::cout << "Field size n: " << n << std::endl;
  std::cout << "Number of cells t: " << t << std::endl;
  std::cout << "Number of rounds: " << num_rounds << std::endl;
  std::cout << "Number of active bits: " << num_bits_active << std::endl;
  std::cout << "Inactive bit index in active bits: " << bit_inactive << std::endl;
  std::cout << "Matrix mode: " << matrix_mode << std::endl;
  std::cout << "Number of input texts: " << num_texts << std::endl;
  std::cout << "S-box: x^" << sbox_degree << std::endl;

  //std::set<word> branch_values;
  word test_vector_plaintext[t];
  word test_vector_ciphertext[t];
  memset(test_vector_plaintext, 0x0, t * sizeof(word));
  memset(test_vector_ciphertext, 0x0, t * sizeof(word));

  uint32 num_affected_branches = ceil((float)num_bits_active / n);

  uint64 i_split = 0;
  uint64 shift_amount = std::min(1, (int)(num_bits_active - bit_inactive)); // either 0 or 1
  for(uint64 i = 0; i < num_texts; i++) {
    // Set difference
    for(uint32 j = 0; j < num_affected_branches; j++) {
      //std::cout << "--- --- --- --- ---" << std::endl;
      //std::cout << "i: " << to_string_binary(&i, sizeof(word) / 2) << std::endl;
      i_split = ((i & (((uint64)0x1 << bit_inactive) - 1)) | ((i << shift_amount) & ~(((uint64)0x1 << (bit_inactive + 1)) - 1))) & (used_mask << (j * n));
      //std::cout << "i_split: " << to_string_binary(&i_split, sizeof(word) / 2) << std::endl;
      in_copy[j + begin_at_branch] = in[j + begin_at_branch] ^ ((i_split >> (j * n)) & used_mask);
      //std::cout << "mask: " << std::hex << used_mask << std::dec << std::endl;
      //std::cout << "(i, j) = (" << i << ", " << j << "): " << to_string_binary(&(in_copy[j + begin_at_branch]), 2) << std::endl;
    }

    // Input spaces (MDS start = 0 except where noted)
    //word mults[t - 2]; // t = 2, dummy
    //word mults[t - 2] = {0xd, 0x1f, 0x7, 0x14, 0x5}; // n = 5, t = 7
    //word mults[t - 2] = {0x38, 0x79, 0x29}; // 7, 5
    //word mults[t - 2] = {0x556}; // 11, 3
    //word mults[t - 2] = {0x155a}; // 13, 3
    //word mults[t - 2] = {0xc, 0x13, 0xf, 0x5, 0x1, 0x12, 0x19, 0x18, 0x0, 0xd, 0x8}; // 5, 13
    //word mults[t - 2] = {0x623, 0x784, 0x1aa6}; // 13, 5
    //word mults[t - 2] = {0x26, 0x5d, 0x30, 0x2e, 0xd, 0x3a, 0x75}; // 7, 9
    //word mults[t - 2] = {0x65, 0x2d, 0xd, 0x4c}; // 7, 6
    //word mults[t - 2] = {0x96, 0x110}; // 9, 4, MDS start = 1
    //word mults[t - 2] = {0x1b2, 0x15f, 0x17e, 0x15d, 0xdc}; // 9, 7
    //word mults[t - 2] = {0x1e5cd, 0x1f52}; // 17, 4, MDS start = 1
    //word mults[t - 2] = {0x73, 0x52, 0x11, 0x54, 0x7a, 0x7d, 0x6a, 0x4d, 0x1c, 0x59, 0x64, 0x14, 0x4f, 0x79, 0x2, 0x58, 0x1f}; // 7, 19
    //word mults[t - 2] = {0x31c96, 0x1af27, 0x32bcd, 0x53a61, 0x299d3}; // 19, 7
    //word mults[t - 2] = {0x1c6, 0x1ea, 0x87, 0x1e7, 0x52, 0x2c, 0x145, 0x74, 0x12e, 0xb1, 0x143, 0x147, 0xda}; // 9, 15
    //word mults[t - 2] = {0x6e0f, 0x5edd, 0x18ee, 0x5b57, 0x31a7, 0x3428, 0x6bdb}; // 15, 9

    //pspn_specific_input(in_copy, mults, i, n, t);
    //pspn_specific_input_17_4(in_copy, i, n, t);

    // Update input sum
    for(uint32 j = 0; j < t; j++) {
      in_sum[j] ^= in_copy[j];
    }

    if(i == 0) {
      for(uint32 j = 0; j < t; j++) {
        memcpy(&(test_vector_plaintext[j]), &(in_copy[j]), sizeof(word));
      }
    }

    cipher(in_copy, out, round_keys, round_constants, num_rounds, n, t, (uchar*)data);

    // Update output sum
    for(uint32 j = 0; j < t; j++) {
      out_sum[j] ^= out[j];
    }

    if(i == 0) {
      for(uint32 j = 0; j < t; j++) {
        memcpy(&(test_vector_ciphertext[j]), &(out[j]), sizeof(word));
      }
    }

    //branch_values.insert((out[2] << (2*n)) | (out[1] << n) | out[0]);
  }

  //std::cout << "Unique output values: " << branch_values.size() << std::endl;

  // Print input sums
  for(uint32 i = 0; i < t; i++) {
    std::cout << "[I] Branch " << i << ": " << to_string_hex(&(in_sum[i]), sizeof(word) / 2) << std::endl;
  }

  std::cout << "----------" << std::endl;

  // Print test vectors for x-th pair
  for(uint32 i = 0; i < t; i++) {
    std::cout << "[Test Vector - PT] Branch " << i << ": " << to_string_hex(&(test_vector_plaintext[i]), branch_size) << std::endl;
  }

  for(uint32 i = 0; i < t; i++) {
    std::cout << "[Test Vector - CT] Branch " << i << ": " << to_string_hex(&(test_vector_ciphertext[i]), branch_size) << std::endl;
  }

  std::cout << "----------" << std::endl;

  // Print output sums
  std::cout << "Out (hex):" << std::endl;
  for(uint32 i = 0; i < t; i++) {
    std::cout << "[O] Branch " << i << ": " << to_string_hex(&(out_sum[i]), sizeof(word) / 2) << std::endl;
  }
  if(binary_output == true) {
    std::cout << "Out (bin):" << std::endl;
    for(uint32 i = 0; i < t; i++) {
      std::cout << "[O] Branch " << i << ": " << to_string_binary(&(out_sum[i]), sizeof(word) / 2) << std::endl;
    }
  }
  //for(uint32 i = 0; i < t; i++) {
  //  std::cout << std::setfill('0') << std::setw(8) << std::hex << in_sum[i] << std::dec << std::endl;
  //}

  if(data != NULL) {
    delete[] data;
  }

  return 0;
}
