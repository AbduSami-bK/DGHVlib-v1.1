/** Copyright (C) 2018-2019 SAU Network Communication Research Room.
 * This program is Licensed under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *   http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. See accompanying LICENSE file.
 */

#ifndef _DGHV_H_
#define _DGHV_H_

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <time.h>
#include <sys/time.h>
#include <string>
#include <cstring>
#include <vector>
#include <math.h>
#include <gmp.h>
#include <gmpxx.h>

// is a parameter level. See secstg.h you can also set it yourself and verify that the parameters are reasonable with the
//bool para_valid (__sec_setting-para)
#define TOY                   0
#define SMALL                 1
#define MEDIUM                2
#define LARGE                 3

#define PROB_EXP              50
#define BASE                  2
#define PRIHL                 8
#define PUBHL                 8

#define W                     (GMP_NUMB_BITS/2)
#define _LSBMASK              1ul
#define _MSBMASK              (1ul << (2 * W - 1))
#define _BOT_N_MASK(n)        ((_LSBMASK << n) - 1)
#define _TOP_N_MASK(n)        (_BOT_N_MASK(n) << (2 * W - n))

#define R_N_SHIFT(x, n)       (x >> n)
#define L_N_SHIFT(x, n)       (x << n)
#define MP_EXP(x)             (x->_mp_exp)          //Get the _mp_exp in the big floating points in the GMP library mpf_t see the gmp.h 197 line comment
#define MP_SIZE(x)            (x->_mp_size)         //mpf_t the number of limbs in , each limb is an unsigned long shaped pointer that holds 64 decimal places in a large number
#define MP_PREC(x)            (x->_mp_prec)         //mpf_t Precision in indicates that there are _mp_prec limbs representing fractional parts.
#define MP_ALLOC(x)           (x->_mp_alloc)        //mpz_t The number of limbs in a large integer
#define LIMB(x, i)            (((i)<((x)->_mp_size))?((x)->_mp_d[i]):(0L))  //Get the ith limb of the mpf_t or mpz_t
#define LSB(x)                (x & _LSBMASK)        //take the lowest significant bit
#define MSB(x)                (x & _MSBMASK)        //take the most significant bit
#define MSBN(x, n)            (x & (_TOP_N_MASK(n)))//The highest N-bit valid bit needs to be moved 2W-N bits to the right again in order to get it correctly
#define LSBN(x, n)            (x & (_BOT_N_MASK(n)))//The lowest N-bit significant bit
#define MIN_ETA(x)            (21 * x + 50)         //The minimum key length when n=5 in the argument.

// The parameter type
typedef struct securitySetting {
    size_t lam;     // Security parameters
    size_t Rho;     // Noise in the public key
    size_t rho;     // Encrypted noise
    size_t eta;     // The length of the key
    size_t gam;     // The length of the public key
    size_t Theta;   // The number of bits of the sparse subset
    size_t theta;   // The Hamming weight of the sparse subset
    size_t tau;     // The number of public keys
    size_t prec;    // the accuracy after the decimal point of yi
    size_t n;       // bootstrapping takes the n-bit after the decimal point, i.e. the c*yi takes the decimal point after the n-bit participates in the redaction refresh.
    mpz_t  pt_limit;// Maximum plaintext number than can be encrypted and decrypted.
} __sec_setting;

// The type of private key
typedef struct privatekey {
    mpz_t sk;           // Private
    mpz_t* sk_rsub;     // Sparse subset
    size_t rsub_size;   // Sparse subset size
    size_t rsub_hw;     // Sparse subset Hamming weights
    size_t sk_bit_cnt;  // Private key bit length
    char gen_time[20];  // Death produces time
} __prikey;

typedef struct publickeyset {
    mpz_t x0;       // The longest public key mode x0 controls the length of the redaction
    mpz_t* pks;     // The collection of public keys
    mpz_t* cs;      // A sparse subset after encryption
    mpf_t* y;       // 1/p = y1+y2+...
    size_t pks_size;// The number of jobs
    size_t y_size;  // the number of yi
    size_t pk_bit_cnt;  // The length of the public key bit
    char gen_time[20];  // The time to produce
} __pubkey_set;

typedef struct sc_privatekey {
    mpz_t sk;
    unsigned long** s0;
    unsigned long** s1;
    unsigned long* fill_s;
    size_t s0_group_cnt;
    size_t s1_group_cnt;
    size_t every_group_length;
    size_t last_group_length;
    size_t fill_cnt;
    size_t rsub_size;
    size_t rsub_hw;
    size_t sk_bit_cnt;
    char gen_time[20];
} __sc_prikey;

typedef struct sc_publickeyset {
    mpz_t x0;
    mpz_t* pk_vector1;         //Xi0
    mpz_t* pk_vector2;         //Xj1
    mpz_t* s0_vector;         //S(0)vector
    mpz_t* s1_vector;         //S(1)vector
    mpz_t* s_fills;
    mpf_t* y;
    unsigned long seed;
    size_t beta;
    size_t s0_group_cnt;
    size_t s1_group_cnt;
    size_t every_group_length;
    size_t last_group_length;
    size_t fill_cnt;
    size_t pks_size;
    size_t y_size;
    size_t pk_bit_cnt;
    char gen_time[20];
} __sc_pubkey_set;

typedef struct rc_privatekey {
    mpz_t sk;
    mpz_t rsk;
    mpz_t* sk_rsub;
    size_t rsub_size;
    size_t rsub_hw;
    size_t sk_bit_cnt;
    size_t rsk_bit_cnt;
    char gen_time[20];
} __rc_prikey;

typedef struct rc_publickey_set {
    mpz_t x0;
    mpz_t rx0;
    mpz_t* delta;
    mpf_t* y;
    mpz_t** sigma;
    size_t sx;
    size_t sy;
    size_t pks_size;
    size_t y_size;
    size_t pk_bit_cnt;
    char gen_time[20];
    unsigned long seed;
} __rc_pubkey_set;


// The type of redaction
typedef struct ciphertext {
    mpz_t c;    // ciphertext
    mpf_t *z;   // Extended redaction zi=cyi
    mpz_t *zt;
    size_t z_size;  // zi's number
} __cit;   //ciphertext

// Hamming Weight Calculation Table
typedef struct hamming_weight_table {
    mpz_t **table;
    size_t x;
    size_t y;
} __hw_table;

// The secret updates the calculation table
typedef struct evaluation_table {
    mpz_t **table;
    size_t x;
    size_t y;
} __ev_table;

typedef gmp_randstate_t  randstate;     // Random state
typedef __prikey*        c_prikey;      // The type of key pointer
typedef __sc_prikey*     sc_prikey;
typedef __rc_prikey*     rc_prikey;
typedef __pubkey_set*    c_pubkeys;     // The type of public key pointer
typedef __sc_pubkey_set* sc_pubkeys;
typedef __rc_pubkey_set* rc_pubkeys;
typedef __sec_setting*   c_parameters;  // The type of argument pointer
typedef __cit*           c_cit;         //The type of redacted pointer


/**************** Security Parameters Setting.  ****************/
//secstg.c

//Initialize the parameters
void init_sec_para(__sec_setting** para);

void clear_sec_para(__sec_setting** para);

//Initialize the default parameters TOY, SMALL, MEDIUM, LARGE four levels you can set yourself specific parameters in the secstg.c
void set_default_para(__sec_setting* para, int level);

//Verify that the parameter settings are reasonable
bool para_valid(__sec_setting* para);

/****************  Initialized Key.  ****************/
//key.c

//Initializing the private key requires parameter initialization, so the parameters must be initialized before the private key can be initialized, and the parameters are set
void init_sk(__prikey** prikey, __sec_setting* para);

//Initialize the collection of public keys
void init_pkset(__pubkey_set** pubkey, __sec_setting* para);

//Release the private key
void clear_sk(__prikey* prikey);

//Release the public key
void clear_pkset(__pubkey_set* pubkey);


/****************  Initialized Square Compress Key.  ****************/

void init_sc_sk(__sc_prikey** prikey, __sec_setting* para);

void init_sc_pkset(__sc_pubkey_set** pubkey, __sc_prikey* prikey, __sec_setting* para);

void clear_sc_sk(__sc_prikey* prikey);

void clear_sc_pkset(__sc_pubkey_set* pubkey );


/****************  Initialized Ramdom Compress Key.  ****************/

void init_rc_sk(__rc_prikey** prikey, __sec_setting* para);

void init_rc_pkset(__rc_pubkey_set** pubkey, __sec_setting* para);

void clear_rc_sk(__rc_prikey* prikey);

void clear_rc_pkset(__rc_pubkey_set* pubkey);

/****************  Generated Ramdom Number.  ****************/
//gen_random.c

//Get random seeds
unsigned long get_seed();

/**
 * @brief Set the randstate object
 * Talk about random seeds combining with random states to prepare for the generation of random numbers
 * @param rs Random state
 * @param seed random seed
 */
void set_randstate(randstate rs, unsigned long seed);

/**
 * @brief Produces random numbers that do not exceed n bit bits
 *
 * @param rn mpz_t type of random number
 * @param rs random state
 * @param n random number length
 */
void gen_rrandomb(mpz_t rn, randstate rs, unsigned long n);

//Produces a random number that does not exceed the large integer ub
void gen_urandomm(mpz_t rn, randstate rs, mpz_t ub);


/****************  Generated Square Compress Private Key & Public Key.  ****************/

void randomize_scs(__sc_prikey* prikey);

void gen_sc_prikey(__sc_prikey* prikey, randstate rs);

void expand_sc_p2y(__sc_pubkey_set* pubkey, __sc_prikey* prikey, size_t prec, randstate rs);

void scXX(__sc_pubkey_set* pubkey, unsigned long index, randstate rs, size_t Rho, int type);

void encrypt_sc_sk(__sc_pubkey_set* pubkey, __sc_prikey* prikey, randstate rs, size_t Rho);

void gen_sc_pubkey(__sc_pubkey_set* pubkey, __sc_prikey* prikey, __sec_setting* para, randstate rs, int model);


/****************  Generated Random Compress Private Key & Public Key.  ****************/

void gen_rc_prikey(__rc_prikey* prikey, randstate rs);

void gen_rc_pubkey(__rc_pubkey_set* pubkey, __rc_prikey* prikey, __sec_setting* para);

void randomize_rsk(mpz_t* yy, mpz_t p, size_t rsk_bit_cnt, size_t ss_hw, size_t prec);

void expand_rc_p2y(__rc_pubkey_set* pubkey, __rc_prikey* prikey, size_t prec, randstate rs);


/****************  Generated Private Key & Public Key.  ****************/
//gen_key.c

/**
 * @brief Produces prime
 *
 * @param p Output prime number
 * @param n random number length
 * @param rs random state
 */
void gen_prime(mpz_t p, size_t n, randstate rs);

void mpf_round_mpz(mpz_t rop, mpf_t op);

//Rounding value of the large integer n/d picker q
void div_round_q(mpz_t q, mpz_t  n, mpz_t d);

//Determine whether b is a rough, a-rough: b with a minimum prime factor of no more than a
bool is_a_rough(mpz_t a, mpz_t b);

// The Q collection p in the resulting public key is the key, mpz_t q is the obtained Q collection
void getQs(mpz_t* q, mpz_t p, size_t gam, size_t tau, size_t lam, randstate rs);

//Randomly producing ss ss is a sparse subset ss_hw the size of a sparse subset ss_size sparse subset
void randomize_ss(mpz_t* ss, size_t ss_hw, size_t ss_size);

//Randomly producing ss_hw yy makes ∑yyi = 「(2^prec)/p」 (here「 」 approximate integer) prepare for the generation of 1/p=∑yi
void randomize_sk(mpz_t* yy, mpz_t p, size_t ss_hw, size_t prec);

//Convert the key p to 1/p=∑yi in the public key pubkey
void expand_p2y(__pubkey_set* pubkey, __prikey* prikey, size_t prec, randstate rs);

// Produces a private key primary
void gen_prikey(__prikey* prikey, randstate rs);

//To generate a public key pubkey, the private key prikey is required in the process of generating the public key, and the parameter para random state rs model indicates whether to encrypt the sparse subset in the key Placed in the public key 1 means 0 means no
void gen_pubkey(__pubkey_set* pubkey, __prikey* prikey, __sec_setting* para, randstate rs, int model);


/****************  Initialized Ciphertext.  ****************/
//ciphertext.c

//Initializing the redaction Theta is the Theta in the parameter
void init_cit(__cit** ciph, size_t Theta);

//Extended redaction zi = cyi is stored in the redaction ciph->z,i, a collection of pubkey bit public keys
void expend_cit(__cit* ciph, __pubkey_set* pubkey);

void expend_sc_cit(__cit* ciph, __sc_pubkey_set* pubkey);

void expend_rc_cit(__cit* ciph, __rc_pubkey_set* pubkey, unsigned long rsk_bit_cnt);

//Release the redaction
void clear_cit(__cit* ciph);

void swap_cit(__cit* ciph1, __cit* ciph2);


/****************  Encrypt & Decrypt.  ****************/
//crypto.c

/**
 * @brief DGHV encryption
 *
 * @param ciphertext encrypted redaction
 * @param plaintext clear text for 0,1 bit (homographic encryption encrypted in bits)
 * @param pubkey public key
 * @param para parameter
 * @param rs random state
 */
void DGHV_encrypt(__cit* ciphertext, unsigned long plaintext, __pubkey_set* pubkey, __sec_setting* para, randstate rs);

/**
 * @brief Decrypt
 *
 * @param ciphertext Decrypted redaction
 * @param prikey private key
 * @param pt_limit Largest-Plaintext number. Setting from security settings parameters
 * @return unsigned long
 */
unsigned long DGHV_decrypt(__cit* ciphertext, __prikey* prikey, mpz_t pt_limit);

void CMNT_encrypt(__cit* ciphertext, unsigned long plaintext, __sc_pubkey_set* pubkey, __sec_setting* para, randstate rs);

unsigned long CMNT_decrypt(__cit* ciphertext, __sc_prikey* prikey, mpz_t pt_limit);

void CNT_encrypt(__cit* ciphertext, mpz_t plaintext, __rc_pubkey_set* pubkey, __sec_setting* para);

mpz_class CNT_decrypt(__cit* ciphertext, __rc_prikey* prikey, mpz_t pt_limit);


/****************  Squashed Decrypt Circuitry.  ****************/
//squa_dec.c This part is not used for calling, this part is the compression decryption circuit used data structure and functions

void init_hw_table(__hw_table** hwtable, size_t x, size_t y);

void init_ev_table(__ev_table** evtable, size_t x, size_t y);

void clear_hw_table(__hw_table* hwtable);

void clear_ev_table(__ev_table* evtable);

void set_ev_table(unsigned long i, mpf_t z, __ev_table* ev_table);

void get_hw(int i, __ev_table* ev_table, __sec_setting* para);

unsigned long get_ciph_lsb(__cit* ciph);

unsigned long get_ciphdivp_lsb(__cit* ciph, __prikey* prikey, __sec_setting* para);

unsigned long get_sc_ciphdivp_lsb(__cit* ciph, __sc_prikey* prikey, __sec_setting* para);


/****************  Evaluated Addition & Multiplication.  ****************/
//eval_oper.c

//Homomorphic addition, and the resulting redaction sum that is added together is extended zi = cyi (no expansion is required if this redaction is not refreshed, so the same addition operation without extension is provided below)
// void evaluate_add_ex(__cit sum, __cit* c1, __cit* c2, __pubkey_set* pubkey);

//Same-state encryption operations without redaction extensions
void evaluate_add(__cit* sum, __cit* c1, __cit* c2, mpz_t x0);

//Same-stage multiplication operation with extension
// void evaluate_mul_ex(__cit* product, __cit* c1, __cit* c2, __pubkey_set* pubkey);

//Same-stage multiplication without extension
void evaluate_mul(__cit* product, __cit* c1, __cit* c2, mpz_t x0);

void evaluate_sub(__cit* diff, __cit* c1, __cit* c2, mpz_t x0);

void evaluate_c_div_ui(__cit* ceil_quotient, __cit* dividend, unsigned long divisor, mpz_t x0);

void evaluate_mod(__cit* result, __cit* c1, unsigned long modulo, mpz_t x0);

/****************  Bootstrapping.  ****************/
//bootstrapping.c

//The Hamming weight in column i is calculated, which is the entry (the entry here is expressed in redaction)
void c_get_hw(int i, __ev_table* ev_table, __sec_setting* para, mpz_t x0);

//Take the redaction ciph minimum valid bit, encrypt the minimum valid bit obtained redaction is stored in cc
void c_get_ciph_lsb(__cit* cc, __cit* ciph, __pubkey_set* pubkey, __sec_setting* para, randstate rs);

/**
 * @brief
 *  Take c/p = 「c∑(si.yi)」+（error does not write out, hahaha) the lowest effective bit, is calculated out the decimal point before and the last digit of the redaction in summation is his lowest significant bit of redaction
 *
 * @param cc The redaction of the lowest significant bit calculated
 * @param ciph The redaction that needs to be calculated
 * @param pubkey
 * @param para
 */
void c_get_ciphdivp_lsb(__cit* cc, __cit* ciph, __pubkey_set* pubkey, __sec_setting* para);

/**
 * @brief Redaction refresh
 *
 * @param cc Refreshed redactions
 * @param ciph The redaction that was refreshed
 * @param pubkey
 * @param para
 * @param rs
 */
void bootstrap(__cit* cc, __cit* ciph, __pubkey_set* pubkey, __sec_setting* para, randstate rs);

void c_get_sc_ciph_lsb(__cit* cc, __cit* ciph, __sc_pubkey_set* pubkey, __sec_setting* para, randstate rs);

void c_get_sc_ciphdivp_lsb(__cit* cc, __cit* ciph, __sc_pubkey_set* pubkey, __sec_setting* para);

void sc_bootstrap(__cit* cc, __cit* ciph, __sc_pubkey_set* pubkey, __sec_setting* para, randstate rs);


/****************  Key Switching.  ****************/

void Powersof2(mpf_t** s_expand, mpz_t* s, unsigned long length, unsigned long k);

void gen_switch_key(__rc_prikey* prikey, __rc_pubkey_set* pubkey, __sec_setting* para);


/****************  Modulus Switching.  ****************/

void BitDecomp(unsigned long** c_expand, mpz_t* z, unsigned long length, unsigned long k);

void mod_switch(__cit* newer, __cit* older, __rc_pubkey_set* pubkey, __sec_setting* para);


/****************  Base64 Encode & Decode.  ****************/

//int base64_encode(char *indata, int inlen, char *outdata, int *outlen);
int base64_encode(const char *in, int inlen, char *out);
std::string base64_encode(const char *in, int inlen);
std::string base64_encode(std::istream &in);

//int base64_decode(char *indata, int inlen, char *outdata, int *outlen);
int base64_decode(const char *in, int inlen, char *out);
int base64_decode(const char *in, std::size_t inlen, std::string &out);
std::string base64_decode(std::istringstream &in);

/****************  Format Ciphertext & Key Convert into String.  ****************/

char* format_ciphertext_str(__cit* ciph);

int format_privatekey_str(__prikey* prikey, char **buffer, int *length);
int format_rc_privatekey_str(__rc_prikey* prikey, char **buffer, int *length);

int format_publickey_str(__pubkey_set *pubkey, char **buffer, int *length);
int read_rc_publickey(__rc_pubkey_set* pubkey, std::istream &in);
std::vector<std::string> format_rc_publickey_str(__rc_pubkey_set *pubkey, int *length);


/****************  Format String Convert into Ciphertext & Key.  ****************/

int format_str_ciphertext(const char* buffer,  __cit* ciph);

int format_str_privatekey(char** buffer, int length, __prikey* prikey);
int format_str_rc_privatekey(char** buffer, int length, __rc_prikey* prikey);

int format_str_publickey(char **buffer, int length, __pubkey_set *pubkey);
int format_str_rc_publickey(std::vector<std::string> &buffer, int length, __rc_pubkey_set *pubkey);
int write_rc_publickey(__rc_pubkey_set* pubkey, std::ostream &out);


/****************  Read & Write Key.  ****************/

int save_sec_para(__sec_setting* para, const char* filename);

int save_prikey(__prikey* prikey, const char* prikey_filename);
int save_rc_prikey(__rc_prikey* prikey, const char* prikey_filename);

int save_pubkey(__pubkey_set* pubkey, const char* pubkey_filename);
int save_rc_pubkey(__rc_pubkey_set* pubkey, const char* pubkey_filename);

int save_str(char** buffer, signed long int length, const char* filename);
int __save_str(char** buffer, unsigned long int length, FILE* openFile);
int __save_1_str(char* str1, FILE* out);
void save_string(std::string* buffer, long length, const char *filename);
void __save_string(std::string* buffer, unsigned long length, std::ofstream& file);
void __save_1_string(std::string str1, std::ofstream& out);


int read_sec_para(__sec_setting* para, const char* filename);

int read_prikey(__prikey* prikey, const char* prikey_filename);
int read_rc_prikey(__rc_prikey* prikey, const char* prikey_filename);

int read_pubkey(__pubkey_set* pubkey, const char* pubkey_filename);
int read_rc_pubkey(__rc_pubkey_set* pubkey, const char* pubkey_filename);

char** read_str(const char* filename);
int malloc_buffer_read_file(char*** buffer, FILE* in);
unsigned int __read_str(FILE* openFile, char*** buffer);
char* __read_1_str(FILE* openFile);
char** read_string(const char* filename);
unsigned long malloc_buffer_read_file(std::ifstream& in, char ***buffer);
unsigned long __read_string(std::ifstream& openFile, char ***buffer);
char* __read_1_string(std::ifstream& openFile);

#endif
