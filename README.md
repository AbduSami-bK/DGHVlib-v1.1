# DGHVlib-v1.1
This repository is about the implementation of homomorphic encryption scheme (DGHV/DGHVlib-v1.1.a).
(translated with [bing.com](www.bing.com "Bing"))

Using gmp large number operation library and gcc compilation tool independently completed the integer on the homomorphic encryption library DGHVlib, functions include key pair generation, encryption, decryption, homomorphic addition operation, homomorphic multiplication operation, compression decryption circuit, redaction refresh, secondary offset public key compression algorithm, random offset public key compression algorithm, key conversion and mode conversion algorithm.

This version adds a secondary offset public key compression algorithm, a random offset public key compression algorithm, a key conversion and an die conversion algorithm to the https://github.com/limengfei1187/DGHVlib's DGHVlib.

You can compile it yourself, go into the src folder to open the terminal make and be able to compile into a static link library libdghv.a This homographic encryption library is done in the ubuntu environment, using the linux system date function, which needs to be used in the linux environment. You can run test code by copying the resulting libdghv.a and dghv.h header files to the test folder.

```c
#define TOY 0 // is a parameter level. See secstg.h you can also set it yourself and verify that the parameters are reasonable with the
            //bool para_valid (__sec_setting-para)
#define SMALL 1
#define MEDIUM 2
#define LARGE 3

#define PROB_EXP 50
#define BASE 2
#define PRIHL 7
#define PUBHL 8

#define W (GMP_NUMB_BITS/2)
#define _LSBMASK 1ul
#define _MSBMASK (1ul << (2 * W - 1))
#define _BOT_N_MASK(n) ((_LSBMASK << n) - 1)
#define _TOP_N_MASK(n) (_BOT_N_MASK(n) << (2 * W - n))

#define R_N_SHIFT(x, n) (x >> n)
#define L_N_SHIFT(x, n) (x << n)
#define MP_EXP(x) (x->_mp_exp) //Get the _mp_exp in the big floating points in the GMP library mpf_t see the gmp.h 197 line comment
#define MP_SIZE(x) (x->_mp_size) //mpf_t the number of limbs in , each limb is an unsigned long shaped pointer that holds 64 decimal places in a large number
#define MP_PREC(x) (x->_mp_prec) //mpf_t Precision in indicates that there are _mp_prec limbs representing fractional parts.
#define MP_ALLOC(x) (x->_mp_alloc) //mpz_t The number of limbs in a large integer
#define LIMB(x, i) (((i)<((x)->_mp_size))?((x)->_mp_d[i]):(0L)) //Get the ith limb of the mpf_t or mpz_t
#define LSB(x) (x & _LSBMASK) //take the lowest significant bit
#define MSB(x) (x & _MSBMASK) //take the most significant bit
#define MSBN(x, n) (x & (_TOP_N_MASK(n))) //The highest N-bit valid bit needs to be moved 2W-N bits to the right again in order to get it correctly
#define LSBN(x, n) (x & (_BOT_N_MASK(n))) //The lowest N-bit significant bit
#define MIN_ETA(x) (21 * x + 50) // The minimum key length when n=5 in the argument.

// The parameter type
typedef struct securitySetting {
    size_t lam; //Security parameters
    size_t Rho; //Noise in the public key
    size_t rho; //Encrypted noise
    size_t eta; //The length of the key
    size_t gam; //The length of the public key
    size_t Theta; // The number of bits of the sparse subset
    size_t theta; // The Hamming weight of the sparse subset
    size_t tau; //The number of public keys
    size_t prec; // the accuracy after the decimal point of yi
    size_t n; //bootstrapping takes the n-bit after the decimal point, i.e. the c*yi takes the decimal point after the n-bit participates in the redaction refresh.
}__sec_setting;

//The type of private key
typedef struct privatekey {
    mpz_t sk; // Private
    mpz_t* sk_rsub; // Sparse subset
    size_t rsub_size; // Sparse subset size
    size_t rsub_hw; //Sparse subset Hamming weights
    size_t sk_bit_cnt;//Private key bit length
    char gen_time[20];// Death produces time
}__prikey;

typedef struct publickeyset {
    mpz_t x0; //The longest public key mode x0 controls the length of the redaction
    mpz_t *pks; // The collection of public keys
    mpz_t *cs; // A sparse subset after encryption
    mpf_t *y; // 1/p = y1+y2+...
    size_t pks_size; // The number of jobs
    size_t y_size; //the number of yi
    size_t pk_bit_cnt; // The length of the public key bit
    char gen_time[20]; // The time to produce
}__pubkey_set;

//The type of redaction
typedef struct ciphertext {
    mpz_t c; // ciphertext
    mpf_t z; //Extended redaction zi=cyi
    size_t z_size; // zi's number
}__cit; //ciphertext

//Hamming Weight Calculation Table
typedef struct hamming_weight_table {
    mpz_t **table;
    size_t x;
    size_t y;
}__hw_table;

//The secret updates the calculation table
typedef struct evaluation_table {
    mpz_t **table;
    size_t x;
    size_t y;
}__ev_table;

typedef gmp_randstate_t randstate; // Random state
typedef __prikey* c_prikey; // The type of key pointer
typedef __pubkey_set* c_pubkeys; // The type of public key pointer
typedef __sec_setting* c_parameters; // The type of argument pointer
typedef __cit* c_cit; //The type of redacted pointer

/**************** Security Parameters Setting. ****************/
//secstg.c

//Initialize the parameters
void init_sec_para(__sec_setting** para);

//Initialize the default parameters TOY, SMALL, MEDIUM, LARGE four levels you can set yourself specific parameters in the secstg.c
void set_default_para(__sec_setting* para, int level);

//Verify that the parameter settings are reasonable
bool para_valid(__sec_setting* para);

/**************** Initialized Key. ****************/
//key.c

//Initializing the private key requires parameter initialization, so the parameters must be initialized before the private key can be initialized, and the parameters are set
void init_sk(__prikey** prikey, __sec_setting* para);

//Initialize the collection of public keys
void init_pkset(__pubkey_set** pubkey, __sec_setting* para);

//Release the private key
void clear_sk(__prikey* prikey);

//Release the public key
void clear_pkset(__pubkey_set* pubkey);

/**************** Generated Random Number. ****************/
//gen_random.c

//Get random seeds
unsigned long get_seed();

//Talk about random seeds combining with random states to prepare for the generation of random numbers
//Random state type randstate, seed random seed
void set_randstate(randstate rs, unsigned long seed);

//Produces random numbers that do not exceed n bit bits
//rn：mpz_t type of random number, rs random state, n random number length
void gen_rrandomb(mpz_t rn, randstate rs, unsigned long n);

//Produces a random number that does not exceed the large integer ub
void gen_urandomm(mpz_t rn, randstate rs, mpz_t ub);

/**************** Generated Private Key & Public Key. ******/
//gen_key.c

//Produces prime prime number p, n random number length, rs random state
void gen_prime(mpz_t p, size_t n, randstate rs);

//Rounding value of the large integer n/d picker q
void div_round_q(mpz_t q, mpz_t n, mpz_t d);

//Determine whether b is a rough, a-rough: b with a minimum prime factor of no more than a
bool is_a_rough(mpz_t a, mpz_t b);

// The Q collection p in the resulting public key is the key, mpz_t q is the obtained Q collection
void getQs(mpz_t q, mpz_t p, size_t gam, size_t tau, size_t lam, randstate rs);

//Randomly producing ss ss is a sparse subset ss_hw the size of a sparse subset ss_size sparse subset
void randomize_ss(mpz_t ss, size_t ss_hw, size_t ss_size);

//Randomly producing ss_hw yy makes ∑yyi = 「(2^prec)/p」 (here「 」 approximate integer) prepare for the generation of 1/p=∑yi
void randomize_sk(mpz_t yy, mpz_t p, size_t ss_hw, size_t prec);

//Convert the key p to 1/p=∑yi in the public key pubkey
void expand_p2y(__pubkey_set pubkey, __prikey prikey, size_t prec, randstate rs);

// Produces a private key primary
void gen_prikey(__prikey prikey, randstate rs);

//To generate a public key pubkey, the private key prikey is required in the process of generating the public key, and the parameter para random state rs model indicates whether to encrypt the sparse subset in the key Placed in the public key 1 means 0 means no
void gen_pubkey(__pubkey_set pubkey, __prikey prikey, __sec_setting para, randstate rs, int model);

/**************** Initialized Ciphertext. ****************/
//ciphertext.c

//Initializing the redaction Theta is the Theta in the parameter
void init_cit(__cit** ciph, size_t Theta);

//Extended redaction zi = cyi is stored in the redaction ciph->z,i, a collection of pubkey bit public keys
void expend_cit(__cit ciph, __pubkey_set* pubkey);

//Release the redaction
void clear_cit(__cit* ciph);

/**************** Encrypt & Decrypt. ****************/
//crypto.c

//DGHV encryption ciphertext encrypted redaction, plaintext: clear text for 0,1 bit (homographic encryption encrypted in bits) pubkey: public key para:parameter rs: random state
void DGHV_encrypt(__cit* ciphertext, unsigned long plaintext, __pubkey_set* pubkey, __sec_setting* para, randstate rs);

//Decrypt ciphertext: Decrypted redaction, prikey private key
unsigned long DGHV_decrypt(__cit* ciphertext, __prikey* prikey);

/**************** Squashed Decrypt Circuitry. **************/
//squa_dec.c This part is not used to say, this part is the compression decryption circuit used data structure and functions
void init_hw_table(__hw_table hwtable, size_t x, size_t y);

void init_ev_table(__ev_table** evtable, size_t x, size_t y);

void clear_hw_table(__hw_table* hwtable);

void clear_ev_table(__ev_table* evtable);

void set_ev_table(unsigned long i, mpf_t z, __ev_table* ev_table);

void get_hw(int i, __ev_table* ev_table, __sec_setting* para);

unsigned long get_ciph_lsb(__cit* ciph);

unsigned long get_ciphdivp_lsb(__cit* ciph, __prikey* prikey, __sec_setting* para);

/**************** Evaluated Addition & Multiplication. ****************/
//eval_oper.c

//Homomorphic addition, and the resulting redaction sum that is added together is extended zi = cyi (no expansion is required if this redaction is not refreshed, so the same addition operation without extension is provided below)
void evaluate_add_ex(__cit sum, __cit* c1, __cit* c2, __pubkey_set* pubkey);

//Same-state encryption operations without redaction extensions
void evaluate_add(__cit* sum, __cit* c1, __cit* c2, mpz_t x0);

//Same-stage multiplication operation with extension
void evaluate_mul_ex(__cit* product, __cit* c1, __cit* c2, __pubkey_set* pubkey);

//Same-stage multiplication without extension
void evaluate_mul(__cit* product, __cit* c1, __cit* c2, mpz_t x0);

/**************** Bootstrapping. ****************/
//bootstrapping.c

//The Hamming weight in column i is calculated, which is the entry (the entry here is expressed in redaction)
void c_get_hw(int i, __ev_table* ev_table, __sec_setting* para, mpz_t x0);

//Take the redaction ciph minimum valid bit, encrypt the minimum valid bit obtained redaction is stored in cc
void c_get_ciph_lsb(__cit* cc, __cit* ciph, __pubkey_set* pubkey, __sec_setting* para, randstate rs);

//Take c/p = 「c∑siyi」+（error does not write out, hahaha) the lowest effective bit, is calculated out the decimal point before and the last digit of the redaction in summation is his lowest significant bit of redaction
//ciph The redaction that needs to be calculated
//cc The redaction of the lowest significant bit calculated
void c_get_ciphdivp_lsb(__cit* cc, __cit* ciph, __pubkey_set* pubkey, __sec_setting* para);

// Redaction refresh cc Refreshed redactions， ciph The redaction that was refreshed
void bootstrap(__cit* cc, __cit* ciph, __pubkey_set* pubkey, __sec_setting* para, randstate rs);

```