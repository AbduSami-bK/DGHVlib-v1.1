/* Copyright (C) 2018-2019 SAU Network Communication Research Room.
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
#include "dghv.h"

void evaluate_add(__cit* sum, __cit* c1, __cit* c2, mpz_t x0)
{
    mpz_add(sum->c, c1->c, c2->c);
	mpz_mod(sum->c, sum->c, x0);
}

void evaluate_sub(__cit* diff, __cit* c1, __cit* c2, mpz_t x0)
{
    mpz_sub(diff->c, c1->c, c2->c);
	mpz_mod(diff->c, diff->c, x0);
}

void evaluate_mul(__cit* product, __cit* c1, __cit* c2, mpz_t x0)
{
	mpz_mul(product->c, c1->c, c2->c);
	mpz_mod(product->c, product->c, x0);
}

void evaluate_c_div_ui(__cit* ceil_quotient, __cit* dividend, unsigned long divisor, mpz_t x0)
{
	mpz_cdiv_q_ui(ceil_quotient->c, dividend->c, divisor);
	mpz_mod(ceil_quotient->c, ceil_quotient->c, x0);
}

void evaluate_mod(__cit* result, __cit* c1, unsigned long modulo, mpz_t x0)
{
	mpz_mod_ui(result->c, c1->c, modulo);
	mpz_mod(result->c, result->c, x0);
}