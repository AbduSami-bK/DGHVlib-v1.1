/** Copyright (C) 2018-2019 SAU Network Communication Research Room.
 * This program is Licensed under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *	http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. See accompanying LICENSE file.
 */


#include "dghv.h"

char* format_ciphertext_str(__cit* ciph) {
	if (ciph == NULL) {
		return NULL;
	}
	char* buffer = (char*) malloc((MP_SIZE(ciph->c)*16 + W*W) * sizeof(char));
	mpz_get_str(buffer, W/2, ciph->c);

	return buffer;
}

int format_str_ciphertext(const char* buffer, __cit* ciph) {
	if(ciph == NULL || buffer == NULL){
		return -1;
	}
	mpz_set_str(ciph->c, buffer, W/2);
	return 0;
}

int format_privatekey_str(__prikey* prikey, char** buffer, int *length){
	if(prikey == NULL || buffer == NULL || length == NULL){
		return -1;
	}
	buffer[0] = (char*)malloc(8*W*sizeof(char));
	sprintf(buffer[0], "%lu %lu %lu", prikey->rsub_size, prikey->rsub_hw, prikey->sk_bit_cnt);

	buffer[1] = (char*)malloc((2 * prikey->rsub_size + 2) * sizeof(char));
	int j = 0;
	for (unsigned long i = 0; i < prikey->rsub_size; i++) {
		j += sprintf(buffer[1] + j, "%lu ", mpz_get_ui(prikey->sk_rsub[i]));
	}

	buffer[2] = (char*)malloc((MP_SIZE(prikey->sk)*16+W) * sizeof(char));
	mpz_get_str(buffer[2], W/2, prikey->sk);

	buffer[3] = (char*)malloc(W * sizeof(char));
	strcpy(buffer[3], prikey->gen_time);

	*length = 4;
	return 0;
}

int format_str_privatekey(char** buffer, int length, __prikey* prikey){
	if(prikey ==NULL || buffer == NULL || length <= -1){
		return -1;
	}

	sscanf(buffer[0], "%lu %lu %lu", &(prikey->rsub_size), &(prikey->rsub_hw), &(prikey->sk_bit_cnt));

	for(unsigned long i = 0; i < prikey->rsub_size; i++) {
		unsigned long val;
		sscanf(buffer[1] + i * 2, "%lu ", &val);
		mpz_set_ui(prikey->sk_rsub[i], val);
	}
	mpz_set_str(prikey->sk, buffer[2], W/2);

	strcpy(prikey->gen_time, buffer[3]);
	return 0;
}

int format_publickey_str(__pubkey_set* pubkey, char** buffer, int *length){
	if(pubkey == NULL || buffer == NULL || length == NULL){
		return -1;
	}

	unsigned long int i;
	int t, l = ((pubkey->pk_bit_cnt/W*W)/4) + W*W*W;
	buffer[0] = (char*)malloc(l * sizeof(char));
	sprintf(buffer[0], "%lu %lu %lu", pubkey->pks_size, pubkey->y_size, pubkey->pk_bit_cnt);

	for(i = 1; i < pubkey->pks_size + 1; i++){
		buffer[i] = (char*)malloc(l * sizeof(char));
		mpz_get_str(buffer[i], W/2, pubkey->pks[i-1]);
	}

	for(; i < pubkey->y_size + pubkey->pks_size + 1; i++){
		t = i - (pubkey->pks_size + 1);
		buffer[i] = (char*)malloc(l * sizeof(char));
		mpz_get_str(buffer[i], W/2, pubkey->cs[t]);
	}

	for(; i < 2 * pubkey->y_size + pubkey->pks_size + 1; i++){
		t = i - (pubkey->y_size + pubkey->pks_size + 1);
		buffer[i] = (char*)malloc(l * sizeof(char));
		int k = sprintf(buffer[i], "%d %d %lu # ", MP_PREC(pubkey->y[t]), MP_SIZE(pubkey->y[t]), MP_EXP(pubkey->y[t]));
		for(int j = 0; j < MP_SIZE(pubkey->y[t]); j++){
			k += sprintf(buffer[i] + k, "%lx ", LIMB(pubkey->y[t], j));
		}
	}

	buffer[i] = (char*)malloc(l * sizeof(char));
	strcpy(buffer[i], pubkey->gen_time);
	*length = ++i;
	return 0;
}

int format_str_publickey(char** buffer, int length, __pubkey_set* pubkey) {
	unsigned long int i;
	int j;
	if(buffer == NULL || pubkey == NULL || length <= -1){
		return -1;
	}

	sscanf(buffer[0], "%lu %lu %lu", &(pubkey->pks_size), &(pubkey->y_size), &(pubkey->pk_bit_cnt));
	for(i = 1; i < pubkey->pks_size + 1; i++){
		mpz_set_str(pubkey->pks[i - 1], buffer[i], W/2);
	}

	for(; i < pubkey->y_size + pubkey->pks_size + 1; i++){
		j = i-(pubkey->pks_size + 1);
		mpz_set_str(pubkey->cs[j], buffer[i], W/2);
	}

	for(; i < 2 * pubkey->y_size + pubkey->pks_size + 1; i++){
		__mpf_struct* tmp;

		j = i-(pubkey->y_size + pubkey->pks_size + 1);
		tmp = (__mpf_struct*)malloc(sizeof(__mpf_struct));
		sscanf(buffer[i], "%d %d %lu ", &(tmp->_mp_prec), &(tmp->_mp_size), &(tmp->_mp_exp));
		tmp->_mp_d = (mp_limb_t*)malloc(tmp->_mp_size*sizeof(mp_limb_t));

		const char* buf = strchr(buffer[i], '#');
		for(int k = 0; k < tmp->_mp_size; ++k){
			buf = strchr(buf, ' ') + 1;
			sscanf(buf, "%lx", &tmp->_mp_d[k]);
		}
		mpf_set(pubkey->y[j], tmp);
		mpf_clear(tmp);
	}

	mpz_set(pubkey->x0, pubkey->pks[0]);
	strcpy(pubkey->gen_time, buffer[i]);
	return 0;
}

int format_rc_privatekey_str(__rc_prikey* prikey, char** buffer, int *length) {
	if (prikey == NULL || buffer == NULL || length == NULL) {
		return -1;
	}
	buffer[0] = (char*) malloc(10 * W * sizeof (char));
	sprintf(buffer[0], "%lu %lu %lu %lu", prikey->rsub_size, prikey->rsub_hw, prikey->sk_bit_cnt, prikey->rsk_bit_cnt);

	buffer[1] = (char*) malloc((2 * prikey->rsub_size + 2) * sizeof (char));
	int j = 0;
	for (unsigned long i = 0; i < prikey->rsub_size; i++) {
		j += sprintf(buffer[1] + j, "%lu ", mpz_get_ui(prikey->sk_rsub[i]));
	}

	buffer[2] = (char*) malloc((MP_SIZE(prikey->sk) * 16 + W) * sizeof (char));
	mpz_get_str(buffer[2], W/2, prikey->sk);

	buffer[3] = (char*) malloc((MP_SIZE(prikey->rsk) * 16 + W) * sizeof (char));
	mpz_get_str(buffer[3], W/2, prikey->rsk);

	buffer[4] = (char*) malloc(W * sizeof (char));
	strcpy(buffer[4], prikey->gen_time);

	*length = 5;
	return 0;
}

int format_str_rc_privatekey(char** buffer, int length, __rc_prikey* prikey) {
	if (prikey ==NULL || buffer == NULL || length <= -1) {
		return -1;
	}

	sscanf(buffer[0], "%lu %lu %lu %lu", &(prikey->rsub_size), &(prikey->rsub_hw), &(prikey->sk_bit_cnt), &(prikey->rsk_bit_cnt));

	for (unsigned long i = 0; i < prikey->rsub_size; i++) {
		unsigned long val;
		sscanf(buffer[1] + i * 2, "%lu ", &val);
		mpz_set_ui(prikey->sk_rsub[i], val);
	}
	mpz_set_str(prikey->sk, buffer[2], W/2);
	mpz_set_str(prikey->rsk, buffer[3], W/2);

	strcpy(prikey->gen_time, buffer[4]);
	return 0;
}

int format_rc_publickey_str(__rc_pubkey_set* pubkey, char** buffer, int *length) {
	if (pubkey == NULL || buffer == NULL || length == NULL) {
		return -1;
	}

	// buffer index
	unsigned long int i;
	int l = pubkey->pk_bit_cnt/W*W + W*W*W;

	// Static sized numbers
	buffer[0] = (char*) malloc(11 * 6 * sizeof (char));		// 11 = log10(LONG_MAX) + 1 (for the space)
	sprintf(buffer[0], "%lu %lu %lu %lu %lu %lu", pubkey->sx, pubkey->sy, pubkey->pks_size, pubkey->y_size, pubkey->pk_bit_cnt, pubkey->seed);

	// delta
	for (i = 1; i < pubkey->pks_size + 1; ++i) {
		buffer[i] = (char*) malloc(W/2 * sizeof (char));
		mpz_get_str(buffer[i], W/2, pubkey->delta[i - 1]);
	}

	// x0
	buffer[i] = (char*) malloc(W/2 * sizeof (char));
	mpz_get_str(buffer[i++], W/2, pubkey->x0);
	buffer[i] = (char*) malloc(W/2 * sizeof (char));
	mpz_get_str(buffer[i++], W/2, pubkey->rx0);

	// y
	for (; i < pubkey->y_size + pubkey->pks_size + 3; ++i) {
		int t = i - (pubkey->pks_size + 3);
		buffer[i] = (char*) malloc(l * sizeof(char));
		int k = sprintf(buffer[i], "%d %d %lu # ", MP_PREC(pubkey->y[t]), MP_SIZE(pubkey->y[t]), MP_EXP(pubkey->y[t]));
		for (int j = 0; j < MP_SIZE(pubkey->y[t]); ++j) {
			k += sprintf(buffer[i] + k, "%lx ", LIMB(pubkey->y[t], j));
		}
	}

	// sigma
	for (unsigned long t = 0; i < pubkey->sx * pubkey->sy + pubkey->y_size + pubkey->pks_size + 3; ++t) {
		for (unsigned long j = 0; j < pubkey->sy; ++j, ++i) {
			buffer[i] = (char*) malloc(W/2 * sizeof (char));
			mpz_get_str(buffer[i], W/2, pubkey->sigma[t][j]);
		}
	}

	// gen_time
	buffer[i] = (char*) malloc(20 * sizeof(char));
	strcpy(buffer[i], pubkey->gen_time);

	*length = ++i;
	return 0;
}

int format_str_rc_publickey(char** buffer, int length, __rc_pubkey_set* pubkey) {
	if (buffer == NULL || pubkey == NULL || length <= -1) {
		return -1;
	}

	// buffer index
	unsigned long int i;

	// Static sized members
	sscanf(buffer[0], "%lu %lu %lu %lu %lu %lu", &(pubkey->sx), &(pubkey->sy), &(pubkey->pks_size), &(pubkey->y_size), &(pubkey->pk_bit_cnt), &(pubkey->seed));

	// delta
	for (i = 1; i < pubkey->pks_size + 1; ++i) {
		mpz_set_str(pubkey->delta[i - 1], buffer[i], W/2);
	}

	// x0
	mpz_set_str(pubkey->x0, buffer[i++], W/2);
	mpz_set_str(pubkey->rx0, buffer[i++], W/2);

	// y
	for (; i < pubkey->y_size + pubkey->pks_size + 3; ++i) {
		__mpf_struct* tmp;

		int j = i - pubkey->y_size - pubkey->pks_size - 3;
		tmp = (__mpf_struct*) malloc(sizeof(__mpf_struct));
		sscanf(buffer[i], "%d %d %lu ", &(tmp->_mp_prec), &(tmp->_mp_size), &(tmp->_mp_exp));
		tmp->_mp_d = (mp_limb_t*) malloc(tmp->_mp_size * sizeof(mp_limb_t));

		char* buf = strchr(buffer[i], '#');
		for (int k = 0; k < tmp->_mp_size; ++k) {
			buf = strchr(buf, ' ') + 1;
			sscanf(buf, "%lx", &tmp->_mp_d[k]);
		}
		mpf_set(pubkey->y[j], tmp);
		mpf_clear(tmp);
		free(tmp->_mp_d);	// TODO See if not needed
		free(tmp);
	}

	// sigma
	for (unsigned long t = 0; i < pubkey->sx * pubkey->sy + pubkey->y_size + pubkey->pks_size + 3; ++t) {
		for (unsigned long j = 0; j < pubkey->sy; ++j, ++i) {
			mpz_set_str(pubkey->sigma[t][j], buffer[i], W/2);
		}
	}

	// gen_time
	strcpy(pubkey->gen_time, buffer[i]);
	return 0;
}
