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
#include <sstream>
#include <iostream>

char* format_ciphertext_str(__cit* ciph) {
	if (ciph == NULL) {
		return NULL;
	}
	char* buffer = (char*) malloc((MP_SIZE(ciph->c)*16 + W*W) * sizeof(char));
	mpz_get_str(buffer, W/2, ciph->c);

	return buffer;
}

std::ostream& operator<<(std::ostream& out, __citpp* ciph) {
	if (ciph == NULL) {
		return out;
	}
	out << ciph->c;

	return out;
}

std::string format_ciphertext_str(__citpp* ciph) {
	if (ciph == NULL) {
		return NULL;
	}
	return ciph->c.get_str();
}

int format_str_ciphertext(const char* buffer, __cit* ciph) {
	if (ciph == NULL || buffer == NULL) {
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

std::vector<std::string> format_rc_privatekey_str(__rc_prikey prikey) {
	std::vector<std::string> out;
	std::ostringstream oBuf;

	oBuf << prikey.rsub_size << " "
		<< prikey.rsub_hw << " "
		<< prikey.sk_bit_cnt << " "
		<< prikey.rsk_bit_cnt;

	out.push_back(oBuf.str());
	oBuf.str("");	// Clear contents

	for (unsigned long i = 0; i < prikey.rsub_size; ++i) {
		oBuf << mpz_get_ui(prikey.sk_rsub[i]) << " ";
	}
	out.push_back(oBuf.str());
	oBuf.str("");

	// void (*freefunc)(void *, size_t);
	// mp_get_memory_functions (NULL, NULL, &freefunc);

	// char * buf = mpz_get_str(NULL, W/2, prikey.sk);
	// out.push_back(buf);
	out.push_back(mpz_class(prikey.sk).get_str());
	// freefunc(buf, strlen(buf) + 1);

	// buf = mpz_get_str(NULL, W/2, prikey.rsk);
	// out.push_back(buf);
	out.push_back(mpz_class(prikey.rsk).get_str());
	// freefunc(buf, strlen(buf) + 1);

	out.push_back(prikey.gen_time);

	return out;
}

std::ostream& operator<<(std::ostream& out, __rc_prikey prikey) {
	out << prikey.rsub_size << " " << prikey.rsub_hw << " " << prikey.sk_bit_cnt << " " << prikey.rsk_bit_cnt << std::endl;

	for (unsigned long i = 0; i < prikey.rsub_size; ++i) {
		out << mpz_get_ui(prikey.sk_rsub[i]) << " ";
	}
	out << std::endl;

	char * buffer = (char*) malloc((MP_SIZE(prikey.sk) * 16 + W) * sizeof (char));

	mpz_get_str(buffer, W/2, prikey.sk);
	out << buffer << std::endl;

	mpz_get_str(buffer, W/2, prikey.rsk);
	out << buffer << std::endl;

	void (*freefunc)(void *, size_t);
	mp_get_memory_functions (NULL, NULL, &freefunc);
	freefunc(buffer, strlen(buffer) + 1);

	out << prikey.gen_time;

	return out;
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

int format_str_rc_privatekey(std::vector<std::string>& buffer, __rc_prikey* prikey) {
	if (prikey == NULL || buffer.empty()) {
		return -1;
	}
	std::istringstream iBuf(buffer[0]);
	iBuf >> prikey->rsub_size >> prikey->rsub_hw >> prikey->sk_bit_cnt >> prikey->rsk_bit_cnt;

	iBuf.str(buffer[1]);
	for (unsigned long i = 0; i < prikey->rsub_size; i++) {
		unsigned long val;
		iBuf >> val;
		mpz_set_ui(prikey->sk_rsub[i], val);
	}
	mpz_set_str(prikey->sk, buffer[2].c_str(), W/2);
	mpz_set_str(prikey->rsk, buffer[3].c_str(), W/2);

	strcpy(prikey->gen_time, buffer[4].c_str());
	return 0;
}

/*__rc_prikey format_str_rc_privatekey(std::vector<std::string> &buffer) {
	__rc_prikey prikey;

	if (buffer.empty()) {
		return prikey;
	}

	std::istringstream iBuf(buffer[0]);
	iBuf >> prikey.rsub_size >> prikey.rsub_hw >> prikey.sk_bit_cnt >> prikey.rsk_bit_cnt;

	iBuf.str(buffer[1]);
	prikey.sk_rsub = (mpz_t *) malloc(prikey.rsub_size * sizeof(mpz_t));
	for (unsigned long i = 0; i < prikey.rsub_size; i++) {
		unsigned long val;
		iBuf >> val;
		mpz_init_set_ui(prikey.sk_rsub[i], val);
	}
	mpz_init_set_str(prikey.sk, buffer[2].c_str(), W/2);
	mpz_init_set_str(prikey.rsk, buffer[3].c_str(), W/2);

	strcpy(prikey.gen_time, buffer[4].c_str());
	return prikey;
}*/

std::istream& operator>>(std::istream& in, __rc_prikey prikey) {
	in >> prikey.rsub_size >> prikey.rsub_hw >> prikey.sk_bit_cnt >> prikey.rsk_bit_cnt;

	prikey.sk_rsub = (mpz_t *) malloc(prikey.rsub_size * sizeof(mpz_t));
	for (unsigned long i = 0; i < prikey.rsub_size; ++i) {
		unsigned long val;
		in >> val;
		mpz_init_set_ui(prikey.sk_rsub[i], val);
	}
	std::string buffer;

	in >> buffer;
	mpz_init_set_str(prikey.sk, buffer.c_str(), W/2);
	in >> buffer;
	mpz_init_set_str(prikey.rsk, buffer.c_str(), W/2);

	in >> prikey.gen_time;

	return in;
}

std::vector<std::string> format_rc_publickey_str(__rc_pubkey_set* pubkey, int *length) {
	if (pubkey == NULL || length == NULL) {
		return {};
	}

	// buffer
	std::vector<std::string> buffer;
	unsigned long int i;
	//int l = pubkey->pk_bit_cnt/W*W + W*W*W;
	//void (*freefunc)(void *, size_t);
	//mp_get_memory_functions (NULL, NULL, &freefunc);

	// Static sized numbers
	{
		//char *temp = (char*) malloc(11 * 6 * sizeof (char));		// 11 = log10(LONG_MAX) + 1 (for the space)
		//sprintf(temp, "%lu %lu %lu %lu %lu %lu", pubkey->sx, pubkey->sy, pubkey->pks_size, pubkey->y_size, pubkey->pk_bit_cnt, pubkey->seed);
		std::ostringstream temp;
		temp
//			<< std::to_string(pubkey->sx) << " "
//			<< std::to_string(pubkey->sy) << " "
//			<< std::to_string(pubkey->pks_size) << " "
//			<< std::to_string(pubkey->y_size) << " "
//			<< std::to_string(pubkey->pk_bit_cnt) << " "
			<< std::to_string(pubkey->seed);
		buffer.push_back(temp.str());
	}

	// Help from https://stackoverflow.com/a/15691617/9600987

	// delta
	for (i = 1; i < pubkey->pks_size + 1; ++i) {
		//char *temp = mpz_get_str(NULL, W/2, pubkey->delta[i - 1]);
		buffer.push_back(mpz_class(pubkey->delta[i - 1]).get_str());
		//freefunc(temp, strlen(temp) + 1);
	}

	// x0
	{
		//char *temp = mpz_get_str(NULL, W/2, pubkey->x0);
		buffer.push_back(mpz_class(pubkey->x0).get_str());
		//freefunc(temp, strlen(temp) + 1);
		++i;
	}
//	{
		//char *temp = mpz_get_str(NULL, W/2, pubkey->rx0);
//		buffer.push_back(mpz_class(pubkey->rx0).get_str());
		//freefunc(temp, strlen(temp) + 1);
//		++i;
//	}

	// y
//	for (; i < pubkey->y_size + pubkey->pks_size + 3; ++i) {
//		int t = i - (pubkey->pks_size + 3);
//		std::ostringstream temp;	// = (char*) malloc(l * sizeof(char));
		//sprintf(temp, "%d %d %lu # ", MP_PREC(pubkey->y[t]), MP_SIZE(pubkey->y[t]), MP_EXP(pubkey->y[t]));
//		temp << std::to_string(MP_PREC(pubkey->y[t])) << " "
//			<< std::to_string(MP_SIZE(pubkey->y[t])) << " "
//			<< std::to_string(MP_EXP(pubkey->y[t])) << " # ";
//		for (int j = 0; j < MP_SIZE(pubkey->y[t]); ++j) {
			//sprintf(temp, "%lx ", LIMB(pubkey->y[t], j));
//			temp << std::to_string(LIMB(pubkey->y[t], j)) << " ";
//		}
//		buffer.push_back(temp.str());
		//free(temp);
//	}

	// sigma
//	for (unsigned long t = 0; i < pubkey->sx * pubkey->sy + pubkey->y_size + pubkey->pks_size + 3; ++t) {
//		for (unsigned long j = 0; j < pubkey->sy; ++j, ++i) {
			//char *temp = mpz_get_str(NULL, W/2, pubkey->sigma[t][j]);
//			buffer.push_back(mpz_class(pubkey->sigma[t][j]).get_str());
			//freefunc(temp, strlen(temp) + 1);
//		}
//	}

	// gen_time
	//buffer[i] = (char*) malloc(20 * sizeof(char));
	buffer.push_back(pubkey->gen_time);

	*length = ++i;
	return buffer;
}

std::vector<std::string> format_rc_publickey_str(__rc_pubkey_set pubkey) {
	// Output Buffer
	std::vector<std::string> out;
	std::ostringstream oBuf;

	// Static sized numbers
	{
		oBuf
			<< pubkey.sy << " "
			<< pubkey.sx << " "
			<< pubkey.pks_size << " "
			<< pubkey.y_size << " "
			<< pubkey.pk_bit_cnt << " "
			<< pubkey.seed;
		out.push_back(oBuf.str());
		oBuf.str("");	// Clear contents;
	}

	void (*freefunc)(void *, size_t);
	mp_get_memory_functions (NULL, NULL, &freefunc);

	// delta
	for (unsigned long i = 0; i < pubkey.pks_size; ++i) {
		oBuf << mpz_get_ui(pubkey.delta[i]) << " ";
	}
	out.push_back(oBuf.str());
	oBuf.str("");

	// x0
	{
		//char *temp = mpz_get_str(NULL, W/2, pubkey.x0);
		out.push_back(mpz_class(pubkey.x0).get_str());
		//freefunc(temp, strlen(temp) + 1);
	}
	{
		//char *temp = mpz_get_str(NULL, W/2, pubkey.rx0);
		out.push_back(mpz_class(pubkey.rx0).get_str());
		//freefunc(temp, strlen(temp) + 1);
	}

	// y
	for (unsigned long i = 0; i < pubkey.y_size; ++i) {
		std::ostringstream temp;
		temp << MP_PREC(pubkey.y[i]) << " "
			<< MP_SIZE(pubkey.y[i]) << " "
			<< MP_EXP(pubkey.y[i]) << " # ";
		for (int j = 0; j < MP_SIZE(pubkey.y[i]); ++j) {
			//sprintf(temp, "%lx ", LIMB(pubkey.y[i], j));
			temp << LIMB(pubkey.y[i], j) << " ";
		}
		out.push_back(temp.str());
		//free(temp);
	}

	// sigma
	for (unsigned long t = 0; t < pubkey.sy; ++t) {
		for (unsigned long j = 0; j < pubkey.sy; ++j) {
			//char *temp = mpz_get_str(NULL, W/2, pubkey.sigma[t][j]);
			out.push_back(mpz_class(pubkey.sigma[t][j]).get_str());
			//freefunc(temp, strlen(temp) + 1);
		}
	}

	// gen_time
	out.push_back(pubkey.gen_time);

	return out;
}

int write_rc_publickey(__rc_pubkey_set* pubkey, std::ostream &out) {
	if (pubkey == NULL) {
		return -1;
	}

	int length = 0;

	// Static sized numbers
	out
		// << pubkey->sx << " " << pubkey->sy << " "
		<< pubkey->pks_size //<< " " << pubkey->y_size << " "
		// << pubkey->pk_bit_cnt << " "
	<< pubkey->seed << "\n";
	++length;

	// delta
	for (unsigned long i = 0; i < pubkey->pks_size; ++i) {
		out << pubkey->delta[i] << " ";
	}
	out << "\n";
	++length;

	// x0
	out << pubkey->x0 << "\n";
//	out << pubkey->rx0 << "\n";
//	length += 2;

	// y
//	for (unsigned long i = 0; i < pubkey->y_size; ++i) {
//		out << std::to_string(MP_PREC(pubkey->y[i])) << " "
//			<< std::to_string(MP_SIZE(pubkey->y[i])) << " "
//			<< std::to_string(MP_EXP(pubkey->y[i])) << " # ";
//		for (int j = 0; j < MP_SIZE(pubkey->y[i]); ++j) {
//			out << std::to_string(LIMB(pubkey->y[i], j)) << " ";
//		}
//		out << "\n";
//		++length;
//	}

	// sigma
//	for (unsigned long i = 0; i < pubkey->sx; ++i) {
//		for (unsigned long j = 0; j < pubkey->sy; ++j) {
//			out << pubkey->sigma[i][j] << " ";
//		}
//		out << "\n";
//		++length;
//	}

	// gen_time
//	out << pubkey->gen_time << "\n";

	return ++length;
}

std::ostream& operator<<(std::ostream& out, __rc_pubkey_set pubkey) {
	write_rc_publickey(&pubkey, out);		// Address of a shallow copy
	return out;
}

int format_str_rc_publickey(std::vector<std::string> &buffer, __rc_pubkey_set* pubkey) {
	if (buffer.empty() || pubkey == NULL) {
		return -1;
	}

	// buffer index
	unsigned long int index = 0;
	std::istringstream iBuf(buffer[index++]);

	// Static sized members
	{
		// sscanf(buffer[0].c_str(), "%lu %lu %lu %lu %lu %lu", &(pubkey->sx), &(pubkey->sy), &(pubkey->pks_size), &(pubkey->y_size), &(pubkey->pk_bit_cnt), &(pubkey->seed));
		// pubkey->seed = stoul(buffer[0]);
		iBuf
			>> pubkey->sx
			>> pubkey->sy
			>> pubkey->pks_size
			>> pubkey->y_size
			>> pubkey->pk_bit_cnt
			>> pubkey->seed;
	}

	// delta
	iBuf.str(buffer[index++]);
	for (unsigned long i = 1; i < pubkey->pks_size + 1; ++i) {
		unsigned long val;
		iBuf >> val;
		mpz_set_ui(pubkey->delta[i], val);
		//mpz_set(pubkey->delta[i - 1], mpz_class(buffer[i], 10).get_mpz_t());
	}

	// x0
	//pubkey->x0 = buffer[i++];
	// mpz_set(pubkey->x0, mpz_class(buffer[i++]).get_mpz_t());
	mpz_set_str(pubkey->x0, buffer[index++].c_str(), W/2);
	mpz_set_str(pubkey->rx0, buffer[index++].c_str(), W/2);

	// y
	for (unsigned long i = 0; i < pubkey->y_size; ++i) {
		// __mpf_struct* tmp;
		iBuf.str(buffer[index++]);

		// tmp = (__mpf_struct*) malloc(sizeof(__mpf_struct));
		// sscanf(buffer[i].c_str(), "%d %d %lu ", &(tmp->_mp_prec), &(tmp->_mp_size), &(tmp->_mp_exp));
		iBuf >> MP_PREC(pubkey->y[i])
			>> MP_SIZE(pubkey->y[i])
			>> MP_EXP(pubkey->y[i]);
		// tmp->_mp_d = (mp_limb_t*) malloc(tmp->_mp_size * sizeof(mp_limb_t));

		// const char* buf = strchr(buffer[i].c_str(), '#');
		iBuf.ignore(3, '#');	// Ignore atmost 3 chars, until you reach '#'.
		for (int k = 0; k < MP_SIZE(pubkey->y[i]); ++k) {
			// buf = strchr(buf, ' ') + 1;
			// sscanf(buf, "%lx", &tmp->_mp_d[k]);
			iBuf >> pubkey->y[i]->_mp_d[k];
		}
		// mpf_set(pubkey->y[j], tmp);
		// mpf_clear(tmp);
		// free(tmp);
	}

	// sigma
	for (unsigned long t = 0; t < pubkey->sy; ++t) {
		for (unsigned long j = 0; j < pubkey->sy; ++j) {
			mpz_set_str(pubkey->sigma[t][j], buffer[index].c_str(), W/2);
		}
	}

	// gen_time
	strcpy(pubkey->gen_time, buffer[index].c_str());
	return 0;
}

/*int format_str_rc_publickey(std::vector<std::string> &buffer, __rc_pubkey_setPP* pubkey) {
	if (buffer.empty() || pubkey == NULL) {
		return -1;
	}

	// buffer index
	unsigned long int index = 0;
	std::istringstream iBuf(buffer[index++]);

	// Static sized members
	{
		// sscanf(buffer[0].c_str(), "%lu %lu %lu %lu %lu %lu", &(pubkey->sx), &(pubkey->sy), &(pubkey->pks_size), &(pubkey->y_size), &(pubkey->pk_bit_cnt), &(pubkey->seed));
		// pubkey->seed = stoul(buffer[0]);
		iBuf
			>> pubkey->sx
			>> pubkey->sy
			>> pubkey->pks_size
			>> pubkey->y_size
			>> pubkey->pk_bit_cnt
			>> pubkey->seed;
	}

	// delta
	iBuf.str(buffer[index++]);
	for (unsigned long i = 1; i < pubkey->pks_size + 1; ++i) {
		unsigned long val;
		iBuf >> val;
		pubkey->delta[i] = val;
		//mpz_set(pubkey->delta[i - 1], mpz_class(buffer[i], 10).get_mpz_t());
	}

	// x0
	//pubkey->x0 = buffer[i++];
	// mpz_set(pubkey->x0, mpz_class(buffer[i++]).get_mpz_t());
	pubkey->x0 = buffer[index++];
	pubkey->rx0 = buffer[index++];

	// y
	for (unsigned long i = 0; i < pubkey->y_size; ++i) {
		// __mpf_struct* tmp;
		iBuf.str(buffer[index++]);

		// tmp = (__mpf_struct*) malloc(sizeof(__mpf_struct));
		// sscanf(buffer[i].c_str(), "%d %d %lu ", &(tmp->_mp_prec), &(tmp->_mp_size), &(tmp->_mp_exp));
		iBuf >> MP_PREC(pubkey->y[i])
			>> MP_SIZE(pubkey->y[i])
			>> MP_EXP(pubkey->y[i]);
		// tmp->_mp_d = (mp_limb_t*) malloc(tmp->_mp_size * sizeof(mp_limb_t));

		// const char* buf = strchr(buffer[i].c_str(), '#');
		iBuf.ignore(3, '#');	// Ignore atmost 3 chars, until you reach '#'.
		for (int k = 0; k < MP_SIZE(pubkey->y[i]); ++k) {
			// buf = strchr(buf, ' ') + 1;
			// sscanf(buf, "%lx", &tmp->_mp_d[k]);
			iBuf >> pubkey->y[i]->_mp_d[k];
		}
		// mpf_set(pubkey->y[j], tmp);
		// mpf_clear(tmp);
		// free(tmp);
	}

	// sigma
	for (unsigned long t = 0; t < pubkey->sy; ++t) {
		for (unsigned long j = 0; j < pubkey->sy; ++j) {
			pubkey->sigma[t][j] = buffer[index];
		}
	}

	// gen_time
	pubkey->gen_time.assign(buffer[index]);
	return 0;
}


__rc_pubkey_set format_str_rc_publickey(std::vector<std::string> &buffer) {
	__rc_pubkey_set pubkey;

	if (buffer.empty()) {
		return pubkey;
	}

	unsigned long index = 0;
	std::istringstream iBuf(buffer[index++]);

	// Static sized members
	{
		iBuf
			>> pubkey.sx
			>> pubkey.sy
			>> pubkey.pks_size
			>> pubkey.y_size
			>> pubkey.pk_bit_cnt
			>> pubkey.seed;
	}

	// delta
	iBuf.str(buffer[index++]);
	pubkey.delta = (mpz_t *) malloc(pubkey.pks_size * sizeof (mpz_t));
	for (unsigned long i = 0; i < pubkey.pks_size; ++i) {
		unsigned long val;
		iBuf >> val;
		mpz_init_set_ui(pubkey.delta[i], val);
	}

	// x0
	mpz_init_set_str(pubkey.x0, buffer[index++].c_str(), W/2);
	mpz_init_set_str(pubkey.rx0, buffer[index++].c_str(), W/2);

	// y
	for (unsigned long i = 0; i < pubkey.y_size; ++i) {
		iBuf.str(buffer[index++]);
		mpf_init(pubkey.y[i]);
		iBuf >> MP_PREC(pubkey.y[i])
			>> MP_SIZE(pubkey.y[i])
			>> MP_EXP(pubkey.y[i]);
		iBuf.ignore(3, '#');	// Ignore atmost 3 chars, until you reach '#'.
		for (int j = 0; j < MP_SIZE(pubkey.y[i]); ++j) {
			iBuf >> pubkey.y[i]->_mp_d[j];
		}
	}

	// sigma
	for (unsigned long t = 0; t < pubkey.sy; ++t) {
		for (unsigned long j = 0; j < pubkey.sy; ++j) {
			// mpz_class tmp;
			mpz_init_set_str(pubkey.sigma[t][j], buffer[index++].c_str(), W/2);
		}
	}

	// gen_time
	strcpy(pubkey.gen_time, buffer[index++].c_str());
	return pubkey;
}*/

int read_rc_publickey(__rc_pubkey_set* pubkey, std::istream &in) {
	if (pubkey == NULL) {
		return -1;
	}

	// Static sized members
	in
		// >> pubkey->sx >> pubkey->sy
		>> pubkey->pks_size //>> pubkey->y_size
		// >> pubkey->pk_bit_cnt
	>> pubkey->seed;

	// delta
	for (unsigned i = 0; i < pubkey->pks_size; ++i) {
		in >> pubkey->delta[i];
	}

	// x0
	in >> pubkey->x0;
//	in >> pubkey->rx0;

	// y
//	for (unsigned long i = 0; i < pubkey->y_size; ++i) {
//		in >> pubkey->y[i]->_mp_prec
//			>> pubkey->y[i]->_mp_size
//			>> pubkey->y[i]->_mp_exp;

//		char discard;
//		in >> discard;	// '#'
//		for (int k = 0; k < pubkey->y[i]->_mp_size; ++k) {
//			in >> pubkey->y[i]->_mp_d[k];
//		}
//	}

	// sigma
//	for (unsigned long i = 0; i < pubkey->sx; ++i) {
//		for (unsigned long j = 0; j < pubkey->sy; ++j) {
//			in >> pubkey->sigma[i][j];
//		}
//	}

	// gen_time
//	std::string buffer;
//	std::getline(in, buffer);
//	strcpy(pubkey->gen_time, buffer.c_str());
	return 0;
}

std::istream& operator>>(std::istream& in, __rc_pubkey_set pubkey) {
	read_rc_publickey(&pubkey, in);
	return in;
}
