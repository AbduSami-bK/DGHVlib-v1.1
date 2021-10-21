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
#include <unistd.h>
#include <fstream>
#include <iostream>
#include <string.h>

static int gen_pubkey_header(__pubkey_set* pubkey, char* header, int lines) {
	int ret = 0;
	if(pubkey == NULL || header == NULL){
		return -1;
	}
	char *owner, *hostname;
	hostname = (char*)malloc(256*sizeof(char));
	owner = getlogin();
	gethostname(hostname,256);
	sprintf(header, "subject: test fhe-dghv\nalgorithm: dghv\nsize: %lu\npublic key numbers: %lu\nowner: %s@%s\nTime: %s\nLines: %d",
			pubkey->pk_bit_cnt, pubkey->pks_size, owner, hostname, pubkey->gen_time, lines);
	free(hostname);
	return ret;
}

static int gen_prikey_header(__prikey* prikey, char* header, int lines) {
	int ret = 0;
	if(prikey == NULL || header == NULL){
		return -1;
	}
	char *owner, *hostname;
	hostname = (char*)malloc(256*sizeof(char));
	owner = getlogin();
	gethostname(hostname,256);
	sprintf(header, "subject: test fhe-dghv\nalgorithm: dghv\nsize: %lu\nowner: %s@%s\nTime: %s\nLines: %d",
			prikey->sk_bit_cnt, owner, hostname, prikey->gen_time, lines);
	free(hostname);
	return ret;
}

static int gen_rc_pubkey_header(__rc_pubkey_set* pubkey, char* header, int lines) {
	int ret = 0;
	if(pubkey == NULL || header == NULL){
		return -1;
	}
	char *owner, *hostname;
	hostname = (char*)malloc(256*sizeof(char));
	owner = getlogin();
	gethostname(hostname,256);
	sprintf(header, "subject: test fhe-dghv\nalgorithm: dghv\nsize: %lu\npublic key numbers: %lu\nowner: %s@%s\nTime: %s\nLines: %d",
			pubkey->pk_bit_cnt, pubkey->pks_size, owner, hostname, pubkey->gen_time, lines);
	free(hostname);
	return ret;
}

static int gen_rc_prikey_header(__rc_prikey* prikey, char* header, int lines) {
	int ret = 0;
	if (prikey == NULL || header == NULL) {
		return -1;
	}
	char *owner, *hostname;
	hostname = (char*) malloc(256 * sizeof(char));
	owner = getlogin();
	gethostname(hostname, 256);
	sprintf(header, "subject: test fhe-dghv\nalgorithm: dghv\nsize: %lu\nrsize: %lu\nowner: %s@%s\nTime: %s\nLines: %d",
			prikey->sk_bit_cnt, prikey->rsk_bit_cnt, owner, hostname, prikey->gen_time, lines);
	free(hostname);
	return ret;
}

int save_str(char** buffer, signed long length, const char* filename) {
	if (buffer == NULL || length <= -1) {
		return -1;
	}

	FILE* out;
	if ((out = fopen(filename, "wt")) == NULL) {
		fprintf(stderr, "Cannot open file %s\n", filename);
		return -1;
	}

	int ret = __save_str(buffer, length, out);

	fclose(out);
	return ret;
}

int __save_str(char** buffer, unsigned long int noOfCStrings, FILE* out) {
	int ret = fprintf(out, "Ciphertexts:%lu\n", noOfCStrings);
	//do {
	for (unsigned long int i = 0; i < noOfCStrings; ++i) {
		ret += __save_1_str(buffer[i], out);
		//++i;
	} //while (i < noOfCStrings);

	return ret;
}

int __save_1_str(char* str1, FILE* out) {
	return fprintf(out, "%lu\n%s\n", strlen(str1), str1);
}

void save_string(std::string* buffer, long length, const char* filename) {
	if (buffer == NULL || length <= -1) {
		return;
	}

	std::ofstream out(filename);
	if (!out.is_open()) {
		fprintf(stderr, "Cannot open file %s\n", filename);
		return;
	}

	__save_string(buffer, length, out);

	out.close();
}

void __save_string(std::string* buffer, unsigned long noOfCStrings, std::ofstream& out) {
	out << "Ciphertexts:" << noOfCStrings << "\n";
	for (unsigned long i = 0; i < noOfCStrings; ++i) {
		__save_1_string(buffer[i], out);
	}
}

void __save_1_string(std::string str1, std::ofstream& out) {
	out << str1.length() << "\n" << str1 << "\n";
}

char** read_str(const char* filename) {

	if (filename == NULL) {
		return NULL;
	}

	FILE* in;
	if((in = fopen(filename, "r")) == NULL) {
		fprintf(stderr, "Cannot open %s file\n", filename);
		return NULL;
	}

	char** buffer = NULL;
	__read_str(in, &buffer);

	fclose(in);
	return buffer;
}

int malloc_buffer_read_file(char*** buffer, FILE* in) {
	unsigned long int len1;
	char* header = (char*) malloc(2*W * sizeof (char));
	header = fgets(header, 2*W, in);
	sscanf(header, "Ciphertexts:%lu\n", &len1);
	*buffer = (char**) malloc((len1+1) * sizeof (char **));
	//buffer[0]= (char*) malloc(2*W * sizeof (char));
	//sprintf(buffer[0], "%d", len1);
	free(header);
	return len1;
}

unsigned int __read_str(FILE* in, char ***buffer) {
	unsigned int len1;

	if (!feof(in)) {
		len1 = malloc_buffer_read_file(buffer, in);
	} else return 0;

	for (unsigned int i = 0; i < len1 && !feof(in); ++i) {
		(*buffer)[i] = __read_1_str(in);
	}
	return len1;
}

char* __read_1_str(FILE* in) {
	int len2;
	/*ret +=*/ fscanf(in, "%d", &len2);
	char* str = (char*) malloc((len2+W) * sizeof (char));
	/*ret +=*/ fscanf(in, "%s", str);
	return str;
}

char** read_string(const char* filename) {
	if (filename == NULL) {
		return NULL;
	}

	std::ifstream in(filename);
	if(!in.is_open()) {
		fprintf(stderr, "Cannot open %s file\n", filename);
		return NULL;
	}

	char **buffer = NULL;
	__read_string(in, &buffer);

	in.close();
	return buffer;
}

unsigned long __read_string(std::ifstream& in, char ***buffer) {
	unsigned long len1;

	if (!in.eof()) {
		len1 = malloc_buffer_read_file(in, buffer);
	} else return 0;

	for (unsigned long i = 0; i < len1 && !in.eof(); ++i) {
		(*buffer)[i] = __read_1_string(in);
	}
	return len1;
}

unsigned long malloc_buffer_read_file(std::ifstream& in, char ***buffer) {
	unsigned long len1 = 0;
	std::string header;
	in >> header;
	int r = sscanf(header.c_str(), "Ciphertexts:%lu\n", &len1);
	if (r != 1) {
		// header.clear();
		return 0;
	}
	*buffer = (char**) malloc((len1+1) * sizeof (char **));
	header.clear();
	return len1;
}

char* __read_1_string(std::ifstream& in) {
	int len2;
	in >> len2;
	char* str = (char*) malloc((len2 + W) * sizeof (char));
	in >> str;
	return str;
}

int save_sec_para(__sec_setting* para, const char* filename)
{
	if (para == NULL || filename == NULL) {
		return -1;
	}

	int ret = 0;

	char *ptl = (char*) malloc(129 * sizeof(char));	//! W/2 - 129 is a magic number. Since I'm encrypting SHA3-512, which are 128 byte long hashes.
	mpz_get_str(ptl, 16, para->pt_limit);

	char* buffer = (char*) malloc((W*8 + 141) * sizeof (char));
	sprintf(buffer, "lam:%lu\nrho:%lu\nRho:%lu\neta:%lu\ngam:%lu\nTheta:%lu\ntheta:%lu\nn:%lu\ntau:%lu\nprec:%lu\npt-limit:%s",
					para->lam, para->rho, para->Rho, para->eta, para->gam,
					para->Theta, para->theta, para->n, para->tau, para->prec, ptl);

	FILE *out;
	if ((out = fopen(filename,"wt")) == NULL) {
		fprintf(stderr, "Cannot open security parameter file\n");
	}

	ret = fprintf(out, "%s\n", buffer);
	free(ptl);
	free(buffer);
	fclose(out);
	return ret;
}

int read_sec_para(__sec_setting* para, const char* filename)
{
	if (para == NULL || filename == NULL) {
		return -1;
	}

	int ret = 0;
	char* buffer = (char*) malloc((W*8 + 141) * sizeof (char));
	memset(buffer, '\0', (W*8 + 140) * sizeof (char));
	char* ptl = (char*) malloc(139 * sizeof (char));
	memset(ptl, '\0', 138 * sizeof (char));
	FILE *in;
	if ((in = fopen(filename, "r")) == NULL) {
		fprintf(stderr, "Cannot open security parameter file\n");
	}
	int i = 0;

	while (!feof(in)) {
		fgets(buffer + i, W*8, in);
		i = strlen(buffer);
	}

	ret = sscanf(buffer, "lam:%lu\nrho:%lu\nRho:%lu\neta:%lu\ngam:%lu\nTheta:%lu\ntheta:%lu\nn:%lu\ntau:%lu\nprec:%lu\npt-limit:%s",
						&(para->lam), &(para->rho), &(para->Rho), &(para->eta), &(para->gam),
						&(para->Theta), &(para->theta), &(para->n), &(para->tau), &(para->prec), ptl);

	mpz_set_str(para->pt_limit, ptl, 16);

	free(ptl);
	free(buffer);
	fclose(in);
	return ret;

}

int save_prikey(__prikey* prikey, const char* prikey_filename) {
	int ret = 0;
	if (prikey == NULL || prikey_filename == NULL) {
		return -1;
	}

	int length, i;
	FILE *out;
	char** buffer = (char**) malloc(W/8 * sizeof (char*));
	char*  header = (char*) malloc(W*W/2 * sizeof (char));
	char*  base64 = (char*) malloc((prikey->sk_bit_cnt/2) * sizeof (char));

	char s1[] = "---- BEGIN FHE PRIVATE KEY ----";
	char s2[] = "---- END FHE PRIVATE KEY ----";

	ret = format_privatekey_str(prikey, buffer, &length);
	ret = gen_prikey_header(prikey, header, length);

	if((out = fopen(prikey_filename,"wt")) == NULL){
		fprintf(stderr,"Cannot open privatekey file\n");
	}

	fprintf(out, "%s\n", s1);
	fprintf(out, "%s\n", header);
	for (i = 0; i < length; i++) {

		base64_encode(buffer[i], strlen(buffer[i]), base64);
		fprintf(out, "%s\n", base64);
	}
	ret = fprintf(out, "%s\n", s2);
	free(base64);
	fclose(out);
	free(header);
	for (i = length - 1; i >= 0; i--)	free(buffer[i]);
	free(buffer);
	return ret;
}

int read_prikey(__prikey* prikey, const char* prikey_filename) {
	int ret = 0;
	if (prikey == NULL || prikey_filename == NULL) {
		return -1;
	}

	FILE* in;
	char tmp[10];
	int i = 0, j = 0, length;
	int base64_len  = prikey->sk_bit_cnt / 2;
	int buffer_ilen = prikey->sk_bit_cnt / 3;
	char** buffer = (char**) malloc(W / 8      * sizeof (char*));
	char*        base64 = (char* ) malloc(base64_len * sizeof (char ));
	char*        header = (char* ) malloc(W * 8      * sizeof (char ));

	if((in = fopen(prikey_filename,"r"))== NULL){
		fprintf(stderr,"Cannot open privatekey file\n");
	}

	while (!feof(in)) {
		if (i < PRIHL) {
			header = fgets(header, W * 8, in);
			strncpy(tmp, header, 5);
			if (strcmp(tmp, "Lines") == 0) {
				strcpy(tmp, header + 7);
				sscanf(tmp, "%d\n", &length);
			}
			++i;
		} else {
			if (j == length)
				break;
			ret = fscanf(in, "%s\n", base64);
			buffer[j] = (char*) malloc(buffer_ilen * sizeof (char));
			memset(buffer[j], '\0', buffer_ilen * sizeof (char));
			base64_decode(base64, strlen(base64), buffer[j]);
			++j;
		}
	}
	format_str_privatekey(buffer, length, prikey);

	free(header);
	free(base64);
	for(i = length - 1; i >= 0; i--)	free(buffer[i]);
	free(buffer);
	fclose(in);
	return ret;
}

 int save_pubkey(__pubkey_set* pubkey, const char* pubkey_filename){
	 int ret = 0;
	 if(pubkey == NULL || pubkey_filename == NULL){
		 return -1;
	 }

	 int i, length;
	 int buffer_len = 2*pubkey->y_size + pubkey->pks_size + 2;
	 int base64_len = (pubkey->pk_bit_cnt + W*W*W)/2;

	 char** buffer = (char**)malloc(buffer_len * sizeof(char*));
	 char*  header = (char*)malloc(W*8 * sizeof(char));
	 char*  base64 = (char*)malloc(base64_len * sizeof(char));

	 char s1[] = "---- BEGIN FHE PUBLIC KEY ----";
	 char s2[] = "---- END FHE PUBLIC KEY ----";

	 format_publickey_str(pubkey, buffer, &length);
	 gen_pubkey_header(pubkey, header, length);

	 FILE *out;
	 if((out = fopen(pubkey_filename,"wt"))== NULL){
			fprintf(stderr,"Cannot open privatekey file\n");
	 }

	 fprintf(out, "%s\n", s1);
	 fprintf(out, "%s\n", header);

	 for(i = 0; i < length; i++){
		 base64_encode(buffer[i], strlen(buffer[i]), base64);
		 fprintf(out, "%s\n", base64);
		 memset(base64, '\0', base64_len * sizeof(char));
	 }
	 fprintf(out, "%s\n", s2);

	 free(base64);
	 fclose(out);
	 free(header);
	 for(i = length - 1; i >= 0; i--){
		 free(buffer[i]);
	 }
	 free(buffer);
	 return ret;
 }

 int read_pubkey(__pubkey_set* pubkey, const char* pubkey_filename){
	 int ret = 0;
	 if(pubkey == NULL || pubkey_filename == NULL){
		 return -1;
	 }

	 int i = 0, j = 0;
	 int base64_len = (pubkey->pk_bit_cnt + W*W*W)/2;
	 int buffer_len = 2*pubkey->y_size+pubkey->pks_size+2;
	 int buffer_j_len = ((pubkey->pk_bit_cnt/W*W)/4) + W*W*W;

	 char** buffer = (char**)malloc(buffer_len * sizeof(char*));
	 char*  base64 = (char*)malloc(base64_len * sizeof(char));
	 char*  header = (char*)malloc(W*8 * sizeof(char));

	 FILE* in;
	 if((in = fopen(pubkey_filename,"r"))== NULL){
			fprintf(stderr,"Cannot open privatekey file\n");
	 }

	 while(!feof(in)){
		 if(i < PUBHL){
			 header = fgets(header, W*8, in);
			 i++;
		 }else if(j < buffer_len){

			 ret = fscanf(in, "%s", base64);
			 buffer[j] = (char*)malloc(buffer_j_len * sizeof(char));
			 memset(buffer[j], '\0', buffer_j_len * sizeof(char));
			 base64_decode(base64, strlen(base64), buffer[j]);
			 j++;
		 }else{
			 break;
		 }
	 }
	 format_str_publickey(buffer, buffer_len, pubkey);

	free(header);
	 free(base64);
	 for(i = 0; i < buffer_len; i++) free(buffer[i]);
	 free(buffer);
	 fclose(in);
	 return ret;
 }

int save_rc_prikey(__rc_prikey* prikey, const char* prikey_filename) {
	int ret = 0;
	if (prikey == NULL || prikey_filename == NULL) {
		return -1;
	}

	int length, i;
	std::ofstream out(prikey_filename);
	char** buffer = (char**) malloc(4 * sizeof (char*));
	char* header = (char*) malloc(W*W * sizeof (char));
	//char*  base64 = (char*) malloc((prikey->sk_bit_cnt/2) * sizeof (char));
	char* r_base64 = (char*) malloc((prikey->rsk_bit_cnt/2) * sizeof (char));

	ret += format_rc_privatekey_str(prikey, buffer, &length);
	ret += gen_rc_prikey_header(prikey, header, length);

	if (!out.is_open()) {
		fprintf(stderr, "Cannot open privatekey file\n");
		return -2;
	}

	out << "---- BEGIN FHE PRIVATE KEY ----\n";
	out << header << "\n";
	for (i = 0; i < length; ++i) {
		base64_encode(buffer[i], strlen(buffer[i]), r_base64);	// TODO Test
		out << r_base64 << "\n";
	}
	out << "---- END FHE PRIVATE KEY ----\n";
	ret += strlen("---- END FHE PRIVATE KEY ----\n");
	free(r_base64);
	out.close();
	free(header);
	for (i = length - 1; i >= 0; --i)
		free(buffer[i]);
	free(buffer);
	return 0;
}

int read_rc_prikey(__rc_prikey* prikey, const char* prikey_filename) {
	int ret = 0;
	if (prikey == NULL || prikey_filename == NULL) {
		return -1;
	}

	std::ifstream	in				(prikey_filename);
	int				length;
	//int				r_base64_len	= prikey->rsk_bit_cnt/2;
	int				buffer_ilen		= prikey->rsk_bit_cnt/3;
	char			**buffer		= (char**)	malloc(4			* sizeof(char*));
	std::string		r_base64		;//= (char*)	malloc(r_base64_len	* sizeof(char))	;
	std::string		header			;//= (char*)	malloc(W * 8		* sizeof(char))	;

	if (!in.is_open()) {
		fprintf(stderr, "Cannot open privatekey file\n");
	}

	for (int i = 0; i < PRIHL; ++i) {
		std::getline(in, header);
		if (header.substr(0, 5).compare("Lines") == 0) {	// TODO test
			length = std::stoi(header.substr(7));
			break;
		}
	}

	for (int i = 0; i != length; ++i) {
		//ret = fscanf(in, "%s\n", r_base64);
		std::getline(in, r_base64);
		ret += r_base64.length();
		buffer[i] = (char*) malloc(buffer_ilen * sizeof(char));
		memset(buffer[i], '\0', buffer_ilen * sizeof(char));
		base64_decode(r_base64.c_str(), r_base64.length(), buffer[i]);
	}

	format_str_rc_privatekey(buffer, length, prikey);

	//header.clear();
	//r_base64.clear();
	for (int i = length - 1; i >= 0; i--)
		free(buffer[i]);
	free(buffer);
	in.close();
	return ret;
}

int save_rc_pubkey(__rc_pubkey_set* pubkey, const char* pubkey_filename) {
	int ret = 0;
	if (pubkey == NULL || pubkey_filename == NULL) {
		return -1;
	}

	int i, length;
	std::size_t buffer_len = 2 * pubkey->y_size + pubkey->pks_size + pubkey->sx * pubkey->sy + 4;
	size_t base64_len = (pubkey->pk_bit_cnt + W*W*W)/2;

	//char** buffer = (char**) malloc(buffer_len * sizeof (char*));
	std::vector<std::string> buffer;
	buffer.reserve(buffer_len);
	char*  header = (char* ) malloc(W * 10     * sizeof (char ));
	char*  base64 = (char* ) malloc(base64_len * sizeof (char ));

	buffer = format_rc_publickey_str(pubkey, &length);
	ret += length;
	ret += gen_rc_pubkey_header(pubkey, header, length);

	std::ofstream out(pubkey_filename);
	if (!out.is_open()) {
		fprintf(stderr, "Cannot open privatekey file\n");
	}

	out << "---- BEGIN FHE PUBLIC KEY ----\n";
	out << header << "\n";

	for (i = 0; i < length; ++i) {
		ret += base64_encode(buffer[i].c_str(), buffer[i].length(), base64);
		out << base64 << "\n";
		memset(base64, '\0', base64_len * sizeof (char));
	}
	out << "---- END FHE PUBLIC KEY ----\n";

	free(base64);
	out.close();
	free(header);
	//for (std::string str : buffer) {
	//	str.clear();
	//}
	//buffer.clear();
	return ret;
 }

int read_rc_pubkey(__rc_pubkey_set* pubkey, const char* pubkey_filename) {
	if (pubkey == NULL || pubkey_filename == NULL) {
		return -1;
	}

	int ret = 0;
	//int base64_len = (pubkey->pk_bit_cnt + W*W*W)/2;
	int buffer_len = 2 * pubkey->y_size + pubkey->pks_size + pubkey->sx * pubkey->sy + 4;
	int buffer_j_len = pubkey->pk_bit_cnt/4 + W*W*W;

	//char *buffer = (char**) malloc(buffer_len * sizeof (char*));
	std::vector<std::string> buffer;
	buffer.reserve(buffer_len);
	std::string base64;	// = (char* ) malloc(base64_len * sizeof (char));
	std::string header;	// = (char* ) malloc(W * 10     * sizeof (char));

	std::ifstream in(pubkey_filename);
	if (!in.is_open()) {
		fprintf(stderr, "Cannot open privatekey file\n");
	}

	for (int i = 0; i < PUBHL; ++i) {
		std::getline(in, header);
	}

	for (int j = 0; j < buffer_len; ++j) {
		std::getline(in, base64);
		if (in.eof())
			break;
		ret += base64.length();
		char *buf = (char*) malloc(buffer_j_len * sizeof (char));
		base64_decode(base64.c_str(), base64.length(), buf);
		buffer.push_back(buf);
		free(buf);
	}
	format_str_rc_publickey(buffer, buffer_len, pubkey);

	//free(header);
	//free(base64);
	for (std::string str : buffer) {
		str.clear();
	}
	buffer.clear();
	in.close();
	return ret;
}
