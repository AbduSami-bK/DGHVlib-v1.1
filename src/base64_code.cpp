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
/**
 *This code is created Created by guofu on 2017/5/25.
 *Copyright c 2017 guofu. All rights reserved.
 *https://www.jianshu.com/p/125c4bbed460
 */

#include "dghv.h"
#include <sstream>

static char base64_table[] = {
     'A','B','C','D','E','F','G','H','I','J',
     'K','L','M','N','O','P','Q','R','S','T',
     'U','V','W','X','Y','Z','a','b','c','d',
     'e','f','g','h','i','j','k','l','m','n',
     'o','p','q','r','s','t','u','v','w','x',
     'y','z','0','1','2','3','4','5','6','7',
     '8','9','+', '/', '\0'
};

int static base64_map(char *in_block, int len) {
    for (int i = 0; i < len; ++i) {
        in_block[i] = base64_table[int (in_block[i])];
    }
    if (len % 4 == 3) {
        in_block[len++] = '=';
    } else if (len % 4 == 2) {
        in_block[len] = in_block[len + 1] = '=';
        len += 2;
    }

    return len;
}

void static base64_unmap(char *in_block) {
    int i;
    char *c;

    for(i = 0; i < 4; ++i) {
        c = in_block + i;

        if(*c>='A' && *c<='Z') {
            *c -= 'A';
            continue;
        }

        if(*c>='a' && *c<='z') {
            *c -= 'a';
            *c += 26;
            continue;
        }

        if(*c == '+') {
            *c = 62;
            continue;
        }

        if(*c == '/') {
            *c = 63;
            continue;
        }

        if(*c == '=') {
            *c = 0;
            continue;
        }

        *c -= '0';
        *c += 52;
    }
}

int base64_encode(const char *in, int inlen, char *out) {
    const char* in_block;
    char* out_block;
    char  temp[3];
    int i, outlen;

    out_block = out;
    in_block = in;

    for (i = 0; i < inlen; i += 3) {
        memset(temp, 0, 3);
        memcpy(temp, in_block, i + 3 < inlen ? 3 : inlen - i);
        memset(out_block, 0, 4);

        out_block[0] = (temp[0] >> 2) & 0x3f;
        out_block[1] = ((temp[0] << 4) & 0x30) | ((temp[1] >> 4) & 0x0f);
        out_block[2] = ((temp[1] << 2) & 0x3c) | ((temp[2] >> 6) & 0x03);
        out_block[3] = (temp[2]) & 0x3f;

        out_block += 4;
        in_block += 3;
    }

    outlen = base64_map(out, ((inlen * 4) - 1) / 3 + 1);
    out[outlen] = '\0';

    return outlen;
}

std::string base64_encode(const char *in, int inlen) {
    char * output = (char *) malloc((inlen * 4 - 1) / 3 + 1);

    base64_encode(in, inlen, output);

    std::string out = output;
    free(output);

    return out;
}

std::string base64_encode(std::string in) {
    std::istringstream instream(in);
    return base64_encode(instream);
}

std::string base64_encode(std::istream &in) {
    char  temp[3];
    int outlen, inlen = 0;

    std::ostringstream out;
    while (in.get(temp, 3)) {
        out << ((temp[0] >> 2) & 0x3f);
        out << (((temp[0] << 4) & 0x30) | ((temp[1] >> 4) & 0x0f));
        out << (((temp[1] << 2) & 0x3c) | ((temp[2] >> 6) & 0x03));
        out << ((temp[2]) & 0x3f);
        inlen += in.gcount();
    }

    std::string tmp = out.str();
    char * output = (char *) malloc(tmp.length() + 1);
    strcpy(output, tmp.c_str());

    outlen = base64_map(output, ((++inlen * 4) - 1) / 3 + 1);
    output[outlen] = '\0';

    tmp = output;
    free(output);

    return tmp;
}

int base64_decode(const char *in, int inlen, char *out) {
    const char* in_block;
    char* out_block;
    char  temp[4];
    int i;

    out_block = out;
    in_block = in;

    for (i = 0; i < inlen; i += 4) {
        if (*in_block == '=') {
            //out_block = '\0';
            return 0;
        }

        memcpy(temp, in_block, 4);
        memset(out_block, 0, 3);
        base64_unmap(temp);

        out_block[0] = ((temp[0]<<2) & 0xfc) | ((temp[1]>>4) & 3);
        out_block[1] = ((temp[1]<<4) & 0xf0) | ((temp[2]>>2) & 0xf);
        out_block[2] = ((temp[2]<<6) & 0xc0) | ((temp[3]   ) & 0x3f);

        out_block += 3;
        //outlen += 3;
        in_block += 4;
    }

    return strlen(out);
}

int base64_decode(const std::string in, std::string &out) {
    char  temp[4];
    unsigned long i;
    std::size_t out_i = 0;

    for (i = 0; i < in.length(); i += 4) {
        if (in[i] == '=') {
            return 0;
        }

        strcpy(temp, in.substr(i, 4).c_str());
        base64_unmap(temp);

        out[out_i    ] = ((temp[0]<<2) & 0xfc) | ((temp[1]>>4) & 3);
        out[out_i + 1] = ((temp[1]<<4) & 0xf0) | ((temp[2]>>2) & 0xf);
        out[out_i + 2] = ((temp[2]<<6) & 0xc0) | ((temp[3]   ) & 0x3f);

        out_i += 3;
    }

    return out.length();
}

std::string base64_decode(std::string encoded) {
    std::istringstream instream(encoded);
    return base64_decode(instream);
}

std::string base64_decode(std::istringstream &in) {
    char  temp[4];
    int i, outlen, inlen = 0;

    std::ostringstream out;

    for (i = 0; i < inlen; i += 4) {
        char c;
        in.get(c);
        if (c == '=') {
            return out.str();
        }

        in.get(temp, 4);
        base64_unmap(temp);

        out << (((temp[0]<<2) & 0xfc) | ((temp[1]>>4) & 3));
        out << (((temp[1]<<4) & 0xf0) | ((temp[2]>>2) & 0xf));
        out << (((temp[2]<<6) & 0xc0) | ((temp[3]   ) & 0x3f));

        outlen += 3;
        inlen += 4;
    }

    return out.str();
}
