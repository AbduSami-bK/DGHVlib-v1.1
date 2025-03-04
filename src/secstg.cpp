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

#include "dghv.h"

void init_sec_para(__sec_setting** para)
{
    *para = (__sec_setting*) malloc(sizeof (__sec_setting));
    if (*para == NULL) {
        printf("memory allocation failed!\n");
        exit(1);
    }

    // mpz_init((*para)->pt_limit);
}

void clear_sec_para(__sec_setting** para)
{
    if (*para != NULL) {
        // mpz_clear((*para)->pt_limit);
        free(*para);
    }
}

void set_default_para(__sec_setting* para, int level)
{
    switch(level) {
        case TOY:
            para->lam = 24;
            para->rho = 8;
            para->Rho = 8;
            para->eta = 872;
            para->gam = 300000;
            para->Theta = 144;
            para->theta = 15;
            para->n = 5;
            para->tau = 200;
            break;
        case SMALL:
            para->lam = 32;
            para->rho = 16;
            para->Rho = 24;
            para->eta = 2216;
            para->gam = 2000000;
            para->Theta = 500;
            para->theta = 15;
            para->n = 5;
            para->tau = 500;
            break;
        case MEDIUM:
            para->lam = 54;
            para->rho = 27;
            para->Rho = 41;
            para->eta = 3644;
            para->gam = 4000000;
            para->Theta = 1500;
            para->theta = 15;
            para->n = 5;
            para->tau = 1000;
            break;
        case LARGE:
            para->lam = 62;
            para->rho = 32;
            para->Rho = 64;
            para->eta = 5576;
            para->gam = 8000000;
            para->Theta = 4500;
            para->theta = 15;
            para->n = 5;
            para->tau = 1500;
            break;
    }
    para->prec = para->gam + para->eta;
    mpz_ui_pow_ui(para->pt_limit.get_mpz_t(), 2, 512);  // SHA3-512 is 128 digits long in base 16. 512 = 8 * 128 / 2 (1 byte can have 2 digits)
}

bool para_valid(__sec_setting* para)
{
    bool ret = true;
    if (para->n < 5) {
        printf("The parameter of n: %lu must be more than 5.When n = 5, FHE have best performance\n", para->n);
        ret = false;
    }
    if (para->Rho < para->rho) {
        printf("The parameter of Rho: %lu must be more than rho:%lu.\n", para->Rho, para->rho);
        ret = false;
    }
    if (para->eta < MIN_ETA(para->Rho)) {
        printf("The parameter of eta: %lu must be more than 21 * Rho + 50.\n", para->eta);
        ret = false;
    }
    if (para->Theta < para->theta) {
        printf("The parameter of Theta: %lu must be more than theta: %lu", para->Theta, para->theta);
        ret = false;
    }
    return ret;
}
