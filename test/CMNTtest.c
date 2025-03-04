#include <stdio.h>
#include <string.h>
#include <gmp.h>
#include "dghv.h"

int main(){


    c_parameters para;
    sc_prikey prikey;
    sc_pubkeys pubkey;
    c_cit c1, c2, c3, newer;

    init_sec_para(&para);
    set_default_para(para, TOY);
    para->eta = para->eta * 2;
    mpf_set_default_prec(2 * para->eta + para->gam);
    

    init_sc_sk(&prikey, para);
    init_sc_pkset(&pubkey, prikey, para);
    init_cit(&c1, para->Theta);
    init_cit(&c2, para->Theta);
    init_cit(&c3, para->Theta);
    init_cit(&newer, para->Theta);


    unsigned long seed = get_seed();
    randstate rs;
    set_randstate(rs, seed);
    gen_sc_prikey(prikey, rs);
    gen_sc_pubkey(pubkey, prikey, para, rs, 1);
    expand_sc_p2y(pubkey, prikey, para->prec, rs);

    unsigned long m1 = 0, m2 = 1;
    CMNT_encrypt(c1, m1, pubkey, para, rs);
    printf("加密m1成功\n");
    expend_sc_cit(c1, pubkey);
    printf("扩展c1成功\n");

    CMNT_encrypt(c2, m2, pubkey, para, rs);
    printf("加密m2成功\n");
    expend_sc_cit(c2, pubkey);
    printf("扩展c2成功\n");

    printf("解密c1->%lu\n",CMNT_decrypt(c1, prikey));

    printf("解密c2->%lu\n",CMNT_decrypt(c2, prikey));

    evaluate_add(c3, c1, c2, pubkey->x0);
    printf("解密c1+c2->%lu\n",CMNT_decrypt(c3, prikey));

    evaluate_mul(c3, c1, c2, pubkey->x0);

    printf("解密c1*c2->%lu\n",CMNT_decrypt(c3, prikey));

    expend_sc_cit(c3, pubkey);

    sc_bootstrap(newer, c3, pubkey, para, rs);

    unsigned long ret = CMNT_decrypt(newer, prikey);

    if(ret == 0){
        printf("密文刷新成功\n");
    }else{

        printf("密文刷新失败\n");
    }

    return 0;

}
