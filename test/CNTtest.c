#include <stdio.h>
#include <string.h>
#include <gmp.h>
#include "dghv.h"

int main()
{
    c_parameters para;
    c_cit c1, c0, c3, newer;

    init_sec_para(&para);
    set_default_para(para, TOY);
    mpf_set_default_prec(2 * para->eta + para->gam);

    init_cit(&c0, para->Theta);
    init_cit(&c1, para->Theta);
    init_cit(&c3, para->Theta);
    init_cit(&newer, para->Theta);

    unsigned long seed = get_seed();
    randstate rs;
    set_randstate(rs, seed);

    __rc_prikey* prikey;
    __rc_pubkey_set* pubkey;

    init_rc_sk(&prikey, para);
    init_rc_pkset(&pubkey, para);

    gen_rc_prikey(prikey, rs);
    gen_rc_pubkey(pubkey, prikey, para);
    expand_rc_p2y(pubkey, prikey, para->prec, rs);


    CNT_encrypt(c0, 0, pubkey, para);
    // expend_rc_cit(c1, pubkey, prikey->rsk_bit_cnt);
    CNT_encrypt(c1, 1, pubkey, para);
    // expend_rc_cit(c2, pubkey, prikey->rsk_bit_cnt);
    evaluate_add(c3, c0, c0, pubkey->x0);
    printf("解密 0 + 0 -> %lu\n", CNT_decrypt(c3, prikey));
    evaluate_add(c3, c0, c1, pubkey->x0);
    printf("解密 0 + 1 -> %lu\n", CNT_decrypt(c3, prikey));
    evaluate_add(c3, c1, c0, pubkey->x0);
    printf("解密 1 + 0 -> %lu\n", CNT_decrypt(c3, prikey));
    evaluate_add(c3, c1, c1, pubkey->x0);
    printf("解密 1 + 1 -> %lu\n", CNT_decrypt(c3, prikey));

    evaluate_mul(c3, c0, c0, pubkey->x0);
    printf("解密 0 * 0 -> %lu\n", CNT_decrypt(c3, prikey));
    evaluate_mul(c3, c0, c1, pubkey->x0);
    printf("解密 0 * 1 -> %lu\n", CNT_decrypt(c3, prikey));
    evaluate_mul(c3, c1, c0, pubkey->x0);
    printf("解密 1 * 0 -> %lu\n", CNT_decrypt(c3, prikey));
    evaluate_mul(c3, c1, c1, pubkey->x0);
    printf("解密 1 * 1 -> %lu\n", CNT_decrypt(c3, prikey));

    expend_rc_cit(c3, pubkey, prikey->rsk_bit_cnt);

    gen_switch_key(prikey, pubkey, para);
    mod_switch(newer, c3, pubkey, para);

    unsigned long ret = CNT_decrypt(newer, prikey);

    if (ret == 0) {
        printf("密文刷新成功\n");
    } else {
        printf("密文刷新失败\n");
    }

    clear_rc_sk(prikey);
    clear_rc_pkset(pubkey);

    return 0;

}
