/**
 *@author WTY
 *@date: 2024/7/3
 *@description: Definition of constants, operations, and header files
 */

#include "SHE.h"
#include <openssl/bn.h>
using namespace std;

int k_M;
int k_r;
int k_L;
int k_p;
int k_q;

BIGNUM* N = NULL;

PrivateKey* sk = NULL;

/**
 * @Method 生成x比特的随机数
 * @param int
 * @return BIGNUM*
 */
BIGNUM* generateRandom(int x) {
    BIGNUM* result = BN_new();
    BN_rand(result, x, -1, 0);
    return result;
}

/**
 * @Method 生成x比特的随机素数
 * @param int x
 * @return BIGNUM*
 */
BIGNUM* generateRandomPrime(int x) {
    BIGNUM* result = BN_new();
    int flag = BN_generate_prime_ex(result, x, 0, NULL, NULL, NULL);
    while (!flag) {
        flag = BN_generate_prime_ex(result, x, 0, NULL, NULL, NULL);
    }
    return result;
}

/**
 * @Method 生成私钥
 * @return void
 */
void generateKeys(int a, int b, int c, int d, int e) {
    // 给全局变量赋值
    k_M = a;
    k_r = b;
    k_L = c;
    k_p = d;
    k_q = e;

    // 定义k_L比特的随机数L
    BIGNUM* L = generateRandom(k_L);

    // 定义k_p比特的随机素数p
    BIGNUM* p = generateRandomPrime(k_p);

    // 随机选择一组k_q比特的随机数{q_i | i <= i <= k_q / k_p}，并计算q = q_1 * q_2 * ... * q_(k_q / k_p)
    BIGNUM* q = BN_new();
    BN_one(q);

    for (int i = 1; i <= k_q / k_p; i++) {
        BIGNUM* q_i = generateRandomPrime(k_p);
        // q = q * q_i
        BN_mul(q, q, q_i, BN_CTX_new());
        BN_free(q_i);
    }

    // N = p * q
    N = BN_new();
    BN_mul(N, p, q, BN_CTX_new());

    // 设置私钥
    sk = new PrivateKey(p, L);

    // 释放临时变量
    BN_free(L);
    BN_free(p);
    BN_free(q);
}

/**
 * @Method 加密
 * @param BIGNUM*  m 消息
 * @param PrivateKey *sk 私钥
 * @return BIGNUM* [[m]] 密文消息
 */
BIGNUM* encrypt_SHE(BIGNUM* m, PrivateKey* sk) {
    // 生成k_r比特的随机数r
    BIGNUM* r = generateRandom(k_r);

    // 生成k_q比特的随机数r_prime
    BIGNUM* r_prime = generateRandom(k_q);

    // 临时变量a,b,c
    BIGNUM* a = BN_new();
    BIGNUM* b = BN_new();
    BIGNUM* c = BN_new();

    // 计算a = (r * L + m) mod N
    BN_mul(a, r, sk->getL(), BN_CTX_new());
    BN_add(a, a, m);
    BN_mod(a, a, N, BN_CTX_new());

    // 计算b = (1 + r_prime * p)
    BN_one(b);
    BN_mul(c, r_prime, sk->getP(), BN_CTX_new());
    BN_mod_add(b, b, c, N, BN_CTX_new());

    // 计算c = (r * L + m) * (1 + r_prime * p) mod N
    BN_mul(c, a, b, BN_CTX_new());
    BN_mod(c, c, N, BN_CTX_new());

    // 释放临时变量
    BN_free(a);
    BN_free(b);
    BN_free(r);
    BN_free(r_prime);

    // 返回密文消息
    return c;
}

/**
 * @Method 解密
 * @param BIGNUM* E_m 密文消息
 * @param PrivateKey *sk 私钥
 * @return BIGNUM* m 消息
 */
BIGNUM* decrypt_SHE(BIGNUM* E_m, PrivateKey* sk) {
    // 计算m_prime = E_m % p % L;
    BIGNUM* m_prime = BN_new();
    BN_mod(m_prime, E_m, sk->getP(), BN_CTX_new());
    BN_mod(m_prime, m_prime, sk->getL(), BN_CTX_new());

    // 计算sk.getL() / 2
    BIGNUM* half_L = BN_new();
    BN_rshift1(half_L, sk->getL());

    // 如果m_prime < sk.getL() / 2，返回m_prime
    if (BN_cmp(m_prime, half_L) < 0) {
        BN_free(half_L);
        return m_prime;
    }

    // 否则返回m_prime - sk.getL()
    BN_sub(m_prime, m_prime, sk->getL());
    BN_free(half_L);
    return m_prime;
}

/**
 * @Method 同态加法，方案一
 * @param BIGNUM* E_m1 密文
 * @param BIGNUM* E_m2 密文
 * @return BIGNUM* [[m1 + m2]] 相加后的密文消息
 */
BIGNUM* Addition_one(BIGNUM* E_m1, BIGNUM* E_m2) {
    BIGNUM* res = BN_new();
    BN_add(res, E_m1, E_m2);
    BN_mod(res, res, N, BN_CTX_new());
    return res;
}

/**
 * @Method 同态加法，方案二
 * @param BIGNUM* E_m1 密文
 * @param BIGNUM* m2 明文
 * @return BIGNUM* [[m1 + m2]] 相加后的密文消息
 */
BIGNUM* Addition_two(BIGNUM* E_m1, BIGNUM* m2) {
    BIGNUM* res = BN_new();
    BN_add(res, E_m1, m2);
    BN_mod(res, res, N, BN_CTX_new());
    return res;
}

/**
 * @Method 同态乘法，方案一
 * @param BIGNUM* E_m1 密文
 * @param BIGNUM* E_m2 密文
 * @return BIGNUM* [[m1 * m2]] 相乘后的密文消息
 */
BIGNUM* Multiplication_one(BIGNUM* E_m1, BIGNUM* E_m2) {
    BIGNUM* res = BN_new();
    BN_mul(res, E_m1, E_m2, BN_CTX_new());
    BN_mod(res, res, N, BN_CTX_new());
    return res;
}

/**
 * @Method 同态乘法，方案二
 * @param BIGNUM* E_m1 密文
 * @param BIGNUM* m2 明文
 * @return BIGNUM* [[m1 * m2]] 相乘后的密文消息
 */
BIGNUM* Multiplication_two(BIGNUM* E_m1, BIGNUM* m2) {
    BIGNUM* res = BN_new();
    BIGNUM* zero = BN_new();
    BN_zero(zero);
    // 如果m2 <= 0，抛出异常
    if (BN_cmp(m2, zero) <= 0)  {
        // 使用 fprintf 输出错误消息到标准错误流
        fprintf(stderr, "process of split have some trouble\n");
    }

    BN_mul(res, E_m1, m2, BN_CTX_new());
    BN_mod(res, res, N, BN_CTX_new());
    // 释放临时变量
    BN_free(zero);
    return res;
}