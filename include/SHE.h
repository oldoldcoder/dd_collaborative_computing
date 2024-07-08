/**
* @author: WTY
* @date: 2024/7/3
* @description: Definition of constants, operations, and header files
*/

#ifndef SHE_H
#define SHE_H

#include <bits/stdc++.h>
#include <openssl/bn.h>
using namespace std;

// 设计一个私钥类
class PrivateKey {
    public:
        PrivateKey(BIGNUM* p, BIGNUM* L) {
            this->p = BN_dup(p);
            this->L = BN_dup(L);
        }
        BIGNUM* getP() {
            return BN_dup(p);
        }
        BIGNUM* getL() {
            return BN_dup(L);
        }
        ~PrivateKey() {
            BN_free(p);
            BN_free(L);
        }

    private:
        BIGNUM* p;
        BIGNUM* L;
};

// 定义安全参数：k_M、k_r、k_L、k_p、k_q
extern int k_M;
extern int k_r;
extern int k_L;
extern int k_p;
extern int k_q;

// 定义安全参数N
extern BIGNUM* N;

// 声明私钥指针
extern PrivateKey* sk;

/**
 * @Method 生成x比特的随机数
 * @param int
 * @return BIGNUM
 */
BIGNUM* generateRandom(int x);

/**
 * @Method 生成x比特的随机素数
 * @param x
 * @return int
 */
BIGNUM* generateRandomPrime(int x);

/**
 * @Method 秘钥生成
 * @return void
 */
void generateKeys(int a, int b, int c, int d, int e);

/**
 * @Method 加密
 * @param BIGNUM*  m 消息
 * @param PrivateKey *sk 私钥
 * @return BIGNUM* [[m]] 密文消息
 */
BIGNUM* encrypt_SHE(BIGNUM* m, PrivateKey* sk);

/**
 * @Method 解密
 * @param BIGNUM* E_m 密文消息
 * @param PrivateKey *sk 私钥
 * @return BIGNUM* m 消息
 */
BIGNUM* decrypt_SHE(BIGNUM* E_m, PrivateKey* sk);

/**
 * @Method 同态加法，方案一
 * @param BIGNUM* E_m1 密文
 * @param BIGNUM* E_m2 密文
 * @return BIGNUM* [[m1 + m2]] 相加后的密文消息
 */
BIGNUM* Addition_one(BIGNUM* E_m1, BIGNUM* E_m2);

/**
 * @Method 同态加法，方案二
 * @param BIGNUM* E_m1 密文
 * @param BIGNUM* m2 明文
 * @return BIGNUM* [[m1 + m2]] 相加后的密文消息
 */
BIGNUM* Addition_two(BIGNUM* E_m1, BIGNUM* m2);

/**
 * @Method 同态乘法，方案一
 * @param BIGNUM* E_m1 密文
 * @param BIGNUM* E_m2 密文
 * @return BIGNUM* [[m1 * m2]] 相乘后的密文消息
 */
BIGNUM* Multiplication_one(BIGNUM* E_m1, BIGNUM* E_m2);

/**
 * @Method 同态乘法，方案二
 * @param BIGNUM* E_m1 密文
 * @param BIGNUM* m2 明文
 * @return BIGNUM* [[m1 * m2]] 相乘后的密文消息
 */
BIGNUM* Multiplication_two(BIGNUM* E_m1, BIGNUM* m2);


#endif //SHE_H
