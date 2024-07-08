/**
* @author: WTY
* @date: 2024/7/4
* @description: Definition of constants, operations, and header files
*/

#include "SHE.h"
#include "PHE.h"
#include <openssl/bn.h>
using namespace std;

PublicKey* pk = NULL;
BN_CTX* CTX = BN_CTX_new();

/**
 * @Method: 计算算数平方根，结果向上取整
 * @param BIGNUM*  n 待开方的数
 * @return BIGNUM*  sqrt(n)
 */
BIGNUM* BN_sqrt(const BIGNUM* n) {
    BIGNUM *low = BN_CTX_get(CTX);
    BIGNUM *high = BN_CTX_get(CTX);
    BIGNUM *mid = BN_CTX_get(CTX);
    BIGNUM *mid_squared = BN_CTX_get(CTX);
    BIGNUM *one = BN_CTX_get(CTX);
    BIGNUM *two = BN_CTX_get(CTX);
    BIGNUM *tmp = BN_CTX_get(CTX);

    BN_copy(low, BN_value_one());  // low = 1
    BN_copy(high, n);              // high = n
    BN_one(one);                   // one = 1
    BN_set_word(two, 2);           // two = 2

    while (BN_cmp(low, high) <= 0) {
        BN_add(tmp, low, high);
        BN_rshift1(mid, tmp);      // mid = (low + high) / 2

        BN_sqr(mid_squared, mid, CTX);  // mid_squared = mid * mid

        int cmp = BN_cmp(mid_squared, n);
        if (cmp == 0) {
            BN_free(low);
            BN_free(high);
            BN_free(mid_squared);
            BN_free(one);
            BN_free(two);
            BN_free(tmp);
            return mid; // mid_squared == n, so mid is the sqrt
        } else if (cmp < 0) {
            BN_copy(low, mid);      // low = mid
            BN_add(low, low, one);  // low += 1
        } else {
            BN_copy(high, mid);     // high = mid
            BN_sub(high, high, one);// high -= 1
        }
    }

    BN_free(mid_squared);
    BN_free(one);
    BN_free(two);
    BN_free(tmp);

    return low;
}

/**
 * @Method 生成PHE公钥
 * @return void
 */
void generatePublicKeys_PHE() {
    // 使用SHE的加密方式生成两个为0的密文
    BIGNUM* zero1 = BN_CTX_get(CTX);
    BIGNUM* zero2 = BN_CTX_get(CTX);
    BN_zero(zero1);
    BN_zero(zero2);
    BIGNUM* zero1_prime = encrypt_SHE(zero1, sk);
    BIGNUM* zero2_prime = encrypt_SHE(zero2, sk);
    // 设置公钥
    pk = new PublicKey(k_M, k_r, k_L, k_p, k_q, N, zero1_prime, zero2_prime);

    // 释放临时变量
    BN_free(zero1);
    BN_free(zero2);
    BN_free(zero1_prime);
    BN_free(zero2_prime);
}

/**
 * @Method 生成公钥和私钥
 * @return void
 */
void InitKeys_PHE(int a, int b, int c, int d, int e) {
    // 生成私钥
    generateKeys(a, b, c, d, e);

    // 生成公钥
    generatePublicKeys_PHE();
}

/**
 * @Method 加密
 * @param BIGNUM*  m 消息
 * @param PrivateKey *sk 公钥
 * @return BIGNUM* [[m]] 密文消息
 */
BIGNUM* encrypt_PHE(BIGNUM* m, PublicKey* pk) {
    BIGNUM* E_m = BN_CTX_get(CTX);
    // 生成两个k_r比特的随机数r_1和r_2
    BIGNUM* r_1 = generateRandom(k_r);
    BIGNUM* r_2 = generateRandom(k_r);
    // 创建临时变量
    BIGNUM* temp = BN_CTX_get(CTX);

    // 计算密文[m] = (m + r_1 * zero1_prime + r_2 * zero2_prime) mod N

    // 计算m_prime = (r_1 * zero1_prime) mod N
    BN_mul(E_m, r_1, pk->get_zero1_prime(), CTX);
    BN_mod(E_m, E_m, N, CTX);
    
    // 计算m_prime = (m_prime + m) mod N
    BN_add(E_m, E_m, m);
    BN_mod(E_m, E_m, N, CTX);
    
    
    // 计算temp = (r_2 * zero2_prime) mod N
    BN_mul(temp, r_2, pk->get_zero2_prime(), CTX);
    BN_mod(temp, temp, N, CTX);

    // 计算m_prime = (m_prime + temp) mod N
    BN_add(E_m, E_m, temp);
    BN_mod(E_m, E_m, N, CTX);

    // 释放临时变量
    BN_free(temp);

    // 返回加密结果
    return E_m;
}

/**
 * @Method 解密
 * @param BIGNUM* E_m 密文消息
 * @param PrivateKey *sk 私钥
 * @return BIGNUM* m 消息
 */
BIGNUM* decrypt_PHE(BIGNUM* E_m, PrivateKey* sk) {
    // 计算m_prime = E_m % p % L;
    BIGNUM* m_prime = BN_CTX_get(CTX);
    BN_mod(m_prime, E_m, sk->getP(), CTX);
    BN_mod(m_prime, m_prime, sk->getL(), CTX);

    // 计算sk.getL() / 2
    BIGNUM* half_L = BN_CTX_get(CTX);
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
 *@Method 均值计算
 *@param vector<BIGNUM*> data_list 数据集合
 *@return BIGNUM* avg 均值
 */
BIGNUM* avg_PHE(vector<BIGNUM*> data_list) {
    // // 定义数据拥有者集合
    // vector<DO*> do_list;
    // // 定义数据拥有者持有的数据结合
    // vector<BIGNUM*> data_list;
    // // 定义数据拥有者的个数
    // int n;
    // // 临时变量，存储当前数据拥有者持有的数据
    // string s;
    // // 输入数据
    // scanf("%d", &n);
    // for (int i = 1; i <= n; i++) {
    //     // 输入当前数据拥有者持有的数据
    //     cin >> s;
    //     BIGNUM* data = BN_CTX_get(CTX);;
    //
    //     // 将输入数据转换为 BIGNUM
    //     if (BN_dec2bn(&data, s.c_str()) == 0) {
    //         // 使用 fprintf 输出错误消息到标准错误流
    //         fprintf(stderr, "Failed to convert input to BIGNUM\n");
    //         BN_free(data);
    //     }
    //
    //     // 创建数据拥有者对象
    //     DO* do_i =  new DO(data, NULL, NULL);
    //
    //     // 第一个用户生成公私钥
    //     if (i == 1) {
    //         InitKeys_PHE(20, 80, 80, 1024, 96448);
    //         do_i->set_pk(pk);
    //         do_i->set_sk(sk);
    //     } else {
    //         // 用户1将公钥发送给其它用户
    //         do_i->set_pk(do_list[0]->get_pk());
    //     }
    //
    //     // 将当前的数据加密
    //     do_i->set_x(encrypt_PHE(data, do_i->get_pk()));
    //
    //     // 将当前数据添加到数据集合
    //     data_list.push_back(do_i->get_x());
    //
    //     // 将数据拥有者对象添加到数据拥有者集合
    //     do_list.push_back(do_i);
    // }

    // 创建用户1和用户2
    DO* do1 = new DO(NULL, NULL, NULL);
    DO* do2 = new DO(NULL, NULL, NULL);

    // 用户1生成公私钥
    InitKeys_PHE(20, 80, 80, 1024, 96448);

    do1->set_pk(pk);
    do1->set_sk(sk);

    // 用户1将公钥发送给用户2
    do2->set_pk(do1->get_pk());

    // 用户将数据加密并发送给用户2
    for (int i = 0; i < data_list.size(); i++) {
        data_list[i] = encrypt_PHE(data_list[i], do1->get_pk());
    }

    // 由用户2来计算所有数据的总和
    BIGNUM* sum = BN_CTX_get(CTX);
    BN_zero(sum);
    for (int i = 0; i < data_list.size(); i++) {
        BN_add(sum, sum, data_list[i]);
        BN_mod(sum, sum, N, CTX);
    }

    // 由用户1利用私钥恢复出sum，然后再计算均值
    BIGNUM* avg = BN_CTX_get(CTX);
    BIGNUM* temp = BN_CTX_get(CTX);
    // 将sum解密
    sum = decrypt_PHE(sum, sk);
    BN_set_word(temp, data_list.size());
    BN_div(avg, NULL, sum, temp, CTX);
    // 释放临时变量
    BN_free(temp);
    BN_free(sum);
    //此处均值只保留的整数部分
    return avg;
}

/**
 *@Method 数据比较
 *@param BIGNUM* x1 第一个数据
 *@param BIGNUM* x2 第二个数据
 *@return bool true:x1 > x2;false:x1 <= x2
 */
bool compare_PHE(BIGNUM* x1, BIGNUM* x2) {
    // 创建用户1和用户2
    DO* do1 = new DO(x1, NULL, NULL);
    DO* do2 = new DO(x2, NULL, NULL);

    // 用户1生成公私钥
    InitKeys_PHE(20, 80, 80, 1024, 96448);

    do1->set_pk(pk);
    do1->set_sk(sk);

    // 用户1将公钥发送给用户2
    do2->set_pk(do1->get_pk());

    // 用户1将x1加密，发给用户2
    do1->set_x(encrypt_PHE(x1, do1->get_pk()));

    // 用户2计算res = r1 * (E_x1 - x2) - r2

    // 生成两个k_M比特的随机数r1, r2
    BIGNUM* r1 = BN_CTX_get(CTX);
    BIGNUM* r2= BN_CTX_get(CTX);
    r1 = generateRandom(k_M);
    r2 = generateRandom(k_M);

    // 要保证r1 > r2 > 0
    while (BN_cmp(r1, r2) != 1) {
        r1 = generateRandom(k_M);
        r2 = generateRandom(k_M);
    }

    // 创建临时变量res
    BIGNUM* res = BN_CTX_get(CTX);
    // 计算res = E_x1 - x2
    BN_sub(res, do1->get_x(), x2);

    // 计算res = res * r1
    BN_mul(res, res, r1, CTX);
    // 计算res = res - r2
    BN_sub(res, res, r2);

    // 释放临时变量
    BN_free(r2);

    // 将r1设为0
    BN_zero(r1);

    // 将res发送给用户1并解密
    res = decrypt_PHE(res, do1->get_sk());

    if (BN_cmp(res,r1) < 0) {
        BN_free(r1);
        BN_free(res);
        return false;
    }
    BN_free(r1);
    BN_free(res);
    return true;
}

/**
 *@Method 相等性测试
 *@param BIGNUM* x1 第一个数据
 *@param BIGNUM* x2 第二个数据
 *@return bool true:x1 == x2;false:x1 != x2
 */
bool equal_PHE(BIGNUM* x1, BIGNUM* x2) {
    // 创建用户1和用户2
    DO* do1 = new DO(x1, NULL, NULL);
    DO* do2 = new DO(x2, NULL, NULL);

    // 用户1生成公私钥
    InitKeys_PHE(20, 80, 80, 1024, 96448);

    do1->set_pk(pk);
    do1->set_sk(sk);

    // 用户1将公钥发送给用户2
    do2->set_pk(do1->get_pk());

    // 用户1将(-x1)和(x1^2)加密发送给用户2
    BIGNUM* x1_neg = BN_dup(x1);
    BN_set_negative(x1_neg, 1);
    x1_neg = encrypt_PHE(x1_neg, do1->get_pk());

    BIGNUM* x1_square = BN_CTX_get(CTX);
    BN_mul(x1_square, x1, x1, CTX);
    x1_square = encrypt_PHE(x1_square, do1->get_pk());

    // 用户2计算r1 * (x1_square + 2 * x2 * x1_neg + x2_square) - r2

    BIGNUM* x2_square = BN_CTX_get(CTX);
    BN_mul(x2_square, x2, x2, CTX);

    // 生成两个k_M比特的随机数r1, r2
    BIGNUM* r1 = BN_CTX_get(CTX);
    BIGNUM* r2= BN_CTX_get(CTX);
    r1 = generateRandom(k_M);
    r2 = generateRandom(k_M);

    // 要保证r1 > r2 > 0
    while (BN_cmp(r1, r2) != 1) {
        r1 = generateRandom(k_M);
        r2 = generateRandom(k_M);
    }

    //创建临时变量t
    BIGNUM* t = BN_CTX_get(CTX);
    BN_set_word(t, 2);

    // 创建临时变量res
    BIGNUM* res = BN_CTX_get(CTX);
    BN_mul(res, t, x2, CTX);
    BN_mul(res, res, x1_neg, CTX);
    BN_add(res, res, x1_square);
    BN_add(res, res, x2_square);
    BN_mul(res, res, r1,CTX);
    BN_sub(res, res, r2);

    // 用户2将res发给用户1并解密
    res = decrypt_PHE(res, do1->get_sk());

    // 释放临时变量
    BN_free(x1_neg);
    BN_free(x1_square);
    BN_free(x2_square);
    BN_free(r1);
    BN_free(r2);

    // 将t设为0
    BN_zero(t);
    if (BN_cmp(res,t) == -1) {
        BN_free(t);
        BN_free(res);
        return true;
    }
    BN_free(t);
    return false;
}

/**
 *@Method 求最小值
 *@param vector<BIGNUM*> datas N个数据拥有者持有的数据集
 *@param int left 数据集的左边界
 *@param int right 数据集的右边界
 *@return BIGNUM* min 最小值
 */
BIGNUM* min_PHE(vector<BIGNUM*> datas, int left, int right) {
    // 数组只有一个元素时，它就是最小的元素
    if (left == right) {
        return BN_dup(datas[left]);
    }

    // 将数据集分为两半
    int mid = (left + right) / 2;

    // 递归地求左半部分和右半部分的最小值
    BIGNUM* left_min = min_PHE(datas, left, mid);
    BIGNUM* right_min = min_PHE(datas, mid + 1, right);

    // 比较左半部分和右半部分的最小值，返回较小的那个
    if (BN_cmp(left_min, right_min) < 0) {
       return BN_dup(left_min);
    }

    return BN_dup(right_min);
}

/**
 *@Method 求最大值
 *@param vector<BIGNUM*> datas N个数据拥有者持有的数据集
 *@param int left 数据集的左边界
 *@param int right 数据集的右边界
 *@return BIGNUM* max 最大值
 */
BIGNUM* max_PHE(vector<BIGNUM*> datas, int left, int right) {
    // 数组只有一个元素时，它就是最小的元素
    if (left == right) {
        return BN_dup(datas[left]);
    }

    // 将数据集分为两半
    int mid = (left + right) / 2;

    // 递归地求左半部分和右半部分的最小值
    BIGNUM* left_max = max_PHE(datas, left, mid);
    BIGNUM* right_max = max_PHE(datas, mid + 1, right);

    // 比较左半部分和右半部分的最大值，返回较大的那个
    if (BN_cmp(left_max, right_max) > 0) {
        return BN_dup(left_max);
    }

    return BN_dup(right_max);;
}

/*
 *@Method 包含关系测试
 *@param BIGNUM* x 用户DO1持有的数据
 *@param BIGNUM* y1 用户DO2持有的数据
 *@param BIGNUM* y2 用户DO2持有的数据
 *@return bool true:x not in [y1,y2];false:x in [y1,y2]
 */
bool include_PHE(BIGNUM* x, BIGNUM* y1, BIGNUM* y2) {
    // 创建用户1和用户2
    DO* do1 = new DO(NULL, NULL, NULL);
    DO* do2 = new DO(NULL, NULL, NULL);

    // 用户1生成公私钥
    InitKeys_PHE(20, 80, 80, 1024, 96448);

    do1->set_pk(pk);
    do1->set_sk(sk);

    // 用户1将公钥发送给用户2
    do2->set_pk(do1->get_pk());

    // 用户1将(-x)和(x^2)加密发送给用户2
    BIGNUM* x_neg = BN_dup(x);
    BN_set_negative(x_neg, 1);
    x_neg = encrypt_PHE(x_neg, do1->get_pk());

    BIGNUM* x_square = BN_CTX_get(CTX);
    BN_mul(x_square, x, x, CTX);
    x_square = encrypt_PHE(x_square, do1->get_pk());

    // 用户2计算r1 * (x_square + x_neg * (y1 + y2) + y1 * y2) - r2

    // 生成两个k_M比特的随机数r1, r2
    BIGNUM* r1 = BN_CTX_get(CTX);
    BIGNUM* r2= BN_CTX_get(CTX);
    r1 = generateRandom(k_M);
    r2 = generateRandom(k_M);

    // 要保证r1 > r2 > 0
    while (BN_cmp(r1, r2) != 1) {
        r1 = generateRandom(k_M);
        r2 = generateRandom(k_M);
    }

    // 定义临时变量t1
    BIGNUM* t1 = BN_CTX_get(CTX);
    // t1 = y1 + y2
    BN_add(t1, y1, y2);
    // t1 = x_neg * (y1 + y2)
    BN_mul(t1, x_neg, t1, CTX);

    // 定义临时变量t2
    BIGNUM* t2 = BN_CTX_get(CTX);
    // t2 = y1 * y2
    BN_mul(t2, y1, y2, CTX);

    // t1 = x_square + x_neg * (y1 + y2)
    BN_add(t1, x_square, t1);

    // t1 = x_square + x_neg * (y1 + y2) + y1 * y2
    BN_add(t1, t1, t2);

    // t1 = r1 * (x_square + x_neg * (y1 + y2) + y1 * y2)
    BN_mul(t1, t1, r1, CTX);

    // t1 = r1 * (x_square + x_neg * (y1 + y2) + y1 * y2) - r2
    BN_sub(t1, t1, r2);

    // 用户D01接收t1并解密
    t1 = decrypt_PHE(t1, do1->get_sk());

    // 释放临时变量
    BN_free(r1);
    BN_free(r2);
    BN_free(x_neg);
    BN_free(x_square);

    BN_zero(t2);
    if (BN_cmp(t1, t2) == 1) {
        // 释放临时变量
        BN_free(t1);
        BN_free(t2);
        return true;
    }

    // 释放临时变量
    BN_free(t1);
    BN_free(t2);
    return false;
}

/*
 *@Method 范围相交测试
 *@param BIGNUM* x1 用户DO1持有的数据
 *@param BIGNUM* x2 用户DO1持有的数据
 *@param BIGNUM* y1 用户DO2持有的数据
 *@param BIGNUM* y2 用户DO2持有的数据
 *@return bool true:范围相交; false:范围不相交
 */
bool intersect_PHE(BIGNUM* x1, BIGNUM* x2, BIGNUM* y1, BIGNUM* y2) {
    // 创建用户1和用户2
    DO* do1 = new DO(NULL, NULL, NULL);
    DO* do2 = new DO(NULL, NULL, NULL);

    // 用户1生成公私钥
    InitKeys_PHE(20, 80, 80, 1024, 96448);

    do1->set_pk(pk);
    do1->set_sk(sk);

    // 用户1将公钥发送给用户2
    do2->set_pk(do1->get_pk());

    // 用户1将x1、x2和(x1 * x2)加密发送给用户2
    BIGNUM* E_x1 = BN_CTX_get(CTX);
    E_x1 = encrypt_PHE(x1, do1->get_pk());

    BIGNUM* E_x2 = BN_CTX_get(CTX);
    E_x2 = encrypt_PHE(x2, do1->get_pk());

    BIGNUM* E_x1_mul_x2 = BN_CTX_get(CTX);
    BN_mul(E_x1_mul_x2, x1, x2, CTX);
    E_x1_mul_x2 = encrypt_PHE(E_x1_mul_x2, do1->get_pk());

    // 用户2计算r1 * (x2 * x1 - x2 * y2 - x1 * y1 + y1 * y2) - r2

    // 生成两个k_M比特的随机数r1, r2
    BIGNUM* r1 = BN_CTX_get(CTX);
    BIGNUM* r2= BN_CTX_get(CTX);
    r1 = generateRandom(k_M);
    r2 = generateRandom(k_M);

    // 要保证r1 > r2 > 0
    while (BN_cmp(r1, r2) != 1) {
        r1 = generateRandom(k_M);
        r2 = generateRandom(k_M);
    }

    // 定义临时变量t1
    BIGNUM* t1 = BN_CTX_get(CTX);
    // t1 = x2 * y2
    BN_mul(t1, x2, y2, CTX);

    // 定义临时变量t2
    BIGNUM* t2 = BN_CTX_get(CTX);
    // t2 = x1 * y1
    BN_mul(t2, x1, y1, CTX);

    // 定义临时变量t3
    BIGNUM* t3 = BN_CTX_get(CTX);
    // t3 = y1 * y2
    BN_mul(t3, y1, y2, CTX);

    // t1 = x2 * x1 - x2 * y2
    BN_sub(t1, E_x1_mul_x2, t1);

    // t1 = x2 * x1 - x2 * y2 - x1 * y1
    BN_sub(t1, t1, t2);

    // t1 = x2 * x1 - x2 * y2 - x1 * y1 + y1 * y2
    BN_add(t1, t1, t3);

    // t1 = r1 * (x2 * x1 - x2 * y2 - x1 * y1 + y1 * y2)
    BN_mul(t1, t1, r1, CTX);

    // t1 = r1 * (x2 * x1 - x2 * y2 - x1 * y1 + y1 * y2) - r2
    BN_sub(t1, t1, r2);

    // 用户D01接收t1并解密
    t1 = decrypt_PHE(t1, do1->get_sk());

    // 释放临时变量
    BN_free(r1);
    BN_free(r2);
    BN_free(E_x1);
    BN_free(E_x2);
    BN_free(E_x1_mul_x2);
    BN_free(t3);

    BN_zero(t2);
    if (BN_cmp(t1, t2) == 1) {
        // 释放临时变量
        BN_free(t1);
        BN_free(t2);
        return false;
    }

    // 释放临时变量
    BN_free(t1);
    BN_free(t2);
    return true;
}

/*
 *@Method 求内积
 *@param vector<BIGNUM*> x1 用户DO1持有的数据
 *@param vector<BIGNUM*> y1 用户DO2持有的数据
 *@return BIGNUM* inner_product 内积
 */
BIGNUM* inner_product_PHE(vector<BIGNUM*> x1, vector<BIGNUM*> y1) {
    // 创建用户1和用户2
    DO* do1 = new DO(NULL, NULL, NULL);
    DO* do2 = new DO(NULL, NULL, NULL);

    // 用户1生成公私钥
    InitKeys_PHE(20, 80, 80, 1024, 96448);

    do1->set_pk(pk);
    do1->set_sk(sk);

    // 用户1将公钥发送给用户2
    do2->set_pk(do1->get_pk());

    // 用户1将持有的数据加密发送给用户2
    for (int i = 0; i < x1.size(); i++) {
        x1[i] = encrypt_PHE(x1[i], do1->get_pk());
    }

    // 用户2计算内积
    BIGNUM* inner_product = BN_CTX_get(CTX);
    BN_zero(inner_product);

    // 定义临时变量t
    BIGNUM* t = BN_CTX_get(CTX);

    for (int i= 0; i < x1.size(); i++) {
        // t = x1[i] * y1[i]
        BN_mul(t, x1[i], y1[i], CTX);

        // inner_product += t
        BN_add(inner_product, inner_product, t);
    }

    // 用户1接收 inner_product并解密
    inner_product = decrypt_PHE(inner_product, do1->get_sk());

    // 释放临时变量
    BN_free(t);

    return inner_product;
}

/*
 *@Method 求欧氏距离
 *@param vector<BIGNUM*> x1 用户DO1持有的数据
 *@param vector<BIGNUM*> y1 用户DO2持有的数据
 *@return BIGNUM* distance 欧氏距离
 */
BIGNUM* distance_PHE(vector<BIGNUM*> x1, vector<BIGNUM*> y1) {
    // 用户1构造向量
    vector<BIGNUM*> x2(x1.size() + 2);;
    // 用户2构造向量
    vector<BIGNUM*> y2(y1.size() + 2);

    // 用户1计算向量
    //定义临时变量t
    BIGNUM* t = BN_CTX_get(CTX);
    BN_one(t);
    x2[0] = BN_dup(t);

    // 定义临时变量t2
    BIGNUM* t2 = BN_CTX_get(CTX);
    BN_zero(t2);

    for (int i = 0; i < x1.size(); i++) {
        // 计算-2 * x1[i]
        BN_set_word(t, 2);
        // 设置负号
        BN_set_negative(t, 1);
        BN_mul(t, t, x1[i], CTX);
        x2[i + 1] = BN_dup(t);

        // 计算x1[i] * x1[i]
        BN_mul(t, x1[i], x1[i], CTX);
        // t2 += t
        BN_add(t2, t2, t);
    }

    // x2[x1.size() + 1] = t2
    x2[x1.size() + 1] = BN_dup(t2);

    // 用户2计算向量
    BN_one(t);
    y2[y1.size() + 1] = BN_dup(t);
    BN_zero(t2);

    for (int i = 0; i < y1.size(); i++) {
        y2[i + 1] = BN_dup(y1[i]);

        // 计算y1[i] * y1[i]
        BN_mul(t, y1[i], y1[i], CTX);

        // t2 += t
        BN_add(t2, t2, t);
    }

    // y2[0] = t2
    y2[0] = BN_dup(t2);

    // 使用内积计算欧式距离
    BIGNUM* distance = inner_product_PHE(x2, y2);

    // 求算数平方根
    distance = BN_sqrt(distance);

    // 释放临时变量
    BN_free(t);
    BN_free(t2);

    return distance;
}

/*
 *@Method 将数据分箱
 *@param vector<BIGNUM*> x 待分箱的数据
 *@param int k 分箱个数
 *@return Bin 分箱结果
 */
vector<Bin> split_PHE(vector<BIGNUM*> x, int k) {
    // 定义最大值和最小值
    BIGNUM* max = BN_CTX_get(CTX);
    BIGNUM* min = BN_CTX_get(CTX);
    // 利用安全最值协议计算最大值和最小值
    max = max_PHE(x, 0, x.size() - 1);
    min = min_PHE(x, 0, x.size() - 1);

    // 计算每个分箱的长度: (max - min) / k
    BIGNUM* length = BN_CTX_get(CTX);
    // 将k转为BIGNUM*
    BIGNUM* k_bn = BN_CTX_get(CTX);
    BN_set_word(k_bn, k);
    BN_sub(length, max, min);
    BN_div(length, NULL, length, k_bn, CTX);

    // 创建k个分箱
    vector<Bin> box(k);
    // 定义临时变量
    BIGNUM* temp1 = BN_dup(min);
    // 设置每个分箱的范围
    for (int i = 0; i < k; i++) {
        box[i].lower = BN_dup(temp1);
        BN_add(temp1, temp1, length);
        box[i].upper = BN_dup(temp1);
    }
    if (BN_cmp(temp1, max) < 0) {
        box[k - 1].upper = BN_dup(max);
    }
    // 将数据添加到指定的箱体中，并将数据分箱公开
    // 除最后一个箱体是左闭右闭区间外，其余均是左闭右开区间
    for (int i = 0; i < x.size(); i++) {
        // 单独判断最后一个区间的右边界
        if (BN_cmp(x[i], box[k - 1].upper) >= 0) {
            box[k - 1].elements.push_back(BN_dup(x[i]));
            continue;
        }
        for (int j = 0; j < k; j++) {
            if (BN_cmp(x[i], box[j].upper) < 0) {
                box[j].elements.push_back(BN_dup(x[i]));
                break;
            }
        }
    }

    // 释放临时变量
    BN_free(max);
    BN_free(min);
    BN_free(length);
    BN_free(k_bn);
    BN_free(temp1);

    return box;

    // // 查找数据q映射的分箱
    // for (int i = 0; i < k; i++) {
    //     if (BN_cmp(q, box[i].upper) < 0) {
    //         return box[i];
    //     }
    // }
    //
    // return box[k - 1];
}

/*
 *@Method 计算每个分箱数据出现的频率
 *@param vector<BIGNUM*> x 待分箱的数据
 *@param int k 分箱个数
 *@return vector<BIGNUM*> 分箱频率
 */
vector<BIGNUM*> frequency_PHE(vector<BIGNUM*> x, int k) {
    // 获取数据分箱
    vector<Bin> box = split_PHE(x, k);

    // 创建用户1
    DO* do1 = new DO(NULL, NULL, NULL);
    // 用户1生成公私钥
    InitKeys_PHE(20, 80, 80, 1024, 96448);
    do1->set_pk(pk);
    do1->set_sk(sk);

    // 定义临时变量t
    BIGNUM* t = BN_CTX_get(CTX);
    BN_zero(t);

    // 用户1将公钥公开
    // 每个用户构造一个k维的向量，该用户持有数据的对应分箱位标记为1，其余为0
    // vector<vector<BIGNUM*> > flag(x.size(), vector<BIGNUM*>(k));
    vector<vector<BIGNUM*> > *flag = new vector<vector<BIGNUM*> >(x.size(), vector<BIGNUM*>(k));
    // 初始化flag
    for (int i = 0; i < x.size(); i++) {
        for (int j = 0; j < k; j++) {
            // *flag[i][j] = BN_dup(t);
            (*flag)[i][j] = BN_dup(t);
        }
    }

    for (int i = 0; i < x.size(); i++) {
        // 最后一个区间的右边界单独判断
        if (BN_cmp(x[i], box[k - 1].upper) == 0) {
            // BN_one(flag[i][k - 1]);
            BN_one((*flag)[i][k - 1]);
            continue;
        }
        for (int j = 0; j < k; j++) {
            if (BN_cmp(x[i], box[j].upper) < 0) {
                // BN_one(flag[i][j]);
                BN_one((*flag)[i][j]);
                break;
            }
        }
    }

    // 将k维的向量加密
    for (int i = 0; i < x.size(); i++) {
        // 第2个用户除外
        if (i != 1) {
            for (int j = 0; j < k; j++) {
                // flag[i][j] = encrypt_PHE(flag[i][j], do1->get_pk());
                (*flag)[i][j] = encrypt_PHE((*flag)[i][j], do1->get_pk());
            }
        }
    }

    // 定义分箱频率
    vector<BIGNUM*> frequency(k);

    // 用户2接收每个用户发来的k维向量，并计算每个分箱的频率
    for (int i = 0; i < k; i++) {
        BN_zero(t);
        for (int j = 0; j < x.size(); j++) {
            // BN_add(t, t, flag[j][i]);
            BN_add(t, t, (*flag)[j][i]);
        }
        frequency[i] = BN_dup(t);
    }

    // 用户1接收分箱频率并解密
    for (int i = 0; i < k; i++) {
        frequency[i] = decrypt_PHE(frequency[i], do1->get_sk());
    }

    // 释放临时变量
    BN_free(t);

    return frequency;
}