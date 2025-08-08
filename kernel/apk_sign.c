#include <linux/err.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/hex.h>
#ifdef CONFIG_KSU_DEBUG
#include <linux/moduleparam.h>
#endif
#include <crypto/hash.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
#include <crypto/sha2.h>
#else
#include <crypto/sha.h>
#endif
#include "apk_sign.h"
#include "kernel_compat.h"

// 签名密钥常量
#define EXPECTED_SIZE_WEISHU     0x033b
#define EXPECTED_HASH_WEISHU     "c371061b19d8c7d7d6133c6a9bafe198fa944e50c1b31c9d8daa8d7f1fc2d2d6"
#define EXPECTED_SIZE_5EC1CFF    384
#define EXPECTED_HASH_5EC1CFF    "7e0c6d7278a3bb8e364e0fcba95afaf3666cf5ff3c245a3b63c8833bd0445cc4"
#define EXPECTED_SIZE_RSUNTK     0x396
#define EXPECTED_HASH_RSUNTK     "f415f4ed9435427e1fdf7f1fccd4dbc07b3d6b8751e4dbcec6f19671f427870b"
#define EXPECTED_SIZE_SHIRKNEKO  0x35c
#define EXPECTED_HASH_SHIRKNEKO  "947ae944f3de4ed4c21a7e4f7953ecf351bfa2b36239da37a34111ad29993eef"
#define EXPECTED_SIZE_NEKO       0x29c
#define EXPECTED_HASH_NEKO       "946b0557e450a6430a0ba6b6bccee5bc12953ec8735d55e26139b0ec12303b21"
#define EXPECTED_SIZE_OTHER      0x300
#define EXPECTED_HASH_OTHER      "0000000000000000000000000000000000000000000000000000000000000000"
#define EXPECTED_SIZE_KSU        0x316
#define EXPECTED_HASH_KSU        "a997df357d1e3a42d3d68f6a2797e3ecec79b21c8972cafc1834c5386920d428"

// 常量定义
#define SHA256_DIGEST_SIZE 32
#define CERT_MAX_LENGTH 1024
#define ZIP_EOCD_XOR_KEY 0xcafebabeu
#define ZIP_EOCD_XOR_RESULT 0xccfbf1eeu

// ZIP 文件签名头部结构
struct zip_entry_header {
    uint32_t signature;
    uint16_t version;
    uint16_t flags;
    uint16_t compression;
    uint16_t mod_time;
    uint16_t mod_date;
    uint32_t crc32;
    uint32_t compressed_size;
    uint32_t uncompressed_size;
    uint16_t file_name_length;
    uint16_t extra_field_length;
} __attribute__((packed));

// 签名密钥数组
static struct apk_sign_key {
    unsigned size;
    const char *sha256;
} apk_sign_keys[] = {
    {EXPECTED_SIZE_SHIRKNEKO, EXPECTED_HASH_SHIRKNEKO},
    {EXPECTED_SIZE_RSUNTK, EXPECTED_HASH_RSUNTK},
    {EXPECTED_SIZE_NEKO, EXPECTED_HASH_NEKO},
    {EXPECTED_SIZE_OTHER, EXPECTED_HASH_OTHER},
    {EXPECTED_SIZE_WEISHU, EXPECTED_HASH_WEISHU},
    {EXPECTED_SIZE_5EC1CFF, EXPECTED_HASH_5EC1CFF},
    {EXPECTED_SIZE_KSU, EXPECTED_HASH_KSU},
#ifdef EXPECTED_SIZE
    {EXPECTED_SIZE, EXPECTED_HASH},
#endif
};

// 签名描述符结构
struct sdesc {
    struct shash_desc shash;
    char ctx[];
};

// 初始化签名描述符
static struct sdesc *init_sdesc(struct crypto_shash *alg)
{
    int size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
    struct sdesc *sdesc = kmalloc(size, GFP_KERNEL);
    if (!sdesc)
        return ERR_PTR(-ENOMEM);
    sdesc->shash.tfm = alg;
    return sdesc;
}

// 计算 SHA256 哈希
static int calc_hash(struct crypto_shash *alg, const unsigned char *data,
                     unsigned int datalen, unsigned char *digest)
{
    struct sdesc *sdesc = init_sdesc(alg);
    if (IS_ERR(sdesc))
        return PTR_ERR(sdesc);

    int ret = crypto_shash_digest(&sdesc->shash, data, datalen, digest);
    kfree(sdesc);
    return ret;
}

// 计算数据的 SHA256 哈希
static int ksu_sha256(const unsigned char *data, unsigned int datalen,
                      unsigned char *digest)
{
    struct crypto_shash *alg = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(alg))
        return PTR_ERR(alg);

    int ret = calc_hash(alg, data, datalen, digest);
    crypto_free_shash(alg);
    return ret;
}

// 检查 APK 签名块
static bool check_block(struct file *fp, u32 *size4, loff_t *pos, u32 *offset)
{
    int i;
    struct apk_sign_key sign_key;

    ksu_kernel_read_compat(fp, size4, sizeof(u32), pos); // signer-sequence length
    ksu_kernel_read_compat(fp, size4, sizeof(u32), pos); // signer length
    ksu_kernel_read_compat(fp, size4, sizeof(u32), pos); // signed data length
    *offset += sizeof(u32) * 3;

    ksu_kernel_read_compat(fp, size4, sizeof(u32), pos); // digests-sequence length
    *pos += *size4;
    *offset += sizeof(u32) + *size4;

    ksu_kernel_read_compat(fp, size4, sizeof(u32), pos); // certificates length
    ksu_kernel_read_compat(fp, size4, sizeof(u32), pos); // certificate length
    *offset += sizeof(u32) * 2;

    for (i = 0; i < ARRAY_SIZE(apk_sign_keys); i++) {
        sign_key = apk_sign_keys[i];
        if (*size4 != sign_key.size)
            continue;

        *offset += *size4;
        if (*size4 > CERT_MAX_LENGTH)
            return false;

        char cert[CERT_MAX_LENGTH];
        ksu_kernel_read_compat(fp, cert, *size4, pos);

        unsigned char digest[SHA256_DIGEST_SIZE];
        if (ksu_sha256((unsigned char *)cert, *size4, digest))
            return false;

        char hash_str[SHA256_DIGEST_SIZE * 2 + 1];
        bin2hex(hash_str, digest, SHA256_DIGEST_SIZE);

        if (strcmp(sign_key.sha256, hash_str) == 0)
            return true;
    }
    return false;
}

// 检查是否存在 V1 签名
static bool has_v1_signature_file(struct file *fp)
{
    const char MANIFEST[] = "META-INF/MANIFEST.MF";
    struct zip_entry_header header;
    loff_t pos = 0;

    while (ksu_kernel_read_compat(fp, &header, sizeof(struct zip_entry_header), &pos) ==
           sizeof(struct zip_entry_header)) {
        if (header.signature != 0x04034b50)
            return false;

        if (header.file_name_length == sizeof(MANIFEST) - 1) {
            char fileName[sizeof(MANIFEST)];
            ksu_kernel_read_compat(fp, fileName, header.file_name_length, &pos);
            fileName[header.file_name_length] = '\0';

            if (strncmp(MANIFEST, fileName, sizeof(MANIFEST) - 1) == 0)
                return true;
        } else {
            pos += header.file_name_length;
        }
        pos += header.extra_field_length + header.compressed_size;
    }
    return false;
}

// 检查 APK 的 V2 签名
static bool check_v2_signature(const char *path)
{
    unsigned char buffer[0x11] = {0};
    u32 size4;
    u64 size8, size_of_block;
    loff_t pos;
    bool v2_signing_valid = false;
    int v2_signing_blocks = 0;
    bool v3_signing_exist = false;
    bool v3_1_signing_exist = false;

    struct file *fp = ksu_filp_open_compat(path, O_RDONLY, 0);
    if (IS_ERR(fp))
        return false;

    fp->f_mode |= FMODE_NONOTIFY;

    if (has_v1_signature_file(fp)) {
        filp_close(fp, NULL);
        return false;
    }

    int i;
    for (i = 0; i <= 0xffff; i++) {
        unsigned short n;
        pos = generic_file_llseek(fp, -i - 2, SEEK_END);
        if (pos < 0)
            goto clean;
        ksu_kernel_read_compat(fp, &n, sizeof(n), &pos);
        if (n == i) {
            pos -= 22;
            ksu_kernel_read_compat(fp, &size4, sizeof(size4), &pos);
            if ((size4 ^ ZIP_EOCD_XOR_KEY) == ZIP_EOCD_XOR_RESULT)
                break;
        }
        if (i == 0xffff)
            goto clean;
    }

    pos += 12;
    ksu_kernel_read_compat(fp, &size4, sizeof(size4), &pos);
    pos = size4 - 0x18;

    ksu_kernel_read_compat(fp, &size8, sizeof(size8), &pos);
    ksu_kernel_read_compat(fp, buffer, 0x10, &pos);
    if (strcmp((char *)buffer, "APK Sig Block 42"))
        goto clean;

    pos = size4 - (size8 + 0x8);
    ksu_kernel_read_compat(fp, &size_of_block, sizeof(size_of_block), &pos);
    if (size_of_block != size8)
        goto clean;

    int loop_count = 0;
    while (loop_count++ < 10) {
        uint32_t id;
        uint32_t offset;
        ksu_kernel_read_compat(fp, &size8, sizeof(size8), &pos);
        if (size8 == size_of_block)
            break;
        ksu_kernel_read_compat(fp, &id, sizeof(id), &pos);
        offset = sizeof(id);

        if (id == 0x7109871au) {
            v2_signing_blocks++;
            v2_signing_valid = check_block(fp, &size4, &pos, &offset);
        } else if (id == 0xf05368c0u) {
            v3_signing_exist = true;
        } else if (id == 0x1b93ad61u) {
            v3_1_signing_exist = true;
        }
        pos += (size8 - offset);
    }

    if (v2_signing_blocks != 1)
        v2_signing_valid = false;

clean:
    filp_close(fp, NULL);
    if (v3_signing_exist || v3_1_signing_exist)
        return false;

    return v2_signing_valid;
}

#ifdef CONFIG_KSU_DEBUG
int ksu_debug_manager_uid = -1;
#include "manager.h"

// 设置调试管理员 UID
static int set_expected_size(const char *val, const struct kernel_param *kp)
{
    int rv = param_set_uint(val, kp);
    ksu_set_manager_uid(ksu_debug_manager_uid);
    return rv;
}

static struct kernel_param_ops expected_size_ops = {
    .set = set_expected_size,
    .get = param_get_uint,
};

module_param_cb(ksu_debug_manager_uid, &expected_size_ops, &ksu_debug_manager_uid, S_IRUSR | S_IWUSR);
#endif

// 检查是否为管理器 APK
bool ksu_is_manager_apk(const char *path)
{
    return check_v2_signature(path);
}