#include <linux/err.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/version.h>
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
#include "klog.h"
#include "kernel_compat.h"

// 常量定义
#define SHA256_DIGEST_SIZE 32
#define CERT_MAX_LENGTH 1024
#define ZIP_EOCD_XOR_KEY 0xcafebabeu
#define ZIP_EOCD_XOR_RESULT 0xccfbf1eeu

// 哈希描述结构
struct sdesc {
    struct shash_desc shash;
    char ctx[];
};

// ZIP 文件头结构
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

// 签名密钥结构
struct apk_sign_key {
    unsigned size;
    const char *sha256;
};

// 签名密钥数组
static struct apk_sign_key apk_sign_keys[] = {
    {0x35c, "947ae944f3de4ed4c21a7e4f7953ecf351bfa2b36239da37a34111ad29993eef"}, // SHIRKNEKO
    {0x396, "f415f4ed9435427e1fdf7f1fccd4dbc07b3d6b8751e4dbcec6f19671f427870b"}, // RSUNTK
    {0x29c, "946b0557e450a6430a0ba6b6bccee5bc12953ec8735d55e26139b0ec12303b21"}, // NEKO
    {0x300, "0000000000000000000000000000000000000000000000000000000000000000"}, // OTHER
    {0x033b, "c371061b19d8c7d7d6133c6a9bafe198fa944e50c1b31c9d8daa8d7f1fc2d2d6"}, // WEISHU
    {384, "7e0c6d7278a3bb8e364e0fcba95afaf3666cf5ff3c245a3b63c8833bd0445cc4"}, // 5EC1CFF
    {0x316, "a997df357d1e3a42d3d68f6a2797e3ecec79b21c8972cafc1834c5386920d428"}, // KSU
#ifdef CONFIG_KSU_SUSFS
    {EXPECTED_SIZE, EXPECTED_HASH}, // 可配置的签名密钥
#endif
};

// 初始化 sdesc 结构用于哈希计算
static struct sdesc *init_sdesc(struct crypto_shash *alg)
{
    struct sdesc *sdesc;
    int size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
    sdesc = kmalloc(size, GFP_KERNEL);
    if (!sdesc)
        return ERR_PTR(-ENOMEM);
    sdesc->shash.tfm = alg;
    return sdesc;
}

// 计算数据的哈希值
static int calc_hash(struct crypto_shash *alg, const unsigned char *data,
                     unsigned int datalen, unsigned char *digest)
{
    struct sdesc *sdesc;
    int ret;
    sdesc = init_sdesc(alg);
    if (IS_ERR(sdesc))
        return PTR_ERR(sdesc);
    ret = crypto_shash_digest(&sdesc->shash, data, datalen, digest);
    kfree(sdesc);
    return ret;
}

// 计算数据的 SHA256 哈希
static int ksu_sha256(const unsigned char *data, unsigned int datalen,
                      unsigned char *digest)
{
    struct crypto_shash *alg;
    int ret;
    alg = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(alg))
        return PTR_ERR(alg);
    ret = calc_hash(alg, data, datalen, digest);
    crypto_free_shash(alg);
    return ret;
}

// 检查签名块是否匹配任何预期的签名密钥
static bool check_block(struct file *fp, u32 *size4, loff_t *pos, u32 *offset)
{
    int i;
    struct apk_sign_key sign_key;

    ksu_kernel_read_compat(fp, size4, sizeof(u32), pos);
    ksu_kernel_read_compat(fp, size4, sizeof(u32), pos);
    ksu_kernel_read_compat(fp, size4, sizeof(u32), pos);
    *offset += sizeof(u32) * 3;

    ksu_kernel_read_compat(fp, size4, sizeof(u32), pos);
    *pos += *size4;
    *offset += sizeof(u32) + *size4;

    ksu_kernel_read_compat(fp, size4, sizeof(u32), pos);
    ksu_kernel_read_compat(fp, size4, sizeof(u32), pos);
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
        hash_str[SHA256_DIGEST_SIZE * 2] = '\0';
        if (strcmp(sign_key.sha256, hash_str) == 0)
            return true;
    }
    return false;
}

// 检查 APK 是否包含 V1 签名文件 META-INF/MANIFEST.MF
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

// 检查 APK 的 V2 签名是否有效，并确保没有 V1 签名和 V3 签名
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
        uint32_t offset = 0;
        ksu_kernel_read_compat(fp, &size8, sizeof(size8), &pos);
        if (size8 == size_of_block)
            break;
        ksu_kernel_read_compat(fp, &id, sizeof(id), &pos);
        offset += sizeof(id);
        if (id == 0x7109871au) {
            v2_signing_blocks++;
            v2_signing_valid = check_block(fp, &size4, &pos, &offset);
        } else if (id == 0xf05368c0u) {
            v3_signing_exist = true;
        } else if (id == 0x1b93ad61u) {
            v3_1_signing_exist = true;
        } else {
#ifdef CONFIG_KSU_DEBUG
            pr_info("Unknown id: 0x%08x\n", id);
#endif
        }
        pos += (size8 - offset);
    }
    if (v2_signing_blocks != 1)
        v2_signing_valid = false;
clean:
    filp_close(fp, NULL);
    if (v3_signing_exist || v3_1_signing_exist) {
#ifdef CONFIG_KSU_DEBUG
        pr_err("Unexpected v3 signature scheme found!\n");
#endif
        return false;
    }
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
    pr_info("ksu_manager_uid set to %d\n", ksu_debug_manager_uid);
    return rv;
}
static struct kernel_param_ops expected_size_ops = {
    .set = set_expected_size,
    .get = param_get_uint,
};
module_param_cb(ksu_debug_manager_uid, &expected_size_ops, &ksu_debug_manager_uid, S_IRUSR | S_IWUSR);
#endif

// 判断是否为合法的管理员 APK
bool ksu_is_manager_apk(const char *path)
{
    return check_v2_signature(path);
}