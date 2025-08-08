#include <linux/dcache.h>
#include <linux/security.h>
#include <asm/current.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/sched/task_stack.h>
#ifdef CONFIG_KSU_SUSFS_SUS_SU
#include <linux/susfs_def.h>
#endif

#include "objsec.h"
#include "allowlist.h"
#include "arch.h"
#include "klog.h"
#include "ksud.h"
#include "kernel_compat.h"

// KernelSU 的 'su' 兼容模块

#define SU_PATH "/system/bin/su"
#define SH_PATH "/system/bin/sh"

// 声明外部函数和变量
extern void ksu_escape_to_root();
extern u32 ksu_devpts_sid;

// 当 CONFIG_KSU_KPROBES_HOOK 未定义时，使用非Kprobes模式
#ifndef CONFIG_KSU_KPROBES_HOOK
static bool ksu_sucompat_non_kp __read_mostly = true;
#endif

// SUSFS 相关变量
#ifdef CONFIG_KSU_SUSFS_SUS_SU
bool ksu_devpts_hook = false;
EXPORT_SYMBOL_GPL(ksu_devpts_hook);
bool susfs_is_sus_su_hooks_enabled __read_mostly = false;
int susfs_sus_su_working_mode = 0;
extern bool ksu_su_compat_enabled;
#endif

// 常量定义，优化内存使用
static const char sh_path[] = SH_PATH;
static const char ksud_path[] = KSUD_PATH;
static const char su[] = SU_PATH;

// 在用户栈上分配空间并复制数据
static inline void __user *userspace_stack_buffer(const void *d, size_t len)
{
    char __user *p = (void __user *)current_user_stack_pointer() - len;
    return copy_to_user(p, d, len) ? NULL : p;
}

// 获取 sh 路径的用户空间指针
static inline char __user *sh_user_path(void)
{
    return userspace_stack_buffer(sh_path, sizeof(sh_path));
}

// 获取 ksud 路径的用户空间指针
static inline char __user *ksud_user_path(void)
{
    return userspace_stack_buffer(ksud_path, sizeof(ksud_path));
}

// 处理 faccessat 系统调用，重定向 su 到 sh
int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode, int *__unused_flags)
{
#ifndef CONFIG_KSU_KPROBES_HOOK
    if (!ksu_sucompat_non_kp) {
        return 0;
    }
#endif
#ifndef CONFIG_KSU_SUSFS_SUS_SU
    if (!ksu_is_allow_uid(current_uid().val)) {
        return 0;
    }
#endif

    char path[sizeof(su) + 1] = {0};
    ksu_strncpy_from_user_nofault(path, *filename_user, sizeof(path));

    if (unlikely(!memcmp(path, su, sizeof(su)))) {
        pr_info("faccessat su->sh!\n");
        *filename_user = sh_user_path();
    }

    return 0;
}

// 处理 stat 系统调用（6.1.0+，SUSFS模式）
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0) && defined(CONFIG_KSU_SUSFS_SUS_SU)
struct filename* susfs_ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags)
{
    struct filename *name = getname_flags(*filename_user, getname_statx_lookup_flags(*flags), NULL);

    if (unlikely(IS_ERR(name) || name->name == NULL)) {
        return name;
    }

    if (likely(memcmp(name->name, su, sizeof(su)))) {
        return name;
    }

    pr_info("vfs_fstatat su->sh!\n");
    memcpy((void *)name->name, sh_path, sizeof(sh_path));
    return name;
}
#endif

// 处理 stat 系统调用，重定向 su 到 sh
int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags)
{
#ifndef CONFIG_KSU_KPROBES_HOOK
    if (!ksu_sucompat_non_kp) {
        return 0;
    }
#endif
#ifndef CONFIG_KSU_SUSFS_SUS_SU
    if (!ksu_is_allow_uid(current_uid().val)) {
        return 0;
    }
#endif

    if (unlikely(!filename_user)) {
        return 0;
    }

    char path[sizeof(su) + 1] = {0};
    ksu_strncpy_from_user_nofault(path, *filename_user, sizeof(path));

    if (unlikely(!memcmp(path, su, sizeof(su)))) {
        pr_info("newfstatat su->sh!\n");
        *filename_user = sh_user_path();
    }

    return 0;
}

// 处理 execveat 系统调用，重定向 su 到 ksud 并提权
int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr, void *__never_use_argv, void *__never_use_envp, int *__never_use_flags)
{
    struct filename *filename;

#ifndef CONFIG_KSU_KPROBES_HOOK
    if (!ksu_sucompat_non_kp) {
        return 0;
    }
#endif

    if (unlikely(!filename_ptr))
        return 0;

    filename = *filename_ptr;
    if (IS_ERR(filename)) {
        return 0;
    }

    if (likely(memcmp(filename->name, su, sizeof(su))))
        return 0;

#ifndef CONFIG_KSU_SUSFS_SUS_SU
    if (!ksu_is_allow_uid(current_uid().val))
        return 0;
#endif

    pr_info("do_execveat_common su found\n");
    memcpy((void *)filename->name, ksud_path, sizeof(ksud_path));
    ksu_escape_to_root();

    return 0;
}

// 处理 execve 系统调用，重定向 su 到 ksud 并提权
int ksu_handle_execve_sucompat(int *fd, const char __user **filename_user, void *__never_use_argv, void *__never_use_envp, int *__never_use_flags)
{
#ifndef CONFIG_KSU_KPROBES_HOOK
    if (!ksu_sucompat_non_kp) {
        return 0;
    }
#endif

    char path[sizeof(su) + 1] = {0};

    if (unlikely(!filename_user))
        return 0;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,0,0)
    if (!access_ok(VERIFY_READ, *filename_user, sizeof(path)))
        return 0;
#else
    if (!access_ok(*filename_user, sizeof(path)))
        return 0;
#endif

    long len = strncpy_from_user(path, *filename_user, sizeof(path));
    if (len <= 0 || len > sizeof(path))
        return 0;

    path[sizeof(path) - 1] = '\0';

    if (likely(memcmp(path, su, sizeof(su))))
        return 0;

    if (!ksu_is_allow_uid(current_uid().val))
        return 0;

    pr_info("sys_execve su found\n");
    *filename_user = ksud_user_path();
    ksu_escape_to_root();

    return 0;
}

// 处理 devpts 的 SELinux 上下文
int ksu_handle_devpts(struct inode *inode)
{
#ifndef CONFIG_KSU_KPROBES_HOOK
    if (!ksu_sucompat_non_kp) {
        return 0;
    }
#endif

    if (!current->mm || (current_uid().val % 100000 < 10000) || !ksu_is_allow_uid(current_uid().val)) {
        return 0;
    }

#ifdef CONFIG_KSU_SUSFS_SUS_SU
    if (!ksu_devpts_hook) {
        return 0;
    }
#else
    if (!ksu_devpts_sid) {
        return 0;
    }
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
    struct inode_security_struct *sec = selinux_inode(inode);
#else
    struct inode_security_struct *sec = (struct inode_security_struct *)inode->i_security;
#endif
    if (sec) {
        sec->sid = ksu_devpts_sid;
    }

    return 0;
}
// 包装 devpts 处理函数（备用）
int __ksu_handle_devpts(struct inode *inode)
{
    return ksu_handle_devpts(inode);
}

#ifdef CONFIG_KPROBES
// Kprobe 处理函数：faccessat
static int faccessat_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct pt_regs *real_regs = PT_REAL_REGS(regs);
    int *dfd = (int *)&PT_REGS_PARM1(real_regs);
    const char __user **filename_user = (const char **)&PT_REGS_PARM2(real_regs);
    int *mode = (int *)&PT_REGS_PARM3(real_regs);

    return ksu_handle_faccessat(dfd, filename_user, mode, NULL);
}

// Kprobe 处理函数：newfstatat
static int newfstatat_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct pt_regs *real_regs = PT_REAL_REGS(regs);
    int *dfd = (int *)&PT_REGS_PARM1(real_regs);
    const char __user **filename_user = (const char **)&PT_REGS_PARM2(real_regs);
    int *flags = (int *)&PT_REGS_SYSCALL_PARM4(real_regs);

    return ksu_handle_stat(dfd, filename_user, flags);
}

// Kprobe 处理函数：execve
static int execve_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct pt_regs *real_regs = PT_REAL_REGS(regs);
    const char __user **filename_user = (const char **)&PT_REGS_PARM1(real_regs);

    return ksu_handle_execve_sucompat(AT_FDCWD, filename_user, NULL, NULL, NULL);
}

// Kprobe 处理函数：pts_unix98_lookup
static int pts_unix98_lookup_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct inode *inode;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)
    struct file *file = (struct file *)PT_REGS_PARM2(regs);
    inode = file->f_path.dentry->d_inode;
#else
    inode = (struct inode *)PT_REGS_PARM2(regs);
#endif
    return ksu_handle_devpts(inode);
}

static struct kprobe *su_kps[4];

// 初始化 Kprobe
static struct kprobe *init_kprobe(const char *name, kprobe_pre_handler_t handler)
{
    struct kprobe *kp = kzalloc(sizeof(struct kprobe), GFP_KERNEL);
    if (!kp)
        return NULL;
    kp->symbol_name = name;
    kp->pre_handler = handler;

    int ret = register_kprobe(kp);
    pr_info("sucompat: register_%s kprobe: %d\n", name, ret);
    if (ret) {
        kfree(kp);
        return NULL;
    }

    return kp;
}

// 销毁 Kprobe
static void destroy_kprobe(struct kprobe **kp_ptr)
{
    struct kprobe *kp = *kp_ptr;
    if (!kp)
        return;
    unregister_kprobe(kp);
    synchronize_rcu();
    kfree(kp);
    *kp_ptr = NULL;
}
#endif

// 初始化 sucompat 模块，注册 Kprobe 钩子
void ksu_sucompat_init(void)
{
#ifdef CONFIG_KPROBES
    su_kps[0] = init_kprobe(SYS_EXECVE_SYMBOL, execve_handler_pre);
    su_kps[1] = init_kprobe(SYS_FACCESSAT_SYMBOL, faccessat_handler_pre);
    su_kps[2] = init_kprobe(SYS_NEWFSTATAT_SYMBOL, newfstatat_handler_pre);
    su_kps[3] = init_kprobe("pts_unix98_lookup", pts_unix98_lookup_pre);
#else
    ksu_sucompat_non_kp = true;
    pr_info("ksu_sucompat_init: hooks enabled: execve/execveat_su, faccessat, stat, devpts\n");
#endif
}

// 清理 sucompat 模块，注销 Kprobe 钩子
void ksu_sucompat_exit(void)
{
#ifdef CONFIG_KPROBES
    for (int i = 0; i < ARRAY_SIZE(su_kps); i++) {
        destroy_kprobe(&su_kps[i]);
    }
#else
    ksu_sucompat_non_kp = false;
    pr_info("ksu_sucompat_exit: hooks disabled: execve/execveat_su, faccessat, stat, devpts\n");
#endif
}

#ifdef CONFIG_KSU_SUSFS_SUS_SU
// 检查 Kprobe 是否启用
static bool ksu_is_su_kps_enabled(void)
{
    for (int i = 0; i < ARRAY_SIZE(su_kps); i++) {
        if (su_kps[i]) {
            return true;
        }
    }
    return false;
}

// 禁用 SUSFS su 钩子
void ksu_susfs_disable_sus_su(void)
{
    susfs_is_sus_su_hooks_enabled = false;
    ksu_devpts_hook = false;
    susfs_sus_su_working_mode = SUS_SU_DISABLED;
    if (!ksu_is_su_kps_enabled()) {
        ksu_sucompat_init();
        ksu_su_compat_enabled = true;
    }
}

// 启用 SUSFS su 钩子
void ksu_susfs_enable_sus_su(void)
{
    if (ksu_is_su_kps_enabled()) {
        ksu_sucompat_exit();
        ksu_su_compat_enabled = false;
    }
    susfs_is_sus_su_hooks_enabled = true;
    ksu_devpts_hook = true;
    susfs_sus_su_working_mode = SUS_SU_WITH_HOOKS;
}
#endif