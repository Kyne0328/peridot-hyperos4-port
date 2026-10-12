#!/usr/bin/env python3
"""Disabling-only ReSukiSU root-only transformation. Default: review/dry-run.
Requires the exact pristine upstream pin and exact LF file bytes. Does not build,
execute project code, contact devices, fetch sources, commit, or push.
"""
import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

DATA = json.loads(r'''{
  "commit": "34210a4dec297cb48ce4bfa1c5ba50a2f7d22641",
  "files": {
    "kernel/feature/selinux_hide.c": {
      "expected_git_blob": "a57ed013f7da086b56eb2924e3aa3ddef7c8a3e2",
      "full_replacement": "/* Root-only downstream boundary: excluded capabilities are deliberately absent. */\n#include <linux/init.h>\n#include <linux/errno.h>\n#include \"root_only_gate.h\"\n#include \"feature/selinux_hide.h\"\n\nvoid __init ksu_selinux_hide_init(void) {}\nvoid __exit ksu_selinux_hide_exit(void) {}\nvoid ksu_selinux_hide_drop_backup_if_unused(void) {}\nvoid ksu_selinux_hide_handle_second_stage(void) {}\nvoid ksu_selinux_hide_handle_post_fs_data(void) {}\n\n/* Never install this adapter in a SELinux operation table. */\nint ksu_handle_selinux_setprocattr(const char *name, void *value, size_t size)\n{\n    (void)name;\n    (void)value;\n    (void)size;\n    return -EOPNOTSUPP;\n}\n"
    },
    "kernel/feature/kernel_umount.c": {
      "expected_git_blob": "d0ddc7c93ab2e7686f4f738494013fe65946af5b",
      "full_replacement": "/* Root-only downstream boundary: excluded capabilities are deliberately absent. */\n#include <linux/init.h>\n#include \"root_only_gate.h\"\n#include \"feature/kernel_umount.h\"\n\nvoid __init ksu_kernel_umount_init(void) {}\nvoid __exit ksu_kernel_umount_exit(void) {}\n\nint ksu_handle_umount(uid_t old_uid, uid_t new_uid)\n{\n    (void)old_uid;\n    (void)new_uid;\n    return 0;\n}\n\nvoid try_umount(const char *mnt, int flags)\n{\n    (void)mnt;\n    (void)flags;\n}\n"
    },
    "kernel/feature/module_load_filter.c": {
      "expected_git_blob": "bbe7c4ce97de7abc9b334efb5dc96805d969e1c0",
      "full_replacement": "/* Root-only downstream boundary: excluded capabilities are deliberately absent. */\n#include <linux/init.h>\n#include \"root_only_gate.h\"\n#include \"feature/module_load_filter.h\"\n\n/* Upstream adapter contract: 1 means continue the original module-load path. */\nint ksu_handle_init_module(const void __user *umod, unsigned long umod_len)\n{\n    (void)umod;\n    (void)umod_len;\n    return 1;\n}\n\nint ksu_handle_finit_module(int fd, int flags)\n{\n    (void)fd;\n    (void)flags;\n    return 1;\n}\n\nvoid __init ksu_module_load_filter_hook_init(void) {}\nvoid __exit ksu_module_load_filter_hook_exit(void) {}\n"
    },
    "kernel/core/init.c": {
      "expected_git_blob": "15e34108c03a54955bcc4afb8477c8484ca7c723",
      "operations": [
        {
          "old": "char ksu_block_modules[256];\nmodule_param_string(block_modules, ksu_block_modules, sizeof(ksu_block_modules), 0);\nMODULE_PARM_DESC(block_modules, \"Comma-separated preset module names to acknowledge without loading\");\n",
          "new": ""
        }
      ]
    },
    "kernel/feature/module_load_filter.h": {
      "expected_git_blob": "ecc0c939e487558caf91b19a6393ec7df8711452",
      "operations": [
        {
          "old": "// 256 should enough\nextern char ksu_block_modules[256];\n\n",
          "new": ""
        }
      ]
    },
    "kernel/feature/kernel_umount.h": {
      "expected_git_blob": "d76044a046a8e9ad4d2a46366e52de2607e0e616",
      "operations": [
        {
          "old": "// for the umount list\nstruct mount_entry {\n    char *umountable;\n    unsigned int flags;\n    struct list_head list;\n};\nextern struct list_head mount_list;\nextern struct rw_semaphore mount_list_lock;\n\n",
          "new": ""
        }
      ]
    },
    "kernel/feature/sucompat.c": {
      "expected_git_blob": "8dbbd847a0e059397f96351e4fef124b775b169c",
      "operations": [
        {
          "old": "extern bool ksu_kernel_umount_enabled;\n\n",
          "new": ""
        }
      ]
    },
    "kernel/selinux/rules.c": {
      "expected_git_blob": "4544b3d125817452c6097315f843cf5481bd4b69",
      "operations": [
        {
          "old": "\nstruct selinux_policy *backup_sepolicy;\n#else\nstruct policydb *backup_policydb;\nstruct sidtab *backup_sidtab;\n",
          "new": ""
        },
        {
          "old": "    backup_sepolicy = ksu_dup_sepolicy(old_pol);\n    if (IS_ERR(backup_sepolicy)) {\n        pr_err(\"failed to create backup sepolicy: %ld\\n\", PTR_ERR(backup_sepolicy));\n        backup_sepolicy = NULL;\n    } else {\n        backup_sepolicy->sidtab = kzalloc(sizeof(*backup_sepolicy->sidtab), GFP_KERNEL);\n        if (!backup_sepolicy->sidtab) {\n            pr_err(\"failed to alloc backup sidtab\\n\");\n            ksu_destroy_sepolicy(backup_sepolicy);\n            backup_sepolicy = NULL;\n        } else {\n            int ret = policydb_load_isids(&backup_sepolicy->policydb, backup_sepolicy->sidtab);\n            if (ret) {\n                pr_err(\"failed to load isids for backup sepolicy: %d!\\n\", ret);\n                kfree(backup_sepolicy->sidtab);\n                ksu_destroy_sepolicy(backup_sepolicy);\n                backup_sepolicy = NULL;\n            } else {\n                pr_info(\"backup sepolicy success! latest_granting=%d\\n\", backup_sepolicy->latest_granting);\n            }\n        }\n    }\n",
          "new": ""
        },
        {
          "old": "    backup_policydb = kzalloc(sizeof(*backup_policydb), GFP_KERNEL);\n\n    ksu_lock_sel_mutex_legacy();\n\n    len = ksu_dup_policydb(policydb_ptr, backup_policydb);\n    pr_info(\"len of ksu_dup_policydb (backup_db) output: %d\", len);\n    if (len < 0) {\n        pr_err(\"failed to dup policydb\");\n        kfree(backup_policydb);\n        backup_policydb = NULL;\n        backup_sidtab = NULL;\n    } else {\n        backup_sidtab = kzalloc(sizeof(*backup_sidtab), GFP_KERNEL);\n        if (!backup_sidtab) {\n            pr_err(\"failed to alloc backup sidtab\\n\");\n            ksu_destroy_policydb(backup_policydb);\n            kfree(backup_policydb);\n            backup_policydb = NULL;\n            backup_sidtab = NULL;\n        } else {\n            int ret = policydb_load_isids(backup_policydb, backup_sidtab);\n            if (ret) {\n                pr_err(\"failed to load isids for backup sepolicy: %d!\\n\", ret);\n                kfree(backup_sidtab);\n                ksu_destroy_policydb(backup_policydb);\n                kfree(backup_policydb);\n                backup_policydb = NULL;\n                backup_sidtab = NULL;\n            } else {\n                pr_info(\"backup sepolicy success!\\n\");\n            }\n        }\n    }\n",
          "new": "    ksu_lock_sel_mutex_legacy();\n"
        }
      ]
    },
    "kernel/include/ksu.h": {
      "expected_git_blob": "2ebbc267604843ad00a9292fdb8f1e7a3736467a",
      "operations": [
        {
          "old": "#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) || defined(KSU_COMPAT_HAS_SELINUX_POLICY_STRUCT)\nextern struct selinux_policy *backup_sepolicy;\n#else\nextern struct policydb *backup_policydb;\nextern struct sidtab *backup_sidtab;\n#endif\n\n",
          "new": ""
        }
      ]
    },
    "kernel/runtime/boot_event.c": {
      "expected_git_blob": "acc6356c436528be4c2085116fe8424749e6a25d",
      "operations": [
        {
          "old": "#if defined(CONFIG_EXT4_FS) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0) || defined(KSU_HAS_MODERN_EXT4))\nextern void ext4_unregister_sysfs(struct super_block *sb);\nint nuke_ext4_sysfs(const char *mnt)\n{\n    struct path path;\n    struct super_block *sb = NULL;\n    const char *name = NULL;\n    int err;\n\n    err = kern_path(mnt, 0, &path);\n    if (err) {\n        pr_err(\"nuke path err: %d\\n\", err);\n        return err;\n    }\n\n    sb = path.dentry->d_inode->i_sb;\n    name = sb->s_type->name;\n    if (strcmp(name, \"ext4\") != 0) {\n        pr_info(\"nuke but module aren't mounted\\n\");\n        path_put(&path);\n        return -EINVAL;\n    }\n\n    ext4_unregister_sysfs(sb);\n    path_put(&path);\n\n    return 0;\n}\n#else\nint nuke_ext4_sysfs(const char *mnt)\n{\n    pr_info(\"%s: feature not implemented!\\n\", __func__);\n    return 0;\n}\n#endif\n",
          "new": "int nuke_ext4_sysfs(const char *mnt)\n{\n    (void)mnt;\n    return -EOPNOTSUPP;\n}\n"
        },
        {
          "old": "#include <linux/err.h>\n",
          "new": "#include <linux/err.h>\n#include <linux/errno.h>\n"
        }
      ]
    },
    "kernel/supercall/dispatch.c": {
      "expected_git_blob": "1edc0640d6a5c526481a943550b66752a935670a",
      "operations": [
        {
          "old": "static int do_uid_should_umount(void __user *arg)\n{\n    struct ksu_uid_should_umount_cmd cmd;\n\n    if (copy_from_user(&cmd, arg, sizeof(cmd))) {\n        return -EFAULT;\n    }\n\n    cmd.should_umount = ksu_uid_should_umount(cmd.uid);\n\n    if (copy_to_user(arg, &cmd, sizeof(cmd))) {\n        pr_err(\"uid_should_umount: copy_to_user failed\\n\");\n        return -EFAULT;\n    }\n\n    return 0;\n}\n",
          "new": "static int do_uid_should_umount(void __user *arg)\n{\n    (void)arg;\n    return -EOPNOTSUPP;\n}\n"
        },
        {
          "old": "static int do_nuke_ext4_sysfs(void __user *arg)\n{\n    struct ksu_nuke_ext4_sysfs_cmd cmd;\n    char mnt[256];\n    long ret;\n\n    if (copy_from_user(&cmd, arg, sizeof(cmd)))\n        return -EFAULT;\n\n    if (!cmd.arg)\n        return -EINVAL;\n\n    memset(mnt, 0, sizeof(mnt));\n\n    const char __user *mnt_user = (const char __user *)(unsigned long)cmd.arg;\n\n    ret = strncpy_from_user(mnt, mnt_user, sizeof(mnt));\n    if (ret < 0) {\n        pr_err(\"nuke ext4 copy mnt failed: %ld\\n\", ret);\n        return -EFAULT;\n    }\n\n    if (ret == sizeof(mnt)) {\n        pr_err(\"nuke ext4 mnt path too long\\n\");\n        return -ENAMETOOLONG;\n    }\n\n    pr_info(\"do_nuke_ext4_sysfs: %s\\n\", mnt);\n\n    return nuke_ext4_sysfs(mnt);\n}\n",
          "new": "static int do_nuke_ext4_sysfs(void __user *arg)\n{\n    (void)arg;\n    return -EOPNOTSUPP;\n}\n"
        },
        {
          "old": "struct list_head mount_list = LIST_HEAD_INIT(mount_list);\nDECLARE_RWSEM(mount_list_lock);\n\nstatic int ksu_umount_list_getsize(struct ksu_manage_try_umount_cmd *cmd, bool legacy)\n{\n    // check for pointer first\n    if (!cmd->arg)\n        return -EFAULT;\n\n    struct mount_entry *entry;\n    size_t total_size = 0; // size of list in bytes\n\n    down_read(&mount_list_lock);\n    list_for_each_entry (entry, &mount_list, list) {\n        total_size = total_size + strlen(entry->umountable) + 1; // + 1 for \\0\n\n        if (!legacy) {\n            // not legacy, append the size of flags\n            total_size += sizeof(unsigned int);\n        }\n    }\n    up_read(&mount_list_lock);\n\n    // debug\n    pr_info(\"cmd_manage_try_umount: total_size: %zu\\n\", total_size);\n\n    if (copy_to_user((size_t __user *)cmd->arg, &total_size, sizeof(total_size)))\n        return -EFAULT;\n\n    return 0;\n}\n\nstatic int ksu_umount_list_getlist(struct ksu_manage_try_umount_cmd *cmd, bool legacy)\n{\n    if (!cmd->arg)\n        return -EFAULT;\n\n    struct mount_entry *entry;\n    char __user *user_buf = (char __user *)cmd->arg;\n    size_t len;\n\n    down_read(&mount_list_lock);\n\n    list_for_each_entry (entry, &mount_list, list) {\n        len = strlen(entry->umountable) + 1; // +1 for \\0\n\n        if (copy_to_user(user_buf, entry->umountable, len)) {\n            up_read(&mount_list_lock);\n            return -EFAULT;\n        }\n        user_buf += len;\n\n        if (!legacy) {\n            // non-legacy mode, includes flags too.\n            // userspace can use a struct to receive data because the memory layout is fully consistent.\n            if (copy_to_user(user_buf, &entry->flags, sizeof(entry->flags))) {\n                up_read(&mount_list_lock);\n                return -EFAULT;\n            }\n            user_buf += sizeof(entry->flags);\n        }\n    }\n\n    up_read(&mount_list_lock);\n    return 0;\n}\n\nstatic int manage_try_umount(void __user *arg)\n{\n    struct mount_entry *new_entry, *entry, *tmp;\n    struct ksu_manage_try_umount_cmd cmd;\n    char buf[256] = { 0 };\n\n    if (copy_from_user(&cmd, arg, sizeof cmd))\n        return -EFAULT;\n\n    switch (cmd.mode) {\n    case KSU_UMOUNT_WIPE: {\n        struct mount_entry *entry, *tmp;\n        down_write(&mount_list_lock);\n        list_for_each_entry_safe (entry, tmp, &mount_list, list) {\n            pr_info(\"wipe_umount_list: removing entry: %s\\n\", entry->umountable);\n            list_del(&entry->list);\n            kfree(entry->umountable);\n            kfree(entry);\n        }\n        up_write(&mount_list_lock);\n\n        return 0;\n    }\n\n    case KSU_UMOUNT_ADD: {\n        long len = strncpy_from_user(buf, (const char __user *)cmd.arg, 256);\n        if (len <= 0)\n            return -EFAULT;\n\n        buf[sizeof(buf) - 1] = '\\0';\n\n        new_entry = kzalloc(sizeof(*new_entry), GFP_KERNEL);\n        if (!new_entry)\n            return -ENOMEM;\n\n        new_entry->umountable = kstrdup(buf, GFP_KERNEL);\n        if (!new_entry->umountable) {\n            kfree(new_entry);\n            return -ENOMEM;\n        }\n\n        down_write(&mount_list_lock);\n\n        // disallow dupes\n        // if this gets too many, we can consider moving this whole task to a kthread\n        list_for_each_entry (entry, &mount_list, list) {\n            if (!strcmp(entry->umountable, buf)) {\n                pr_info(\"cmd_manage_try_umount: %s is already here!\\n\", buf);\n                up_write(&mount_list_lock);\n                kfree(new_entry->umountable);\n                kfree(new_entry);\n                return -EEXIST;\n            }\n        }\n\n        // now check flags and add\n        // this also serves as a null check\n        if (cmd.flags)\n            new_entry->flags = cmd.flags;\n        else\n            new_entry->flags = 0;\n\n        // debug\n        list_add(&new_entry->list, &mount_list);\n        up_write(&mount_list_lock);\n        pr_info(\"cmd_manage_try_umount: %s added!\\n\", buf);\n\n        return 0;\n    }\n\n    // this is just strcmp'd wipe anyway\n    case KSU_UMOUNT_DEL: {\n        long len = strncpy_from_user(buf, (const char __user *)cmd.arg, sizeof(buf) - 1);\n        if (len <= 0)\n            return -EFAULT;\n\n        buf[sizeof(buf) - 1] = '\\0';\n\n        down_write(&mount_list_lock);\n        list_for_each_entry_safe (entry, tmp, &mount_list, list) {\n            if (!strcmp(entry->umountable, buf)) {\n                pr_info(\"cmd_manage_try_umount: entry removed: %s\\n\", entry->umountable);\n                list_del(&entry->list);\n                kfree(entry->umountable);\n                kfree(entry);\n            }\n        }\n        up_write(&mount_list_lock);\n\n        return 0;\n    }\n    // this way userspace can deduce the memory it has to prepare.\n    case KSU_UMOUNT_GETSIZE_LEGACY: {\n        return ksu_umount_list_getsize(&cmd, true);\n    }\n\n    case KSU_UMOUNT_GETSIZE_NEW: {\n        return ksu_umount_list_getsize(&cmd, false);\n    }\n\n    // WARNING! this is straight up pointerwalking.\n    // this way we don't need to redefine the ioctl defs.\n    // this also avoids us needing to kmalloc\n    // userspace has to send pointer to memory or pointer to a VLA.\n    // userspace also has to process the flat blob itself and zero init properly.\n    case KSU_UMOUNT_GETLIST_LEGACY: {\n        return ksu_umount_list_getlist(&cmd, true);\n    }\n\n    case KSU_UMOUNT_GETLIST_NEW: {\n        return ksu_umount_list_getlist(&cmd, false);\n    }\n    default: {\n        pr_err(\"cmd_manage_try_umount: invalid operation %u\\n\", cmd.mode);\n        return -EINVAL;\n    }\n\n    } // switch(cmd.mode)\n\n    return 0;\n}\n",
          "new": "static int manage_try_umount(void __user *arg)\n{\n    (void)arg;\n    return -EOPNOTSUPP;\n}\n"
        },
        {
          "old": "void ksu_supercall_cleanup_state(void)\n{\n    struct mount_entry *entry, *tmp;\n\n    down_write(&mount_list_lock);\n    list_for_each_entry_safe (entry, tmp, &mount_list, list) {\n        list_del(&entry->list);\n        kfree(entry->umountable);\n        kfree(entry);\n    }\n    up_write(&mount_list_lock);\n}\n",
          "new": "void ksu_supercall_cleanup_state(void)\n{\n    /* The root-only build has no mount-list state to release. */\n}\n"
        }
      ]
    },
    "kernel/tools/static_export_check.mk": {
      "expected_git_blob": "cc97681f9327e796270f6d33ed3c658a76bd4dbe",
      "operations": [
        {
          "old": "# Reason: selinux_hide\n$(eval $(call check_symbol_export, static ssize_t (*write_op[]), $(srctree)/security/selinux/selinuxfs.c, write_op))\n",
          "new": ""
        },
        {
          "old": "# Reason: selinux_hide\n$(eval $(call check_symbol_export, static const struct file_operations sel_handle_status_ops, $(srctree)/security/selinux/selinuxfs.c, sel_handle_status_ops))\n",
          "new": ""
        },
        {
          "old": "    # Reason: selinux_hide\n    $(eval $(call check_symbol_export, static struct page *selinux_status_page, $(srctree)/security/selinux/ss/status.c, selinux_status_page))\n",
          "new": ""
        },
        {
          "old": "    # Reason: selinux_hide\n    $(eval $(call check_symbol_export, static void security_dump_masked_av, $(srctree)/security/selinux/ss/services.c, security_dump_masked_av func))\n",
          "new": ""
        },
        {
          "old": "    $(eval $(call check_symbol_export, static DEFINE_MUTEX(selinux_status_lock), $(srctree)/security/selinux/ss/status.c, selinux_status_lock))\n",
          "new": ""
        },
        {
          "old": "    $(eval $(call check_symbol_export, static void context_struct_compute_av, $(srctree)/security/selinux/ss/services.c, context_struct_compute_av func))\n",
          "new": ""
        }
      ]
    }
  },
  "additions": {
    "kernel/include/root_only_gate.h": "/* This header enforces the reviewed build scope; it adds no runtime behavior. */\n#ifndef KSU_ROOT_ONLY_GATE_H\n#define KSU_ROOT_ONLY_GATE_H\n#include <linux/version.h>\n#if !defined(CONFIG_KSU) || defined(MODULE) || !defined(CONFIG_ARM64) || !defined(CONFIG_KSU_TRACEPOINT_HOOK)\n#error \"Root-only candidate requires built-in KernelSU, ARM64 and tracepoint hooks\"\n#endif\n#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0) || LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)\n#error \"This reviewed root-only boundary is limited to kernel 6.1\"\n#endif\n#if defined(CONFIG_KSU_SUSFS) || defined(CONFIG_KSU_MANUAL_HOOK)\n#error \"SUSFS and manual hooks are excluded from this root-only candidate\"\n#endif\n#if defined(CONFIG_KSU_DISABLE_MANAGER) || defined(CONFIG_KSU_DISABLE_POLICY) || defined(CONFIG_KSU_DEBUG) || defined(CONFIG_KSU_TOOLKIT_SUPPORT)\n#error \"Root-only candidate requires manager and per-app policy support, with debug and toolkit disabled\"\n#endif\n#endif\n"
  }
}''')

def blob_sha(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()

def sha256(data):
    return hashlib.sha256(data).hexdigest()

def fail(message):
    raise RuntimeError(message)

def git_read(repo, *arguments):
    result = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8",
    )
    if result.returncode:
        fail("Git read failed: " + result.stderr.strip())
    return result.stdout.strip()

def checked_path(repo, relative):
    candidate = repo.joinpath(*relative.split("/"))
    current = candidate
    while current != repo:
        if current.is_symlink():
            fail("Refusing symlink: " + str(current))
        current = current.parent
    if not candidate.parent.is_dir():
        fail("Missing source directory: " + str(candidate.parent))
    return candidate

def atomic_write(path, content, mode):
    descriptor, temporary = tempfile.mkstemp(prefix=".root-only-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True,
                        help="Root of the pristine pinned ReSukiSU checkout")
    parser.add_argument("--out-dir", type=Path, required=True,
                        help="New receipt directory outside the source checkout")
    parser.add_argument("--apply", action="store_true",
                        help="Write the reviewed changes after all guards pass")
    args = parser.parse_args()
    repo = args.repo.resolve(strict=True)
    if not repo.is_dir():
        fail("--repo must be a directory")
    top = Path(git_read(repo, "rev-parse", "--show-toplevel")).resolve()
    if top != repo:
        fail("--repo must be the ReSukiSU repository root")
    head = git_read(repo, "rev-parse", "HEAD")
    if head != DATA["commit"]:
        fail("Unexpected HEAD: " + head)
    if git_read(repo, "status", "--porcelain=v1", "--untracked-files=all"):
        fail("Checkout must be pristine, including untracked files; keep this helper outside it")
    out = args.out_dir.resolve()
    if out == repo or repo in out.parents:
        fail("--out-dir must be outside the source checkout")
    if out.exists():
        fail("--out-dir must not already exist; use a new directory for each review/apply")
    original = {}
    planned = {}
    modes = {}
    for relative, spec in DATA["files"].items():
        path = checked_path(repo, relative)
        if not path.is_file():
            fail("Missing exact upstream file: " + relative)
        raw = path.read_bytes()
        if blob_sha(raw) != spec["expected_git_blob"]:
            fail("Upstream byte/hash mismatch: " + relative +
                 " (CRLF-normalized checkouts are intentionally rejected)")
        text = raw.decode("utf-8")
        if "full_replacement" in spec:
            result = spec["full_replacement"]
        else:
            result = text
            for operation in spec["operations"]:
                if result.count(operation["old"]) != 1:
                    fail("Expected exact unique match missing: " + relative)
                result = result.replace(operation["old"], operation["new"], 1)
        original[relative] = raw
        planned[relative] = result.encode("utf-8")
        modes[relative] = stat.S_IMODE(path.stat().st_mode)
    for relative, content in DATA["additions"].items():
        path = checked_path(repo, relative)
        if path.exists():
            fail("New scope-guard path already exists: " + relative)
        original[relative] = None
        planned[relative] = content.encode("utf-8")
        modes[relative] = 0o644

    # Preflight is complete. Nothing in the source checkout has been written.
    patches = []
    records = []
    for relative in sorted(planned):
        before = original[relative]
        after = planned[relative]
        patches.extend(difflib.unified_diff(
            [] if before is None else before.decode("utf-8").splitlines(keepends=True),
            after.decode("utf-8").splitlines(keepends=True),
            fromfile="/dev/null" if before is None else "a/" + relative,
            tofile="b/" + relative,
        ))
        records.append({
            "path": relative,
            "upstream_git_blob": DATA["files"].get(relative, {}).get("expected_git_blob"),
            "before_sha256": None if before is None else sha256(before),
            "after_sha256": sha256(after),
            "before_bytes": None if before is None else len(before),
            "after_bytes": len(after),
        })
    patch_bytes = "".join(patches).encode("utf-8")
    manifest = {
        "upstream_commit": head,
        "source_repository": "https://github.com/ReSukiSU/ReSukiSU",
        "mode": "apply" if args.apply else "dry-run",
        "status": "preflight-passed",
        "scope": "ARM64 built-in tracepoint kernel 6.1; no SUSFS/manual/debug/toolkit; manager and policy retained",
        "build_or_runtime_test_performed": False,
        "diff_sha256": sha256(patch_bytes),
        "files": records,
    }
    out.mkdir(parents=True, exist_ok=False)
    (out / "root-only.diff").write_bytes(patch_bytes)

    written = []
    try:
        if args.apply:
            # Recheck source bytes immediately before the first mutation.
            for relative, expected in original.items():
                path = checked_path(repo, relative)
                if expected is None:
                    if path.exists():
                        fail("Concurrent addition detected: " + relative)
                elif path.read_bytes() != expected:
                    fail("Concurrent source change detected: " + relative)
            for relative, after in planned.items():
                atomic_write(checked_path(repo, relative), after, modes[relative])
                written.append(relative)
            for relative, after in planned.items():
                if checked_path(repo, relative).read_bytes() != after:
                    fail("Post-write verification failed: " + relative)
            manifest["status"] = "applied-and-byte-verified"
        else:
            manifest["status"] = "dry-run-complete"
    except BaseException as error:
        rollback = {}
        for relative in reversed(written):
            path = checked_path(repo, relative)
            try:
                # Do not overwrite an unexpected concurrent writer.
                if not path.exists() or path.read_bytes() != planned[relative]:
                    rollback[relative] = "skipped: unexpected concurrent state"
                    continue
                if original[relative] is None:
                    path.unlink()
                else:
                    atomic_write(path, original[relative], modes[relative])
                rollback[relative] = "restored"
            except BaseException as restore_error:
                rollback[relative] = "FAILED: " + str(restore_error)
        manifest["status"] = "failed"
        manifest["error"] = str(error)
        manifest["rollback"] = rollback
        (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        raise
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(manifest["status"])
    print("Diff and byte-hash manifest: " + str(out))
    print("No build, binary execution, device operation, commit or push was performed.")

if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, UnicodeError, ValueError) as error:
        print("STOP: " + str(error), file=sys.stderr)
        sys.exit(2)
