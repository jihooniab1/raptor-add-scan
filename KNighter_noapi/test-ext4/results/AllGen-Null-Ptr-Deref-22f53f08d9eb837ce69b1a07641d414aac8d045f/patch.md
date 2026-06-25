## Patch Description

ext4: fix possible null-ptr-deref in mbt_kunit_exit()

There's issue as follows:
    # test_new_blocks_simple: failed to initialize: -12
KASAN: null-ptr-deref in range [0x0000000000000638-0x000000000000063f]
Tainted: [E]=UNSIGNED_MODULE, [N]=TEST
RIP: 0010:mbt_kunit_exit+0x5e/0x3e0 [ext4_test]
Call Trace:
 <TASK>
 kunit_try_run_case_cleanup+0xbc/0x100 [kunit]
 kunit_generic_run_threadfn_adapter+0x89/0x100 [kunit]
 kthread+0x408/0x540
 ret_from_fork+0xa76/0xdf0
 ret_from_fork_asm+0x1a/0x30

If mbt_kunit_init() init testcase failed will lead to null-ptr-deref.
So add test if 'sb' is inited success in mbt_kunit_exit().

Fixes: 7c9fa399a369 ("ext4: add first unit test for ext4_mb_new_blocks_simple in mballoc")
Signed-off-by: Ye Bin <yebin10@huawei.com>
Reviewed-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
Reviewed-by: Ojaswin Mujoo <ojaswin@linux.ibm.com>
Link: https://patch.msgid.link/20260330133035.287842-6-yebin@huaweicloud.com
Signed-off-by: Theodore Ts'o <tytso@mit.edu>

## Buggy Code

```c
// Function: mbt_kunit_exit in fs/ext4/mballoc-test.c
static void mbt_kunit_exit(struct kunit *test)
{
	struct super_block *sb = (struct super_block *)test->priv;

	mbt_mb_release(sb);
	mbt_ctx_release(sb);
	mbt_ext4_free_super_block(sb);
}
```

```c
// Function: mbt_kunit_init in fs/ext4/mballoc-test.c
static int mbt_kunit_init(struct kunit *test)
{
	struct mbt_ext4_block_layout *layout =
		(struct mbt_ext4_block_layout *)(test->param_value);
	struct super_block *sb;
	int ret;

	sb = mbt_ext4_alloc_super_block();
	if (sb == NULL)
		return -ENOMEM;

	mbt_init_sb_layout(sb, layout);

	ret = mbt_ctx_init(sb);
	if (ret != 0) {
		mbt_ext4_free_super_block(sb);
		return ret;
	}

	test->priv = sb;
	kunit_activate_static_stub(test,
				   ext4_read_block_bitmap_nowait,
				   ext4_read_block_bitmap_nowait_stub);
	kunit_activate_static_stub(test,
				   ext4_wait_block_bitmap,
				   ext4_wait_block_bitmap_stub);
	kunit_activate_static_stub(test,
				   ext4_get_group_desc,
				   ext4_get_group_desc_stub);
	kunit_activate_static_stub(test,
				   ext4_mb_mark_context,
				   ext4_mb_mark_context_stub);

	/* stub function will be called in mbt_mb_init->ext4_mb_init */
	if (mbt_mb_init(sb) != 0) {
		mbt_ctx_release(sb);
		mbt_ext4_free_super_block(sb);
		return -ENOMEM;
	}

	return 0;
}
```

## Bug Fix Patch

```diff
diff --git a/fs/ext4/mballoc-test.c b/fs/ext4/mballoc-test.c
index 6f5bfbb0e8a4..95cb644cd32f 100644
--- a/fs/ext4/mballoc-test.c
+++ b/fs/ext4/mballoc-test.c
@@ -362,7 +362,6 @@ static int mbt_kunit_init(struct kunit *test)
 		return ret;
 	}
 
-	test->priv = sb;
 	kunit_activate_static_stub(test,
 				   ext4_read_block_bitmap_nowait,
 				   ext4_read_block_bitmap_nowait_stub);
@@ -383,6 +382,8 @@ static int mbt_kunit_init(struct kunit *test)
 		return -ENOMEM;
 	}
 
+	test->priv = sb;
+
 	return 0;
 }
 
@@ -390,6 +391,9 @@ static void mbt_kunit_exit(struct kunit *test)
 {
 	struct super_block *sb = (struct super_block *)test->priv;
 
+	if (!sb)
+		return;
+
 	mbt_mb_release(sb);
 	mbt_ctx_release(sb);
 	mbt_ext4_free_super_block(sb);
```
