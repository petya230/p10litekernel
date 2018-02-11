#include <asm/compiler.h>
#include <linux/compiler.h>
#include <linux/fd.h>
#include <linux/tty.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/semaphore.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_reserved_mem.h>
#include <linux/of_device.h>
#include <linux/of_platform.h>
#include <linux/delay.h>
#include <linux/timer.h>
#include <linux/atomic.h>
#include <linux/notifier.h>
#include <linux/printk.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/interrupt.h>
#include <linux/hisi/ipc_msg.h>
#include <linux/hisi/hisi_rproc.h>
#include <linux/hisi/kirin_partition.h>
#include <linux/clk.h>
#include <linux/mm.h>
#include "soc_acpu_baseaddr_interface.h"
#include "soc_sctrl_interface.h"
#include "hisi_hisee.h"
#include "hisi_hisee_fs.h"
#include "hisi_hisee_power.h"
#include "hisi_hisee_upgrade.h"
#include "hisi_hisee_chip_test.h"

/*
 * this module implements: manufacture function; slt test functions; channel test function
 */

/* part 1: manufacture function */
extern void release_hisee_semphore(void);

static int otp_image_upgrade_func(void *buf, int para)
{
	int ret;
	ret = write_hisee_otp_value(OTP_IMG_TYPE);
	check_and_print_result();
	set_errno_and_return(ret);
}/*lint !e715*/

static int write_rpmb_key_func (void *buf, int para)
{
	char *buff_virt = NULL;
	phys_addr_t buff_phy = 0;
	atf_message_header *p_message_header;
	int ret = HISEE_OK;
	int image_size = 0;

	buff_virt = (void *)dma_alloc_coherent(g_hisee_data.cma_device, SIZE_1K * 4,
											&buff_phy, GFP_KERNEL);
	if (buff_virt == NULL) {
		pr_err("%s(): dma_alloc_coherent failed\n", __func__);
		set_errno_and_return(HISEE_NO_RESOURCES);
	}
	memset(buff_virt, 0, SIZE_1K * 4);
	p_message_header = (atf_message_header *)buff_virt;
	set_message_header(p_message_header, CMD_WRITE_RPMB_KEY);
	image_size = HISEE_ATF_MESSAGE_HEADER_LEN;
	ret = send_smc_process(p_message_header, buff_phy, image_size,
							HISEE_ATF_WRITE_RPMBKEY_TIMEOUT, CMD_WRITE_RPMB_KEY);
	dma_free_coherent(g_hisee_data.cma_device, (unsigned long)(SIZE_1K * 4), buff_virt, buff_phy);
	check_and_print_result();
	set_errno_and_return(ret);
}/*lint !e715*/

static int set_sm_lcs_func(void *buf, int para)
{
	char *buff_virt = NULL;
	phys_addr_t buff_phy = 0;
	atf_message_header *p_message_header;
	int ret = HISEE_OK;
	int image_size;
	unsigned int result_offset;

	buff_virt = (void *)dma_alloc_coherent(g_hisee_data.cma_device, SIZE_1K * 4,
											&buff_phy, GFP_KERNEL);
	if (buff_virt == NULL) {
		pr_err("%s(): dma_alloc_coherent failed\n", __func__);
		set_errno_and_return(HISEE_NO_RESOURCES);
	}
	memset(buff_virt, 0, SIZE_1K * 4);
	p_message_header = (atf_message_header *)buff_virt;
	set_message_header(p_message_header, CMD_SET_LCS_SM);

	image_size = HISEE_ATF_MESSAGE_HEADER_LEN;
	result_offset = HISEE_ATF_MESSAGE_HEADER_LEN;
	p_message_header->test_result_phy = (unsigned int)buff_phy + result_offset;
	p_message_header->test_result_size = SIZE_1K * 4 - result_offset;
	ret = send_smc_process(p_message_header, buff_phy, (unsigned int)image_size,
							HISEE_ATF_GENERAL_TIMEOUT, CMD_SET_LCS_SM);
	if (HISEE_OK != ret) {
		pr_err("%s(): hisee reported fail code=%d\n", __func__, *((int *)(void *)(buff_virt + result_offset)));
	}

	dma_free_coherent(g_hisee_data.cma_device, (unsigned long)(SIZE_1K * 4), buff_virt, buff_phy);
	check_and_print_result();
	set_errno_and_return(ret);
}/*lint !e715*/

static int upgrade_one_file_func(char *filename, se_smc_cmd cmd)
{
	char *buff_virt;
	phys_addr_t buff_phy = 0;
	atf_message_header *p_message_header;
	int ret = HISEE_OK;
	int image_size = 0;

	buff_virt = (void *)dma_alloc_coherent(g_hisee_data.cma_device, HISEE_SHARE_BUFF_SIZE,
											&buff_phy, GFP_KERNEL);
	if (buff_virt == NULL) {
		pr_err("%s(): dma_alloc_coherent failed\n", __func__);
		set_errno_and_return(HISEE_NO_RESOURCES);
	}
	memset(buff_virt, 0, HISEE_SHARE_BUFF_SIZE);
	p_message_header = (atf_message_header *)buff_virt; /*lint !e826*/
	set_message_header(p_message_header, cmd);

	ret = hisee_read_file((const char *)filename, (buff_virt + HISEE_ATF_MESSAGE_HEADER_LEN), 0, 0);
	if (ret < HISEE_OK) {
		pr_err("%s(): hisee_read_file failed, filename=%s, ret=%d\n", __func__, filename, ret);
		dma_free_coherent(g_hisee_data.cma_device, (unsigned long)HISEE_SHARE_BUFF_SIZE, buff_virt, buff_phy);
		set_errno_and_return(ret);
	}
	image_size = (ret + HISEE_ATF_MESSAGE_HEADER_LEN);
	ret = send_smc_process(p_message_header, buff_phy, (unsigned int)image_size,
							HISEE_ATF_GENERAL_TIMEOUT, cmd);
	dma_free_coherent(g_hisee_data.cma_device, (unsigned long)HISEE_SHARE_BUFF_SIZE, buff_virt, buff_phy);
	check_and_print_result();
	set_errno_and_return(ret);
}

static int factory_apdu_test_func(void *buf, int para)
{
	int ret = HISEE_OK;
	ret = upgrade_one_file_func("/hisee_fs/test.apdu.bin", CMD_FACTORY_APDU_TEST);
	check_and_print_result();
	set_errno_and_return(ret);
}

int verify_key(void)
{
	char *buff_virt;
	phys_addr_t buff_phy = 0;
	atf_message_header *p_message_header;
	int ret = HISEE_OK;
	unsigned int image_size;

	buff_virt = (void *)dma_alloc_coherent(g_hisee_data.cma_device, (unsigned long)SIZE_1K * 4,
											&buff_phy, GFP_KERNEL);
	if (buff_virt == NULL) {
		pr_err("%s(): dma_alloc_coherent failed\n", __func__);
		set_errno_and_return(HISEE_NO_RESOURCES);
	}
	memset(buff_virt, 0, (unsigned long)SIZE_1K * 4);
	p_message_header = (atf_message_header *)buff_virt;  /*lint !e826*/
	set_message_header(p_message_header, CMD_HISEE_VERIFY_KEY);
	image_size = HISEE_ATF_MESSAGE_HEADER_LEN;
	ret = send_smc_process(p_message_header, buff_phy, image_size,
							HISEE_ATF_GENERAL_TIMEOUT, CMD_HISEE_VERIFY_KEY);
	dma_free_coherent(g_hisee_data.cma_device, (unsigned long)(SIZE_1K * 4), buff_virt, buff_phy);
	check_and_print_result();
	set_errno_and_return(ret);
}

static int g_hisee_debug_flag = 0;
void hisee_debug(void)
{
#ifdef CONFIG_HISI_DEBUG_FS
	g_hisee_debug_flag = 1;
#endif
}

static int hisee_total_manafacture_func(void *buf, int para)
{
	int ret1, ret = HISEE_OK;
	unsigned int hisee_lcs_mode = 0;
	int write_rpmbkey_try = 5;
	cosimage_version_info misc_version;
	/*unsigned char apdu_key_cmd0[21] = {	0xF0, 0x10, 0x00, 0x00, \
								0x10, 0x01, 0x23, 0x45, \
								0x67, 0x89, 0xab, 0xcd, \
								0xef, 0xfe, 0xdc, 0xba, \
								0x98, 0x76, 0x54, 0x32, \
								0x10};
	unsigned char apdu_key_cmd1[5] = {0xF0,0xd8, 0x00,0x00,0x00};
	unsigned char apdu_key_cmd2[5] = {0x00, 0xa4, 0x04, 0x00, 0x00};
	unsigned char apdu_key_cmd3[12] = {0x80, 0xe4, 0x00, 0x80,0x07, \
									  0x4f, 0x05, 0x12, 0x34, 0x56, \
									  0x78, 0x90};*/

	ret = get_hisee_lcs_mode(&hisee_lcs_mode);
	if (HISEE_OK != ret) {
		pr_err("%s() get_hisee_lcs_mode failed,ret=%d\n", __func__, ret);
		set_errno_and_return(ret);
	}
write_rpmbkey_retry_process:
	ret = hisee_poweroff_func(NULL, HISEE_PWROFF_LOCK);
	if (HISEE_OK != ret) {
		pr_err("%s() hisee_poweroff_func 1 failed,ret=%d\n", __func__, ret);
		set_errno_and_return(ret);
	}
	if (HISEE_DM_MODE_MAGIC == hisee_lcs_mode) {
		ret = hisee_poweron_upgrade_func(NULL, 0);
	} else {
		ret = hisee_poweron_upgrade_func(NULL, HISEE_POWER_ON_UPGRADE_SM);
	}
	if (HISEE_OK != ret) {
		pr_err("%s() poweron upgrade failed,ret=%d\n", __func__, ret);
		set_errno_and_return(ret);
	}

	hisee_mdelay(200); /*lint !e744 !e747 !e748*/
	if (HISEE_DM_MODE_MAGIC == hisee_lcs_mode) {
		ret = write_rpmb_key_func(NULL, 0);
		if (HISEE_OK != ret) {
			write_rpmbkey_try--;
			if (0 == write_rpmbkey_try) {
				pr_err("%s() write_rpmb_key_func failed,ret=%d\n", __func__, ret);
				goto err_process;
			}
			goto write_rpmbkey_retry_process;
		}
	}

	hisee_mdelay(DELAY_BETWEEN_STEPS); /*lint !e744 !e747 !e748*/
	ret = cos_image_upgrade_func(NULL, HISEE_FACTORY_TEST_VERSION);
	if (HISEE_OK != ret) {
		pr_err("%s() cos_image_upgrade_func failed,ret=%d\n", __func__, ret);
		goto err_process;
	}

	if (HISEE_DM_MODE_MAGIC == hisee_lcs_mode) {
		hisee_mdelay(DELAY_BETWEEN_STEPS); /*lint !e744 !e747 !e748*/
		ret = hisee_poweron_booting_func(NULL, 0);
		if (HISEE_OK != ret) {
			pr_err("%s() poweron booting failed,ret=%d\n", __func__, ret);
			set_errno_and_return(ret);
		}
		wait_hisee_ready(HISEE_STATE_MISC_READY, 30000);

		ret = otp_image_upgrade_func(NULL, 0);
		if (HISEE_OK != ret) {
			pr_err("%s() otp_image_upgrade_func failed,ret=%d\n", __func__, ret);
			goto err_process;
		}

		hisee_mdelay(DELAY_BETWEEN_STEPS); /*lint !e744 !e747 !e748*/

		ret = misc_image_upgrade_func(NULL, 0);
		if (HISEE_OK != ret) {
			pr_err("%s() misc_image_upgrade_func failed,ret=%d\n", __func__, ret);
			return ret;
		}

		wait_hisee_ready(HISEE_STATE_COS_READY, 30000);

		/* verify key */
		ret = verify_key();
		if (HISEE_OK != ret) {
			pr_err("%s() verify_key failed,ret=%d\n", __func__, ret);
			goto err_process;
		}

		 /* write current misc version into record area */
		if (g_misc_version) {
			misc_version.magic = HISEE_SW_VERSION_MAGIC_VALUE;
			misc_version.img_version_num = g_misc_version;
			access_hisee_image_partition((char *)&misc_version, MISC_VERSION_WRITE_TYPE);
		}
	}else {
		ret = hisee_misc_process();
		if (HISEE_OK != ret) {
			pr_err("%s() hisee_misc_process failed,ret=%d\n", __func__, ret);
			goto err_process;
		}
	}
	/* cos should be ready now */

	ret = factory_apdu_test_func(NULL, 0);
	if (HISEE_OK != ret) {
		pr_err("%s() factory_apdu_test_func failed,ret=%d\n", __func__, ret);
		goto err_process;
	}

	/* send command to delete test applet */
	ret = send_apdu_cmd(HISEE_DEL_TEST_APPLET);
	if (HISEE_OK != ret) {
		pr_err("%s() send_apdu_cmd failed,ret=%d\n", __func__, ret);
		goto err_process;
	}

	if (HISEE_DM_MODE_MAGIC == hisee_lcs_mode) {
		if (g_hisee_debug_flag == 0) {

			ret = set_sm_lcs_func(NULL, 0);
			if (HISEE_OK != ret) {
				pr_err("%s() set_sm_lcs_func failed,ret=%d\n", __func__, ret);
				goto err_process;
			}

			hisee_mdelay(DELAY_BETWEEN_STEPS); /*lint !e744 !e747 !e748*/
			ret = set_hisee_lcs_sm_flg();
			if (HISEE_OK != ret) {
				pr_err("%s() set_hisee_lcs_sm_flg failed,ret=%d\n", __func__, ret);
				set_errno_and_return(ret);
				BUG_ON(1);
			}
		}
	}
	pr_err("%s() success!\n", __func__);
	ret = HISEE_OK;

err_process:
	ret1 = hisee_poweroff_func(NULL, HISEE_PWROFF_LOCK);
	if (HISEE_OK != ret1) {
		pr_err("%s() hisee poweroff entry failed,ret=%d\n", __func__, ret1);
		ret = ret1;
	}
	hisee_mdelay(DELAY_BETWEEN_STEPS);
	if (HISEE_OK == ret)
		release_hisee_semphore();

	set_errno_and_return(ret);
}

static int factory_test_body(void *arg)
{
	int ret;

	if (g_hisee_data.factory_test_state != HISEE_FACTORY_TEST_RUNNING) {
		pr_err("%s BUG_ON\n", __func__);
		BUG_ON(1);
	}
	ret = hisee_total_manafacture_func(NULL, 0);
	if (HISEE_OK != ret)
		g_hisee_data.factory_test_state = HISEE_FACTORY_TEST_FAIL;
	else
		g_hisee_data.factory_test_state = HISEE_FACTORY_TEST_SUCCESS;

	check_and_print_result();
	set_errno_and_return(ret);
} /*lint !e715*/

int hisee_parallel_manafacture_func(void *buf, int para)
{
	int ret = HISEE_OK;
	struct task_struct *factory_test_task = NULL;

	if (HISEE_FACTORY_TEST_RUNNING != g_hisee_data.factory_test_state) {
		g_hisee_data.factory_test_state = HISEE_FACTORY_TEST_RUNNING;
		factory_test_task = kthread_run(factory_test_body, NULL, "factory_test_body");
		if (!factory_test_task) {
			ret = HISEE_THREAD_CREATE_ERROR;
			g_hisee_data.factory_test_state = HISEE_FACTORY_TEST_FAIL;
			pr_err("hisee err create factory_test_task failed\n");
		}
	}
	set_errno_and_return(ret);
}/*lint !e715*/


/* part 2: slt test functions */
#ifdef __SLT_FEATURE__
static int application_upgrade_func(void *buf, int para)
{
	char *buff_virt = NULL;
	phys_addr_t buff_phy = 0;
	atf_message_header *p_message_header;
	int ret = HISEE_OK;
	int image_size = 0;

	buff_virt = (void *)dma_alloc_coherent(g_hisee_data.cma_device, HISEE_SHARE_BUFF_SIZE,
										&buff_phy, GFP_KERNEL);

	if (buff_virt == NULL) {
		pr_err("%s(): dma_alloc_coherent failed\n", __func__);
		set_errno_and_return(HISEE_NO_RESOURCES);
	}
	memset(buff_virt, 0, HISEE_SHARE_BUFF_SIZE);
	p_message_header = (atf_message_header *)buff_virt;
	set_message_header(p_message_header, CMD_UPGRADE_APPLET);
	ret = hisee_read_file((const char *)"/hisee_fs/applet.apdu.bin", (buff_virt + HISEE_ATF_MESSAGE_HEADER_LEN), 0, 0);
	if (ret < HISEE_OK) {
		pr_err("%s(): filesys_hisee_read_image failed, ret=%d\n", __func__, ret);
		goto oper_over1;
	}
	image_size = (ret + HISEE_ATF_MESSAGE_HEADER_LEN);
	ret = send_smc_process(p_message_header, buff_phy, image_size,
							HISEE_ATF_APPLICATION_TIMEOUT, CMD_UPGRADE_APPLET);
	if (HISEE_OK != ret) {
		pr_err("%s(): send_smc_process failed, ret=%d\n", __func__, ret);
		goto oper_over1;
	}
oper_over1:
	dma_free_coherent(g_hisee_data.cma_device, (unsigned long)HISEE_SHARE_BUFF_SIZE, buff_virt, buff_phy);
	check_and_print_result();
	set_errno_and_return(ret);
}/*lint !e715*/

int hisee_total_slt_func(void *buf, int para)
{
	int ret1, ret = HISEE_OK;

	ret = hisee_poweroff_func(NULL, HISEE_PWROFF_LOCK);
	if (HISEE_OK != ret) {
		pr_err("%s() hisee_poweroff_func 1 failed,ret=%d\n", __func__, ret);
		set_errno_and_return(ret);
	}
	ret = hisee_poweron_upgrade_func(NULL, 0);
	if (HISEE_OK != ret) {
		pr_err("%s() poweron upgrade failed,ret=%d\n", __func__, ret);
		set_errno_and_return(ret);
	}
	hisee_mdelay(300); /*lint !e744 !e747 !e748*/
	ret = cos_image_upgrade_func(NULL, HISEE_FACTORY_TEST_VERSION);
	if (HISEE_OK != ret) {
		pr_err("%s() cos_image_upgrade_func failed,ret=%d\n", __func__, ret);
		goto err_process;
	}

	hisee_mdelay(DELAY_BETWEEN_STEPS); /*lint !e744 !e747 !e748*/
	ret = hisee_poweron_booting_func(NULL, 0);
	if (HISEE_OK != ret) {
		pr_err("%s() poweron booting failed,ret=%d\n", __func__, ret);
		set_errno_and_return(ret);
	}
	wait_hisee_ready(HISEE_STATE_MISC_READY, 30000);

	ret = misc_image_upgrade_func(NULL, 0);
	if (HISEE_OK != ret) {
		pr_err("%s() misc_image_upgrade_func failed,ret=%d\n", __func__, ret);
		goto err_process;
	}

	wait_hisee_ready(HISEE_STATE_COS_READY, 30000);
	ret = factory_apdu_test_func(NULL, 0);
	if (HISEE_OK != ret) {
		pr_err("%s() factory_apdu_test_func failed,ret=%d\n", __func__, ret);
		goto err_process;
	}

	/* send command to delete test applet */
	ret = send_apdu_cmd(HISEE_DEL_TEST_APPLET);
	if (HISEE_OK != ret) {
		pr_err("%s() send_apdu_cmd failed,ret=%d\n", __func__, ret);
		goto err_process;
	}

	pr_err("%s() success!\n", __func__);
	ret = HISEE_OK;

err_process:
	ret1 = hisee_poweroff_func(NULL, HISEE_PWROFF_LOCK);
	if (HISEE_OK != ret1) {
		pr_err("%s() hisee poweroff entry failed,ret=%d\n", __func__, ret1);
		ret = ret1;
	}
	hisee_mdelay(DELAY_BETWEEN_STEPS);

	set_errno_and_return(ret);
}

int hisee_read_slt_func(void *buf, int para)
{
	int err_code;
	int ret = HISEE_OK;

	err_code = atomic_read(&g_hisee_errno);

	if (HISEE_OK == err_code) {
		if (HISEE_FACTORY_TEST_SUCCESS != g_hisee_data.factory_test_state) {
			pr_err("%s() SLT test is not success, test_state=%x\n", __func__, g_hisee_data.factory_test_state);
			ret = HISEE_ERROR;
		}
	} else {
		ret = err_code;
		pr_err("%s() ret=%d\n", __func__, ret);
	}
	return ret;
}

static int slt_test_body(void *arg)
{
	int ret;
	int try_cnt = 3;

	if (g_hisee_data.factory_test_state != HISEE_FACTORY_TEST_RUNNING) {
		pr_err("%s BUG_ON\n", __func__);
		BUG_ON(1);
	}
	do {
		ret = hisee_total_slt_func(NULL, 0);
		if (HISEE_OK == ret) {
			g_hisee_data.factory_test_state = HISEE_FACTORY_TEST_SUCCESS;
			check_and_print_result();
			set_errno_and_return(ret);
		}
		try_cnt--;
	} while(try_cnt > 0);
	g_hisee_data.factory_test_state = HISEE_FACTORY_TEST_FAIL;
	check_and_print_result();
	set_errno_and_return(ret);
} /*lint !e715*/

int hisee_parallel_total_slt_func(void *buf, int para)
{
	int ret = HISEE_OK;
	struct task_struct *slt_test_task = NULL;

	if (HISEE_FACTORY_TEST_RUNNING != g_hisee_data.factory_test_state) {
		g_hisee_data.factory_test_state = HISEE_FACTORY_TEST_RUNNING;
		slt_test_task = kthread_run(slt_test_body, NULL, "slt_test_body");
		if (!slt_test_task) {
			ret = HISEE_THREAD_CREATE_ERROR;
			g_hisee_data.factory_test_state = HISEE_FACTORY_TEST_FAIL;
			pr_err("hisee err create slt_test_task failed\n");
		} else
			pr_err("%s() success!\n", __func__);
	}
	set_errno_and_return(ret);
}/*lint !e715*/

#endif /*__SLT_FEATURE__*/


/* part 3: channel test function */
#ifdef CONFIG_HISI_DEBUG_FS
/**
 *notes: echo command should add "new line" character(0xa) to the end of string.
 *so path should discard this character.
 */
static int hisee_test(char *path, phys_addr_t result_phy, size_t result_size)
{
	char *buff_virt = NULL;
	phys_addr_t buff_phy = 0;
	char fullname[MAX_PATH_NAME_LEN + 1] = { 0 };
	int fd;
	int i = 0;
	mm_segment_t fs;
	atf_message_header *p_message_header;
	int ret;
	int image_size;

	do {
		if (0xa == path[i] || 0x20 == path[i]) {
			break;
		}
		fullname[i] = path[i];
		i++;
	} while (i < MAX_PATH_NAME_LEN);
	if (i <= 0) {
		pr_err("%s() filename is invalid\n", __func__);
		set_errno_and_return(HISEE_CHANNEL_TEST_PATH_ABSENT_ERROR);
	}

	fs = get_fs();
	set_fs(KERNEL_DS);
	fd = (int)sys_open(fullname, O_RDONLY, HISEE_FILESYS_DEFAULT_MODE);
	if (fd < 0) {
		pr_err("%s(): open %s failed, fd=%d\n", __func__, fullname, fd);
		set_fs(fs);
		set_errno_and_return(HISEE_CHANNEL_TEST_PATH_ABSENT_ERROR);
	}
	image_size = sys_lseek(fd, 0, SEEK_END);
	if (image_size < 0) {
		pr_err("%s(): sys_lseek failed from set.\n", __func__);
		sys_close(fd);
		set_fs(fs);
		set_errno_and_return(HISEE_LSEEK_FILE_ERROR);
	}
	image_size += HISEE_ATF_MESSAGE_HEADER_LEN;
	pr_err("%s() file size is 0x%x\n", __func__, image_size);
	sys_close(fd);

	sys_unlink(TEST_SUCCESS_FILE);
	sys_unlink(TEST_FAIL_FILE);
	sys_unlink(TEST_RESULT_FILE);
	set_fs(fs);

	buff_virt = (void *)dma_alloc_coherent(g_hisee_data.cma_device, ALIGN_UP_4KB(image_size),
											&buff_phy, GFP_KERNEL);
	if (buff_virt == NULL) {
		pr_err("%s(): dma_alloc_coherent failed\n", __func__);
		set_errno_and_return(HISEE_NO_RESOURCES);
	}
	memset(buff_virt, 0, ALIGN_UP_4KB(image_size));
	p_message_header = (atf_message_header *)buff_virt;
	set_message_header(p_message_header, CMD_HISEE_CHANNEL_TEST);
	p_message_header->test_result_phy = result_phy;
	p_message_header->test_result_size = result_size;

	ret = hisee_read_file(fullname, buff_virt + HISEE_ATF_MESSAGE_HEADER_LEN, 0, image_size - HISEE_ATF_MESSAGE_HEADER_LEN);
	if (ret < HISEE_OK) {
		pr_err("%s(): hisee_read_file failed, ret=%d\n", __func__, ret);
		dma_free_coherent(g_hisee_data.cma_device, (unsigned long)ALIGN_UP_4KB(image_size), buff_virt, buff_phy);
		set_errno_and_return(ret);
	}

	ret = send_smc_process(p_message_header, buff_phy, image_size,
							HISEE_ATF_GENERAL_TIMEOUT, CMD_HISEE_CHANNEL_TEST);

	fs = get_fs();
	set_fs(KERNEL_DS);
	fd = (int)sys_mkdir(TEST_DIRECTORY_PATH, HISEE_FILESYS_DEFAULT_MODE);
	if (fd < 0 && (-EEXIST != fd)) {/*EEXIST(File exists), don't return error*/
		set_fs(fs);
		dma_free_coherent(g_hisee_data.cma_device, (unsigned long)ALIGN_UP_4KB(image_size), buff_virt, buff_phy);
		pr_err("create dir %s fail, ret: %d.\n", TEST_DIRECTORY_PATH, fd);
		return fd;
	}
	if (HISEE_OK == ret) {
		/* create file for test flag */
		pr_err("%s(): rcv result size is 0x%x\r\n", __func__, p_message_header->test_result_size);
		if ((g_hisee_data.channel_test_item_result.phy == p_message_header->test_result_phy) &&
			(g_hisee_data.channel_test_item_result.size >= (long)p_message_header->test_result_size)) {
			fd = (int)sys_open(TEST_RESULT_FILE, O_RDWR|O_CREAT, 0);
			if (fd < 0) {
				pr_err("sys_open %s fail, fd: %d.\n", TEST_RESULT_FILE, fd);
				ret = fd;
				goto error;
			}
			sys_write(fd, g_hisee_data.channel_test_item_result.buffer, p_message_header->test_result_size);
			sys_close(fd);
			fd = (int)sys_open(TEST_SUCCESS_FILE, O_RDWR|O_CREAT, 0);
			if (fd < 0) {
				pr_err("sys_open %s fail, fd: %d.\n", TEST_SUCCESS_FILE, fd);
				ret = fd;
				goto error;
			}
			sys_close(fd);
			ret = HISEE_OK;
		} else {
			fd = (int)sys_open(TEST_FAIL_FILE, O_RDWR|O_CREAT, 0);
			if (fd < 0) {
				pr_err("sys_open %s fail, fd: %d.\n", TEST_FAIL_FILE, fd);
				ret = fd;
				goto error;
			}
			sys_close(fd);
			ret = HISEE_CHANNEL_TEST_WRITE_RESULT_ERROR;
		}
	} else {
		fd = (int)sys_open(TEST_FAIL_FILE, O_RDWR|O_CREAT, 0);
		if (fd < 0) {
			pr_err("sys_open %s fail, fd: %d.\n", TEST_FAIL_FILE, fd);
			ret = fd;
			goto error;
		}
		sys_close(fd);
		ret = HISEE_CHANNEL_TEST_WRITE_RESULT_ERROR;
	}

error:
	set_fs(fs);
	dma_free_coherent(g_hisee_data.cma_device, (unsigned long)ALIGN_UP_4KB(image_size), buff_virt, buff_phy);
	set_errno_and_return(ret);
}

static int channel_test_check_buffer_size(char *buff)
{
	int i, j, k, value;
	int offset = 0;

	if (0 == strncmp(buff + offset, "result_size:0x", sizeof("result_size:0x") - 1)) {
		offset += sizeof("result_size:0x") - 1;
		/* find last size char */
		i = 0;
		while (0x20 != buff[offset + i]) {
			i++;
		}

		if (0 == i) {
			pr_err("result size is bad, use default size.\n");
			k = 0;
			g_hisee_data.channel_test_item_result.size = CHANNEL_TEST_RESULT_SIZE_DEFAULT;
		} else {
			g_hisee_data.channel_test_item_result.size = 0;
			k = i;
			i--;
			j = 0;
			while (i >= 0) {
				if ((buff[offset + i] >= '0') && (buff[offset + i] <= '9')) {
					value = buff[offset + i] - 0x30;
				} else if ((buff[offset + i] >= 'a') && (buff[offset + i] <= 'f')) {
					value = buff[offset + i] - 'a' + 0x10;
				} else if ((buff[offset + i] >= 'A') && (buff[offset + i] <= 'F')) {
					value = buff[offset + i] - 'A' + 0x10;
				} else {
					pr_err("result size is bad, use default size.\n");
					g_hisee_data.channel_test_item_result.size = TEST_RESULT_SIZE_DEFAULT;
					break;
				}
				g_hisee_data.channel_test_item_result.size += (value << (unsigned int)j);
				i--;
				j += 4;
			}
		}
		offset += k;
	} else {
		g_hisee_data.channel_test_item_result.size = TEST_RESULT_SIZE_DEFAULT;
	}
	return offset;
}
#endif /*CONFIG_HISI_DEBUG_FS; hisee_channel_test_func inner functions*/

int hisee_channel_test_func(void *buf, int para)
{
#ifdef CONFIG_HISI_DEBUG_FS
	char *buff = buf;
	int ret = HISEE_OK;
	int offset = 0;

	if (NULL == buf) {
		pr_err("%s(): input buf is NULL.\n", __func__);
		set_errno_and_return(HISEE_NO_RESOURCES);
	}
	bypass_space_char();

	offset = channel_test_check_buffer_size(buff);

	pr_err("result size is 0x%x.\n", g_hisee_data.channel_test_item_result.size);
	if (0 == g_hisee_data.channel_test_item_result.size) {
		pr_err("result size is bad.\r\n");
		set_errno_and_return(HISEE_CHANNEL_TEST_CMD_ERROR);
	}

	bypass_space_char();

	if (0 == buff[offset]) {
		pr_err("test file path is bad.\n");
		set_errno_and_return(HISEE_CHANNEL_TEST_CMD_ERROR);
	}

	if (NULL != g_hisee_data.channel_test_item_result.buffer) {
		dma_free_coherent(g_hisee_data.cma_device,
					(unsigned long)ALIGN_UP_4KB(g_hisee_data.channel_test_item_result.size),
					g_hisee_data.channel_test_item_result.buffer,
					g_hisee_data.channel_test_item_result.phy);
	}

	g_hisee_data.channel_test_item_result.buffer = (char *)dma_alloc_coherent(g_hisee_data.cma_device,
													ALIGN_UP_4KB(g_hisee_data.channel_test_item_result.size),
													(dma_addr_t *)&g_hisee_data.channel_test_item_result.phy,
													GFP_KERNEL);
	if (NULL == g_hisee_data.channel_test_item_result.buffer) {
		pr_err("%s(): alloc 0x%x fail.\r\n", __func__, ALIGN_UP_4KB(g_hisee_data.channel_test_item_result.size));
		set_errno_and_return(HISEE_CHANNEL_TEST_RESULT_MALLOC_ERROR);
	}


    ret = hisee_test(buff + offset, g_hisee_data.channel_test_item_result.phy, g_hisee_data.channel_test_item_result.size);
	if (HISEE_OK != ret) {
		pr_err("%s(): hisee_test fail, ret = %d\n", __func__, ret);
	}
	dma_free_coherent(g_hisee_data.cma_device,
				(unsigned long)ALIGN_UP_4KB(g_hisee_data.channel_test_item_result.size),
				g_hisee_data.channel_test_item_result.buffer,
				g_hisee_data.channel_test_item_result.phy);
	g_hisee_data.channel_test_item_result.buffer = NULL;
	g_hisee_data.channel_test_item_result.phy = 0;
	g_hisee_data.channel_test_item_result.size = 0;
	check_and_print_result();
	set_errno_and_return(ret);
#else
	int ret = HISEE_OK;
	check_and_print_result();
	set_errno_and_return(ret);
#endif
}/*lint !e715*/
