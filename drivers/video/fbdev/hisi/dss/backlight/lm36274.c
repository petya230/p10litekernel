/*
* Simple driver for Texas Instruments LM3639 Backlight + Flash LED driver chip
* Copyright (C) 2012 Texas Instruments
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2 as
* published by the Free Software Foundation.
*
*/
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/i2c.h>
#include <linux/leds.h>
#include <linux/backlight.h>
#include <linux/err.h>
#include <linux/delay.h>
#include <linux/uaccess.h>
#include <linux/interrupt.h>
#include <linux/regmap.h>
#include <linux/semaphore.h>
#include "lm36274.h"
#include "hisi_fb.h"
#if defined (CONFIG_HUAWEI_DSM)
#include <dsm/dsm_pub.h>
extern struct dsm_client *lcd_dclient;
#endif

struct class *lm36274_class = NULL;
struct lm36274_chip_data *lm36274_g_chip = NULL;
/* static int lcd_fake_panel_enable_reg = 0x3; */
static bool lm36274_init_status = false;

/*
** for debug, S_IRUGO
** /sys/module/hisifb/parameters
*/
unsigned lm36274_msg_level = 7;
module_param_named(debug_lm36274_msg_level, lm36274_msg_level, int, 0644);
MODULE_PARM_DESC(debug_lm36274_msg_level, "backlight lm36274 msg level");

static int lm36274_parse_dts(struct device_node *np)
{
	int ret = 0;
	int i = 0;

	for (i = 0;i < LM36274_RW_REG_MAX;i++ ) {
		ret = of_property_read_u32(np, lm36274_dts_string[i], &bl_info.lm36274_reg[i]);
		if (ret < 0) {
			LM36274_INFO("get lm36274 dts config failed\n");
		} else {
			LM36274_INFO("get %s value = 0x%x\n", lm36274_dts_string[i],bl_info.lm36274_reg[i]);
		}
	}

	return ret;
}

static int lm36274_config_register(struct lm36274_chip_data *pchip)
{
	int ret = 0;
	int i = 0;

	for(i = 0;i < LM36274_RW_REG_MAX;i++) {
		ret = regmap_write(pchip->regmap, lm36274_reg_addr[i], bl_info.lm36274_reg[i]);
		if (ret < 0) {
			LM36274_ERR("write lm36274 backlight config register 0x%x failed",lm36274_reg_addr[i]);
			goto exit;
		}
		else{
			LM36274_ERR("register get 0x%x value = 0x%x\n", lm36274_reg_addr[i], bl_info.lm36274_reg[i]);
		}
	}

exit:
	return ret;
}


static int lm36274_config_read(struct lm36274_chip_data *pchip)
{
	int ret = 0;
	int i = 0;
	for(i = 0;i < LM36274_RW_REG_MAX;i++) {
		ret = regmap_read(pchip->regmap, lm36274_reg_addr[i],&bl_info.lm36274_reg[i]);
		if (ret < 0) {
			LM36274_ERR("read lm36274 backlight config register 0x%x failed",&bl_info.lm36274_reg[i]);
			goto exit;
		}
		else{
			LM36274_ERR("read get 0x%x value = 0x%x\n", lm36274_reg_addr[i], bl_info.lm36274_reg[i]);
		}
	}

exit:
	return ret;
}



/* initialize chip */
static int lm36274_chip_init(struct lm36274_chip_data *pchip)
{
	int ret = -1;
	struct device_node *np = NULL;
  /*	int enable_reg = 0xF; */

	LM36274_INFO("in!\n");

	memset(&bl_info, 0, sizeof(struct backlight_information));

	np = of_find_compatible_node(NULL, NULL, DTS_COMP_LM36274);
	if (!np) {
		LM36274_ERR("NOT FOUND device node %s!\n", DTS_COMP_LM36274);
		goto out;
	}

	ret = lm36274_parse_dts(np);
	if (ret < 0) {
		LM36274_ERR("parse lm36274 dts failed");
		goto out;
	}

	ret = lm36274_config_register(pchip);
	if (ret < 0) {
		LM36274_ERR("lm36274 config register failed");
		goto out;
	}

	ret = lm36274_config_read(pchip);
	if (ret < 0) {
		LM36274_ERR("lm36274 config read failed");
		goto out;
	}


	/**
	* if (g_fake_lcd_flag) {
	*	LM36274_INFO("is unknown lcd\n");
	*	enable_reg = 0;
	* }

	* ret = regmap_write(pchip->regmap, REG_BL_ENABLE, enable_reg);
	* if (ret < 0)
	*	goto out;
	*/

	LM36274_INFO("ok!\n");

	return ret;

out:
	dev_err(pchip->dev, "i2c failed to access register\n");
	return ret;
}

/**
 * lm36274_set_backlight_reg(): Set Backlight working mode
 *
 * @bl_level: value for backlight ,range from 0 to 2047
 *
 * A value of zero will be returned on success, a negative errno will
 * be returned in error cases.
 */
ssize_t lm36274_set_backlight_reg(uint32_t bl_level)
{
	ssize_t ret = -1;
	uint32_t level = 0;
	int bl_msb = 0;
	int bl_lsb = 0;
	static int last_level = -1;
/*	static int enable_flag = 0;*/
/*	static int disable_flag = 0;*/

	if (!lm36274_init_status) {
		LM36274_ERR("init fail, return.\n");
		return ret;
	}

	if (down_trylock(&(lm36274_g_chip->test_sem))) {
		LM36274_INFO("Now in test mode\n");
		return 0;
	}

	level = bl_level;

	if (level > BL_MAX) {
		level = BL_MAX;
	}

	 /**
	* if (g_fake_lcd_flag) {
	*	if (level > 0) {
	* 		if (!enable_flag) {
	*			ret = regmap_write(lm36274_g_chip->regmap, REG_BL_ENABLE, lcd_fake_panel_enable_reg);
	*			LM36274_INFO("REG_BL_ENABLE = %d\n", lcd_fake_panel_enable_reg);
	*			mdelay(16);
	*		}
	*		enable_flag = 1;
	*		disable_flag = 0;
	*	} else {
	*	if (!disable_flag) {
	*			ret = regmap_write(lm36274_g_chip->regmap, REG_BL_ENABLE, 0x0);
	*			LM36274_INFO("REG_BL_ENABLE = 0x0\n");
	*			mdelay(16);
	*		}
	*		disable_flag = 1;
	*		enable_flag = 0;
	*	}
	* }
*/
	/* 11-bit brightness code */
	bl_msb = level >> 3;
	bl_lsb = level & 0x07;

	if ((BL_MIN == last_level && LOG_LEVEL_INFO == lm36274_msg_level)
		|| (BL_MIN == level && LOG_LEVEL_INFO == lm36274_msg_level)
		|| (-1 == last_level)) {
		LM36274_INFO("level = %d, bl_msb = %d, bl_lsb = %d\n", level, bl_msb, bl_lsb);
	}

	LM36274_INFO("level = %d, bl_msb = %d, bl_lsb = %d\n", level, bl_msb, bl_lsb);

	ret = regmap_update_bits(lm36274_g_chip->regmap, REG_BL_BRIGHTNESS_LSB, MASK_BL_LSB,bl_lsb);
	if (ret < 0) {
		goto i2c_error;
	}

	ret = regmap_write(lm36274_g_chip->regmap, REG_BL_BRIGHTNESS_MSB, bl_msb);
	if (ret < 0) {
		goto i2c_error;
	}

	last_level = level;
	up(&(lm36274_g_chip->test_sem));
	return ret;

i2c_error:
	up(&(lm36274_g_chip->test_sem));
	dev_err(lm36274_g_chip->dev, "%s:i2c access fail to register\n", __func__);
	return ret;
}
/* EXPORT_SYMBOL(lm36274_set_backlight_reg); */

/**
 * lm36274_set_reg(): Set lm36274 reg
 *
 * @bl_reg: which reg want to write
 * @bl_mask: which bits of reg want to change
 * @bl_val: what value want to write to the reg
 *
 * A value of zero will be returned on success, a negative errno will
 * be returned in error cases.
 */
ssize_t lm36274_set_reg(u8 bl_reg,u8 bl_mask,u8 bl_val)
{
	ssize_t ret = -1;
	u8 reg = bl_reg;
	u8 mask = bl_mask;
	u8 val = bl_val;

	if (!lm36274_init_status) {
		LM36274_ERR("init fail, return.\n");
		return ret;
	}

	if (REG_MAX < reg) {
		LM36274_ERR("Invalid argument!!!\n");
		return ret;
	}

	LM36274_INFO("%s:reg=0x%x,mask=0x%x,val=0x%x\n", __func__, reg, mask, val);

	ret = regmap_update_bits(lm36274_g_chip->regmap, reg, mask, val);
	if (ret < 0) {
		LM36274_ERR("i2c access fail to register\n");
		return ret;
	}

	return ret;
}
EXPORT_SYMBOL(lm36274_set_reg);

static ssize_t lm36274_reg_bl_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct lm36274_chip_data *pchip = NULL;
	struct i2c_client *client = NULL;
	ssize_t ret = -1;
	int bl_lsb = 0;
	int bl_msb = 0;
	int bl_level = 0;

	if (!dev)
		return snprintf(buf, PAGE_SIZE, "dev is null\n");

	pchip = dev_get_drvdata(dev);
	if (!pchip)
		return snprintf(buf, PAGE_SIZE, "data is null\n");

	client = pchip->client;
	if(!client)
		return snprintf(buf, PAGE_SIZE, "client is null\n");

	ret = regmap_read(pchip->regmap, REG_BL_BRIGHTNESS_MSB, &bl_msb);
	if(ret < 0)
		return snprintf(buf, PAGE_SIZE, "LM36274 I2C read error\n");

	ret = regmap_read(pchip->regmap, REG_BL_BRIGHTNESS_LSB, &bl_lsb);
	if(ret < 0)
		return snprintf(buf, PAGE_SIZE, "LM36274 I2C read error\n");

	bl_level = (bl_msb << 3) | bl_lsb;

	return snprintf(buf, PAGE_SIZE, "LM36274 bl_level:%d\n", bl_level);
}

static ssize_t lm36274_reg_bl_store(struct device *dev,
					struct device_attribute *devAttr,
					const char *buf, size_t size)
{
	ssize_t ret = -1;
	struct lm36274_chip_data *pchip = dev_get_drvdata(dev);
	unsigned int bl_level = 0;
	unsigned int bl_msb = 0;
	unsigned int bl_lsb = 0;

	ret = kstrtouint(buf, 10, &bl_level);
	if (ret)
		goto out_input;

	LM36274_INFO("%s:buf=%s,state=%d\n", __func__, buf, bl_level);

	/*if (bl_level < BL_MIN)
		bl_level = BL_MIN;
	*/
	if (bl_level > BL_MAX)
		bl_level = BL_MAX;

	/* 11-bit brightness code */
	bl_msb = bl_level >> 3;
	bl_lsb = bl_level & 0x07;

	LM36274_INFO("bl_level = %d, bl_msb = %d, bl_lsb = %d\n", bl_level, bl_msb, bl_lsb);

	ret = regmap_update_bits(pchip->regmap, REG_BL_BRIGHTNESS_LSB, MASK_BL_LSB, bl_lsb);
	if (ret < 0)
		goto i2c_error;

	ret = regmap_write(pchip->regmap, REG_BL_BRIGHTNESS_MSB, bl_msb);
	if (ret < 0)
		goto i2c_error;

	return size;

i2c_error:
	dev_err(pchip->dev, "%s:i2c access fail to register\n", __func__);
	return snprintf((char *)buf, PAGE_SIZE, "%s: i2c access fail to register\n", __func__);

out_input:
	dev_err(pchip->dev, "%s:input conversion fail\n", __func__);
	return snprintf((char *)buf, PAGE_SIZE, "%s: input conversion fail\n", __func__);
}

static DEVICE_ATTR(reg_bl, (S_IRUGO|S_IWUSR), lm36274_reg_bl_show, lm36274_reg_bl_store);

static ssize_t lm36274_reg_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct lm36274_chip_data *pchip = NULL;
	struct i2c_client *client = NULL;
	ssize_t ret = -1;
	unsigned char val[REG_MAX] = {0};

	if (!dev)
		return snprintf(buf, PAGE_SIZE, "dev is null\n");

	pchip = dev_get_drvdata(dev);
	if (!pchip)
		return snprintf(buf, PAGE_SIZE, "data is null\n");

	client = pchip->client;
	if(!client)
		return snprintf(buf, PAGE_SIZE, "client is null\n");

	ret = regmap_bulk_read(pchip->regmap, REG_REVISION, &val[0], REG_MAX);
	if (ret < 0)
		goto i2c_error;

	return snprintf(buf, PAGE_SIZE, "Revision(0x01)= 0x%x\nBacklight Configuration1(0x02)= 0x%x\n \
			\rBacklight Configuration2(0x03) = 0x%x\nBacklight Brightness LSB(0x04) = 0x%x\n \
			\rBacklight Brightness MSB(0x05) = 0x%x\nBacklight Auto-Frequency Low(0x06) = 0x%x\n \
			\rBacklight Auto-Frequency High(0x07) = 0x%x\nBacklight Enable(0x08) = 0x%x\n \
			\rDisplay Bias Configuration 1(0x09)  = 0x%x\nDisplay Bias Configuration 2(0x0A)  = 0x%x\n \
			\rDisplay Bias Configuration 3(0x0B) = 0x%x\nLCM Boost Bias Register(0x0C) = 0x%x\n \
			\rVPOS Bias Register(0x0D) = 0x%x\nVNEG Bias Register(0x0E) = 0x%x\n \
			\rFlags Register(0x0F) = 0x%x\nBacklight Option 1 Register(0x10) = 0x%x\n \
			\rBacklight Option 2 Register(0x11) = 0x%x\nPWM-to-Digital Code Readback LSB(0x12) = 0x%x\n \
			\rPWM-to-Digital Code Readback MSB(0x13) = 0x%x\n",
			val[0],val[1],val[2],val[3],val[4],val[5],val[6],val[7],
			val[8],val[9],val[10],val[11],val[12],val[13],val[14],val[15],
			val[16],val[17],val[18]);

i2c_error:
	return snprintf(buf, PAGE_SIZE,"%s: i2c access fail to register\n", __func__);
}

static ssize_t lm36274_reg_store(struct device *dev,
					struct device_attribute *devAttr,
					const char *buf, size_t size)
{
	ssize_t ret = -1;
	struct lm36274_chip_data *pchip = dev_get_drvdata(dev);
	unsigned int reg = 0;
	unsigned int mask = 0;
	unsigned int val = 0;

	ret = sscanf(buf, "reg=0x%x, mask=0x%x, val=0x%x",&reg,&mask,&val);
	if (ret < 0) {
		printk("check your input!!!\n");
		goto out_input;
	}

	if (reg > REG_MAX) {
		printk("Invalid argument!!!\n");
		goto out_input;
	}

	LM36274_INFO("%s:reg=0x%x,mask=0x%x,val=0x%x\n", __func__, reg, mask, val);

	ret = regmap_update_bits(pchip->regmap, reg, mask, val);
	if (ret < 0)
		goto i2c_error;

	return size;

i2c_error:
	dev_err(pchip->dev, "%s:i2c access fail to register\n", __func__);
	return snprintf((char *)buf, PAGE_SIZE, "%s: i2c access fail to register\n", __func__);

out_input:
	dev_err(pchip->dev, "%s:input conversion fail\n", __func__);
	return snprintf((char *)buf, PAGE_SIZE, "%s: input conversion fail\n", __func__);
}
static DEVICE_ATTR(reg, (S_IRUGO|S_IWUSR), lm36274_reg_show, lm36274_reg_store);

static const struct regmap_config lm36274_regmap = {
	.reg_bits = 8,
	.val_bits = 8,
	.reg_stride = 1,
};

/* pointers to created device attributes */
static struct attribute *lm36274_attributes[] = {
	&dev_attr_reg_bl.attr,
	&dev_attr_reg.attr,
	NULL,
};

static const struct attribute_group lm36274_group = {
	.attrs = lm36274_attributes,
};

static int lm36274_probe(struct i2c_client *client,
				const struct i2c_device_id *id)
{
	struct i2c_adapter *adapter = client->adapter;
	struct lm36274_chip_data *pchip = NULL;
	int ret = -1;
#if defined (CONFIG_HUAWEI_DSM)
	unsigned int val = 0;
#endif

	LM36274_INFO("in!\n");

	if (!i2c_check_functionality(adapter, I2C_FUNC_I2C)) {
		dev_err(&client->dev, "i2c functionality check fail.\n");
		return -EOPNOTSUPP;
	}

	pchip = devm_kzalloc(&client->dev,
				sizeof(struct lm36274_chip_data), GFP_KERNEL);
	if (!pchip)
		return -ENOMEM;

#ifdef CONFIG_REGMAP_I2C
	pchip->regmap = devm_regmap_init_i2c(client, &lm36274_regmap);
	if (IS_ERR(pchip->regmap)) {
		ret = PTR_ERR(pchip->regmap);
		dev_err(&client->dev, "fail : allocate register map: %d\n", ret);
		goto err_out;
	}
#endif
	pchip->client = client;
	i2c_set_clientdata(client, pchip);

	sema_init(&(pchip->test_sem), 1);

	/* chip initialize */
	ret = lm36274_chip_init(pchip);
	if (ret < 0) {
		dev_err(&client->dev, "fail : chip init\n");
		goto err_out;
	}

#if defined (CONFIG_HUAWEI_DSM)
	ret = regmap_read(pchip->regmap, REG_FLAGS, &val);
	if (ret < 0) {
		dev_err(&client->dev, "fail : read chip reg REG_FAULT_FLAG error!\n");
		goto err_out;
	}

	if (DEVICE_FAULT_OCCUR != val) {
		ret = dsm_client_ocuppy(lcd_dclient);
		if (!ret) {
			dev_err(&client->dev, "fail : REG_FAULT_FLAG statues error 0X0F=%d!\n", val);
			dsm_client_record(lcd_dclient, "REG_FAULT_FLAG statues error 0X0F=%d!\n", val);
			dsm_client_notify(lcd_dclient, DSM_LCD_OVP_ERROR_NO);
			} else {
			dev_err(&client->dev, "dsm_client_ocuppy fail:  ret=%d!\n", ret);
		}
	}
#endif

	pchip->dev = device_create(lm36274_class, NULL, 0, "%s", client->name);
	if (IS_ERR(pchip->dev)) {
		/* Not fatal */
		LM36274_ERR("Unable to create device; errno = %ld\n", PTR_ERR(pchip->dev));
		pchip->dev = NULL;
	} else {
		dev_set_drvdata(pchip->dev, pchip);
		ret = sysfs_create_group(&pchip->dev->kobj, &lm36274_group);
		if (ret)
			goto err_sysfs;
	}

	lm36274_g_chip = pchip;

	LM36274_INFO("name: %s, address: (0x%x) ok!\n", client->name, client->addr);
	lm36274_init_status = true;

	return ret;

err_sysfs:
	device_destroy(lm36274_class, 0);
err_out:
	devm_kfree(&client->dev, pchip);
	return ret;
}

static int lm36274_remove(struct i2c_client *client)
{
	struct lm36274_chip_data *pchip = i2c_get_clientdata(client);

	regmap_write(pchip->regmap, REG_BL_ENABLE, 0x00);

	sysfs_remove_group(&client->dev.kobj, &lm36274_group);

	return 0;
}

static const struct i2c_device_id lm36274_id[] = {
	{LM36274_NAME, 0},
	{}
};

static const struct of_device_id lm36274_of_id_table[] = {
	{.compatible = "ti,lm36274"},
	{ },
};

MODULE_DEVICE_TABLE(i2c, lm36274_id);
static struct i2c_driver lm36274_i2c_driver = {
		.driver = {
			.name = "lm36274",
			.owner = THIS_MODULE,
			.of_match_table = lm36274_of_id_table,
		},
		.probe = lm36274_probe,
		.remove = lm36274_remove,
		.id_table = lm36274_id,
};

static int __init lm36274_module_init(void)
{
	int ret = -1;

	LM36274_INFO("in!\n");

	lm36274_class = class_create(THIS_MODULE, "lm36274");
	if (IS_ERR(lm36274_class)) {
		LM36274_ERR("Unable to create lm36274 class; errno = %ld\n", PTR_ERR(lm36274_class));
		lm36274_class = NULL;
	}

	ret = i2c_add_driver(&lm36274_i2c_driver);
	if (ret)
		LM36274_ERR("Unable to register lm36274 driver\n");

	LM36274_INFO("ok!\n");

	return ret;
}
late_initcall(lm36274_module_init);

MODULE_DESCRIPTION("Texas Instruments Backlight driver for LM36274");
MODULE_AUTHOR("Daniel Jeong <daniel.jeong@ti.com>");
MODULE_AUTHOR("G.Shark Jeong <gshark.jeong@gmail.com>");
MODULE_LICENSE("GPL v2");
