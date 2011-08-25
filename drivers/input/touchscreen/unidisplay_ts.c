#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/pm.h>
#include <linux/i2c.h>
#include <linux/platform_device.h>
#include <linux/interrupt.h>
#include <linux/input.h>
#include <linux/clk.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/gpio.h>

#include <mach/regs-gpio.h>

#include <plat/gpio-cfg.h>

/* 20 ms */
#define TOUCH_READ_TIME		msecs_to_jiffies(20)

#define TOUCH_INT_PIN		EXYNOS4_GPX3(1)
#define TOUCH_INT_PIN_SHIFT	1
#define TOUCH_RST_PIN		EXYNOS4_GPE3(5)

#define TOUCHSCREEN_MINX	0
#define TOUCHSCREEN_MAXX	3968
#define TOUCHSCREEN_MINY	0
#define TOUCHSCREEN_MAXY	2304
#define TOUCH_DEBUG
#ifdef TOUCH_DEBUG
#define DEBUG_PRINT(fmt, args...) printk(fmt, ##args)
#else
#define DEBUG_PRINT(fmt, args...)
#endif

#define	INPUT_REPORT(x, y, p, val1, val2)	\
		{ \
		input_report_abs(tsdata->input, ABS_MT_POSITION_X, x); \
		input_report_abs(tsdata->input, ABS_MT_POSITION_Y, y); \
		input_report_abs(tsdata->input, ABS_MT_TOUCH_MAJOR, p); \
		input_report_abs(tsdata->input, ABS_PRESSURE, val1); \
		input_report_key(tsdata->input, BTN_TOUCH, val2); \
		input_mt_sync(tsdata->input); \
		}

struct unidisplay_ts_data {
	struct i2c_client *client;
	struct input_dev *input;
	struct task_struct *kidle_task;
	wait_queue_head_t idle_wait;
	struct delayed_work work;
	int irq;
	unsigned int irq_pending;
};


static irqreturn_t unidisplay_ts_isr(int irq, void *dev_id);

static void unidisplay_ts_config(void)
{
	s3c_gpio_cfgpin(TOUCH_INT_PIN, S3C_GPIO_SFN(0x0F));
	s3c_gpio_setpull(TOUCH_INT_PIN, S3C_GPIO_PULL_UP);

	if (gpio_request(TOUCH_INT_PIN, "TOUCH_INT_PIN")) {
		pr_err("%s : gpio request failed.\n", __func__);
		return;
	}
	gpio_direction_input(TOUCH_INT_PIN);
	gpio_free(TOUCH_INT_PIN);

	s3c_gpio_setpull(TOUCH_RST_PIN, S3C_GPIO_PULL_NONE);
	s3c_gpio_cfgpin(TOUCH_RST_PIN, S3C_GPIO_OUTPUT);

	if (gpio_request(TOUCH_RST_PIN, "TOUCH_RST_PIN")) {
		pr_err("%s : gpio request failed.\n", __func__);
		return;
	}
	gpio_direction_output(TOUCH_RST_PIN, 1);
	gpio_free(TOUCH_RST_PIN);
}

static void unidisplay_ts_start(void)
{
	if (gpio_request(TOUCH_RST_PIN, "TOUCH_RST_PIN")) {
		pr_err("%s : gpio request failed.\n", __func__);
		return;
	}
	gpio_set_value(TOUCH_RST_PIN, 0);
	gpio_free(TOUCH_RST_PIN);
}

static void unidisplay_ts_stop(void)
{
	if (gpio_request(TOUCH_RST_PIN, "TOUCH_RST_PIN")) {
		pr_err("%s : gpio request failed.\n", __func__);
		return;
	}
	gpio_set_value(TOUCH_RST_PIN, 1);
	gpio_free(TOUCH_RST_PIN);
}

static void unidisplay_ts_reset(void)
{
	unidisplay_ts_stop();
	udelay(100);
	unidisplay_ts_start();
}

static int unidisplay_ts_pen_up(void)
{
	return (gpio_get_value(TOUCH_INT_PIN) & 0x1);
}

static irqreturn_t unidisplay_ts_isr(int irq, void *dev_id)
{
	struct unidisplay_ts_data *tsdata = dev_id;
	if (irq == tsdata->irq) {
		disable_irq_nosync(tsdata->irq);
		tsdata->irq_pending = 1;
		wake_up(&tsdata->idle_wait);
		return IRQ_HANDLED;
	}
	return IRQ_NONE;
}

static int unidisplay_ts_thread(void *kthread)
{
	struct unidisplay_ts_data *tsdata = kthread;
	struct task_struct *tsk = current;
	int ret = 0;
	struct sched_param param = { .sched_priority = 1 };
	sched_setscheduler(tsk, SCHED_FIFO, &param);
	set_freezable();
	while (!kthread_should_stop()) {
			int x1 = 0, y1 = 0;
			u8 buf[9];
			u8 type = 0;
			unsigned int pendown = 0;
			long timeout = 0;
			if (tsdata->irq_pending) {
				tsdata->irq_pending = 0;
				enable_irq(tsdata->irq);
			}
			pendown = !unidisplay_ts_pen_up();
			if (pendown) {
				u8 addr = 0x10;
				memset(buf, 0, sizeof(buf));
				ret = i2c_master_send(tsdata->client, &addr, 1);
				if (ret != 1) {
					dev_err(&tsdata->client->dev,\
					"Unable to write to i2c touchscreen\n");
					ret = -EIO;
					timeout = MAX_SCHEDULE_TIMEOUT;
					goto wait_event;
				}
				ret = i2c_master_recv(tsdata->client, buf, 9);
				if (ret != 9) {
					dev_err(&tsdata->client->dev,\
					"Unable to read to i2c touchscreen!\n");
					ret = -EIO;
					timeout = MAX_SCHEDULE_TIMEOUT;
					goto wait_event;
				}
				/* mark everything ok now */
				ret = 0;
				type = buf[0];
				if (type & 0x1) {
					x1 = buf[2];
					x1 <<= 8;
					x1 |= buf[1];
					y1 = buf[4];
					y1 <<= 8;
					y1 |= buf[3];
					INPUT_REPORT(x1, y1, 1, 255, 1);
				}
				if (type & 0x2) {
					x1 = buf[6];
					x1 <<= 8;
					x1 |= buf[5];
					y1 = buf[8];
					y1 <<= 8;
					y1 |= buf[7];
					INPUT_REPORT(x1, y1, 2, 255, 1);
				}
				input_sync(tsdata->input);
				timeout = msecs_to_jiffies(20);
			} else {
				INPUT_REPORT(0, 0, 0, 0 ,0);
				INPUT_REPORT(0, 0, 0, 0, 0);
				input_sync(tsdata->input);
				timeout = MAX_SCHEDULE_TIMEOUT;
			}
wait_event:
			wait_event_freezable_timeout(tsdata->idle_wait, \
				tsdata->irq_pending || kthread_should_stop(), \
				timeout);
	}
	return ret;
}

static int unidisplay_ts_open(struct input_dev *dev)
{
	struct unidisplay_ts_data *tsdata = input_get_drvdata(dev);
	int ret = 0;
	u8 addr = 0x10;
	BUG_ON(tsdata->kidle_task);

	ret = i2c_master_send(tsdata->client, &addr, 1);

	if (ret != 1) {
		dev_err(&tsdata->client->dev, "Unable to open touchscreen device\n");
		return -ENODEV;
	}

	tsdata->kidle_task = kthread_run(unidisplay_ts_thread, tsdata, \
					 "unidisplay_ts");
	if (IS_ERR(tsdata->kidle_task)) {
		ret = PTR_ERR(tsdata->kidle_task);
		tsdata->kidle_task = NULL;
		return ret;
	}
	enable_irq(tsdata->irq);

	return 0;
}

static void unidisplay_ts_close(struct input_dev *dev)
{
	struct unidisplay_ts_data *tsdata = input_get_drvdata(dev);

	if (tsdata->kidle_task) {
		kthread_stop(tsdata->kidle_task);
		tsdata->kidle_task = NULL;
	}

	disable_irq(tsdata->irq);
}

static int unidisplay_ts_probe(struct i2c_client *client,
				const struct i2c_device_id *id)
{
	struct unidisplay_ts_data *tsdata;
	int err;

	unidisplay_ts_config();
	unidisplay_ts_reset();

	if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
		dev_err(&client->dev, "i2c func not supported\n");
		err = -EIO;
		goto end;
	}

	tsdata = kzalloc(sizeof(*tsdata), GFP_KERNEL);
	if (!tsdata) {
		dev_err(&client->dev, "failed to allocate driver data!\n");
		err = -ENOMEM;
		goto fail1;
	}

	dev_set_drvdata(&client->dev, tsdata);

	tsdata->input = input_allocate_device();
	if (!tsdata->input) {
		dev_err(&client->dev, "failed to allocate input device!\n");
		err = -ENOMEM;
		goto fail2;
	}

	tsdata->input->evbit[0] = BIT_MASK(EV_SYN) | BIT_MASK(EV_KEY) |\
		BIT_MASK(EV_ABS);
	set_bit(EV_SYN, tsdata->input->evbit);
	set_bit(EV_KEY, tsdata->input->evbit);
	set_bit(EV_ABS, tsdata->input->evbit);

	tsdata->input->keybit[BIT_WORD(BTN_TOUCH)] = BIT_MASK(BTN_TOUCH);

	set_bit(0, tsdata->input->absbit);
	set_bit(1, tsdata->input->absbit);
	set_bit(2, tsdata->input->absbit);

	input_set_abs_params(tsdata->input, ABS_X, TOUCHSCREEN_MINX,\
						TOUCHSCREEN_MAXX, 0, 0);
	input_set_abs_params(tsdata->input, ABS_Y, TOUCHSCREEN_MINY,\
						TOUCHSCREEN_MAXY, 0, 0);
	input_set_abs_params(tsdata->input, ABS_HAT0X, TOUCHSCREEN_MINX,\
						TOUCHSCREEN_MAXX, 0, 0);
	input_set_abs_params(tsdata->input, ABS_HAT0Y, TOUCHSCREEN_MINY,\
						TOUCHSCREEN_MAXY, 0, 0);
	input_set_abs_params(tsdata->input, ABS_MT_POSITION_X,\
				TOUCHSCREEN_MINX, TOUCHSCREEN_MAXX, 0, 0);
	input_set_abs_params(tsdata->input, ABS_MT_POSITION_Y, \
				TOUCHSCREEN_MINY, TOUCHSCREEN_MAXY, 0, 0);
	input_set_abs_params(tsdata->input, ABS_MT_TOUCH_MAJOR, 0, 255, 0, 0);
	input_set_abs_params(tsdata->input, ABS_MT_WIDTH_MAJOR, 0, 25, 0, 0);

	tsdata->input->name = client->name;
	tsdata->input->id.bustype = BUS_I2C;
	tsdata->input->dev.parent = &client->dev;

	tsdata->input->open = unidisplay_ts_open;
	tsdata->input->close = unidisplay_ts_close;

	input_set_drvdata(tsdata->input, tsdata);

	tsdata->client = client;
	tsdata->irq = client->irq;

	err = input_register_device(tsdata->input);
	if (err)
		goto fail2;

	device_init_wakeup(&client->dev, 1);
	init_waitqueue_head(&tsdata->idle_wait);

	err = request_irq(tsdata->irq, unidisplay_ts_isr,\
		IRQF_TRIGGER_FALLING, client->name, tsdata);
	if (err != 0) {
		dev_err(&client->dev, "Unable to request touchscreen IRQ.\n");
		goto fail3;
	}
	/* disable irq for now, will be enabled when device is opened */
	disable_irq(tsdata->irq);
	pr_info("Unidisplay touch driver registered successfully\n");
	return err;
fail3:
	input_unregister_device(tsdata->input);
fail2:
	input_free_device(tsdata->input);
	kfree(tsdata);
fail1:
	dev_set_drvdata(&client->dev, NULL);
end:
	return err;
}


static int unidisplay_ts_remove(struct i2c_client *client)
{
	struct unidisplay_ts_data *tsdata = dev_get_drvdata(&client->dev);
	disable_irq(tsdata->irq);
	free_irq(tsdata->irq, tsdata);
	input_unregister_device(tsdata->input);
	kfree(tsdata);
	dev_set_drvdata(&client->dev, NULL);
	return 0;
}
#ifdef CONFIG_PM
static int unidisplay_ts_suspend(struct device *dev)
{
	struct unidisplay_ts_data *tsdata = dev_get_drvdata(dev);
	disable_irq(tsdata->irq);
	return 0;
}

static int unidisplay_ts_resume(struct device *dev)
{
	struct unidisplay_ts_data *tsdata = dev_get_drvdata(dev);
	enable_irq(tsdata->irq);
	return 0;
}
static const struct dev_pm_ops unidisplay_ts_pm = {
	.suspend = unidisplay_ts_suspend,
	.resume  = unidisplay_ts_resume,
};
#endif

static const struct i2c_device_id unidisplay_ts_i2c_id[] = {
	{ "unidisplay_ts", 0 },
	{ }
};
MODULE_DEVICE_TABLE(i2c, unidisplay_ts_i2c_id);

static struct i2c_driver unidisplay_ts_i2c_driver = {
	.driver = {
		.name	=	"Unidisplay Touch Driver",
		.owner	=	THIS_MODULE,
#ifdef CONFIG_PM
		.pm	=	&unidisplay_ts_pm,
#endif
	},
	.probe		=	unidisplay_ts_probe,
	.remove		=	unidisplay_ts_remove,
	.id_table	=	unidisplay_ts_i2c_id,
};

static int __init unidisplay_ts_init(void)
{
	return i2c_add_driver(&unidisplay_ts_i2c_driver);
}
module_init(unidisplay_ts_init);

static void __exit unidisplay_ts_exit(void)
{
	i2c_del_driver(&unidisplay_ts_i2c_driver);
}
module_exit(unidisplay_ts_exit);

MODULE_AUTHOR("JHKIM");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
MODULE_DESCRIPTION("unidisplay Touch-screen Driver");

