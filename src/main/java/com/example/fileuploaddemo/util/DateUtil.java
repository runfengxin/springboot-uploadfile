package com.example.fileuploaddemo.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;

/**
 * 日期工具类
 * 
 * @author dengjianjun
 *
 */
public class DateUtil {

	private final static Logger logger = LoggerFactory.getLogger(DateUtil.class);

	private static long dayStartTime = -1;
	private static long dayEndTime = -1;
	private static int day = -1;
	private static String dayStr = null;
	private static Date dayDate = null;
	private static Date dayDateEnd = null;

	/**
	 * 格式化日期
	 * 
	 * @param date
	 * @param pattern
	 * @return
	 */
	public static String format(Date date, String pattern) {
		DateFormat format = new SimpleDateFormat(pattern);
		return format.format(date);
	}

	/**
	 * 格式化当前日期
	 * 
	 * @param pattern
	 * @return
	 */
	public static String formatNow(String pattern) {
		DateFormat format = new SimpleDateFormat(pattern);
		return format.format(new Date());
	}

	/**
	 * 获取今日天数
	 * 
	 * @return
	 */
	public static String getTodayStr() {
		long time = System.currentTimeMillis();
		if (day > 0 && time > dayStartTime && time < dayEndTime) {
			return dayStr;
		}
		resetDate();
		return dayStr;
	}

	/**
	 * 获取今日日期
	 * 
	 * @return
	 */
	public static Date getTodayDate() {
		long time = System.currentTimeMillis();

		if (day > 0 && time > dayStartTime && time < dayEndTime) {
			return dayDate;
		}

		resetDate();
		return dayDate;
	}

	/**
	 * 获取今日日期
	 * 
	 * @return
	 */
	public static Date getTodayDateEnd() {
		long time = System.currentTimeMillis();

		if (day > 0 && time > dayStartTime && time < dayEndTime) {
			return dayDateEnd;
		}

		resetDate();
		return dayDateEnd;
	}

	/**
	 * 获取今日天数
	 * 
	 * @return
	 */
	public static int getTodayDay() {
		long time = System.currentTimeMillis();

		if (day > 0 && time > dayStartTime && time < dayEndTime) {
			return day;
		}

		resetDate();
		return day;
	}

	/**
	 * 查询时间是否在今日
	 * 
	 * @param time
	 * @return
	 */
	public static boolean isToday(long time) {
		if (System.currentTimeMillis() > dayEndTime) {
			resetDate();
		}

		return time > dayStartTime && time < dayEndTime;
	}

	/**
	 * 查询时间是否在今日
	 * 
	 * @param time
	 * @return
	 */
	public static boolean isToday(Date time) {
		if (time == null) {
			return false;
		}

		return isToday(time.getTime());
	}

	private static synchronized void resetDate() {
		Calendar cal = Calendar.getInstance();

		day = cal.get(Calendar.DAY_OF_YEAR);

		cal.set(Calendar.HOUR_OF_DAY, 0);
		cal.set(Calendar.MINUTE, 0);
		cal.set(Calendar.SECOND, 0);
		cal.set(Calendar.MILLISECOND, 0);
		dayStartTime = cal.getTimeInMillis();

		dayDate = cal.getTime();

		dayStr = new SimpleDateFormat("yyyyMMdd").format(dayDate);

		cal.set(Calendar.HOUR_OF_DAY, 23);
		cal.set(Calendar.MINUTE, 59);
		cal.set(Calendar.SECOND, 59);
		cal.set(Calendar.MILLISECOND, 999);
		dayEndTime = cal.getTimeInMillis();

		dayDateEnd = cal.getTime();

		logger.info("重置今日时间：{}", dayStr);
	}

}
