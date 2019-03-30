package com.example.fileuploaddemo.common;

/**
 * @author xin.rf
 * @date 2018/11/12 15:07
 * @Description TODO
 **/
public enum ErrorEnum {
    /**
     * 异常错误枚举类
     */
    PHONE_NOT_REG(1000,"手机号尚未注册"),
    EXCEPTION_REQ(1001,"请求异常"),
    LACK_REQ_PARAM(1002,"缺少必填参数"),
    USERNAME_PASSWORD_ERROR(1003,"手机号或密码错误"),
    PHONE_HAS_REGISTER(1004,"手机号已被注册！"),
    EMAIL_CODE_HAS_OVERDUE(1005,"验证码无效或已过期！"),
    EMAIL_CODE_ERROR(1006,"验证码错误！"),
    UPDATE_ERROR(1007,"修改失败！"),
    EMAIL_CODE_HAS_SEND(1008,"验证码已发送，请勿重新提交！"),
    USER_HAS_NOT_ACTIVE(1009,"用户未激活！"),
    PASSWORD_ERROR_MORE_THAN_FIVE(1010,"密码输入错误超过五次，请1分钟后重试！"),
    DATA_IS_NULL(1011,"数据为空！"),
    DELETE_FAIL(1012,"删除失败"),
    FILE_IS_NULL(1013,"上传文件不得为空"),
    FILE_FAIL(1014,"上传失败,请重新上传"),
    OLD_PASSWORD_ERROR(1015,"旧密码错误"),
    LOGIN_STATUS_IS_INVALID(1016,"登录状态已失效，请重新登录"),
    FORMAT_CONVERT_FAIL(1017,"格式转换失败"),
    SUPPLIER_SCHOOL_NOT_BING(1018,"当前供应商未绑定任何学校"),
    SCHOOL_NOT_EXIST(1019,"不存在该学校"),
    FILE_IS_TOO_LARGE(1020,"上传文件过大，请压缩后上传"),
    STU_NUM_ERROR(1021,"学号格式错误"),
    STU_NUM_EXIST_ALREADY(1022,"学号已存在，请重新填写"),
    NETWORK_ERROR(1023,"网络错误，请检查网络"),
    CANTEEN_FOOD_NOT_SELECT(1024,"请至少选择一件餐品"),
    SUPPLIER_TIME_OVERDUE(1025,"部分商品当前时间超过供应时间，请重新编辑上架"),
    PAY_PASSWORD_ERROR(1026,"支付密码错误"),
    ADMIN_LOGIN_ERROR(1027,"用户名或密码错误"),
    ILLEGAL_REQUEST(1028,"非法请求"),
    PAY_PRICE_ERROT(1029,"支付金额不符"),
    FILE_NOT_FOUND(1030,"找不到文件")
    



    ;

    private Integer key;

    private String msg;

    ErrorEnum(Integer key, String msg) {
        this.key = key;
        this.msg = msg;
    }

    public Integer getKey() {
        return key;
    }

    public String getMsg() {
        return msg;
    }
}
