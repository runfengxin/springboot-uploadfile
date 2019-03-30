package com.example.fileuploaddemo.common;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class HttpResult {
    /**
     * 结果信息
     */
    private String msg;

    /**
     * 状态码
     */
    private String code;

    /**
     * 返回数据对象
     */
    private Object data;
}
