package com.github.diudiuseven.accountloginsecurityjava.model;

/** 同一账号多端会话策略。 */
public enum SessionStrategy {
    /** 多端并存，新登录不影响旧会话。 */
    MULTI,
    /** 互相顶替：新登录吊销旧会话。 */
    KICK_OUT
}
