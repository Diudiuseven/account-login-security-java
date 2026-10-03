package com.github.diudiuseven.accountloginsecurityjava.security;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.springframework.stereotype.Component;

/**
 * 安全审计：记录敏感操作与越权尝试，便于追溯。
 * 事件内容绝不包含口令或摘要；容量有界，写路径无锁不拖垮吞吐。
 */
@Component
public class AuditLog {

    private static final int MAX_EVENTS = 10_000;

    public record Event(long timestamp, String action, String actor,
                        String target, String outcome, String detail) {
    }

    private final CopyOnWriteArrayList<Event> events = new CopyOnWriteArrayList<>();

    public void record(String action, String actor, String target,
                       String outcome, String detail) {
        events.add(new Event(System.currentTimeMillis(), action, actor, target, outcome, detail));
        if (events.size() > MAX_EVENTS) {
            // 超出容量时丢弃最旧的一半，保持有界
            events.subList(0, MAX_EVENTS / 2).clear();
        }
    }

    public List<Event> events() {
        return List.copyOf(events);
    }

    public List<Event> eventsByAction(String action) {
        List<Event> out = new ArrayList<>();
        for (Event e : events) {
            if (e.action().equals(action)) {
                out.add(e);
            }
        }
        return out;
    }
}
