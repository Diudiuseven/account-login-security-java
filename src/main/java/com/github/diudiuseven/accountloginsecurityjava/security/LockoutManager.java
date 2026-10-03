package com.github.diudiuseven.accountloginsecurityjava.security;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Component;

/**
 * 登录失败节流与临时锁定。按 账号 / 来源 两个维度统计，
 * 同一键上的状态变更在该键的监视器上串行化，
 * 并发失败收敛到同一个锁定结果，不会因竞态多放行。
 * 锁定到期后自动解除并清空计数。
 */
@Component
public class LockoutManager {

    /** 可序列化的锁定状态。failures 为窗口内的失败时间戳。 */
    public record LockState(List<Long> failures, long lockedUntil) {
    }

    /** 持久化快照：账号维度 + 来源维度。 */
    public record LockoutSnapshot(Map<String, LockState> byAccount,
                                  Map<String, LockState> bySource) {
    }

    /** 运行态：在某个键上 synchronized 保证计数与锁定的原子性。 */
    private static final class MutableState {
        final Deque<Long> failures = new ArrayDeque<>();
        long lockedUntil;
    }

    private final SecurityProperties properties;
    private final ConcurrentHashMap<String, MutableState> byAccount = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, MutableState> bySource = new ConcurrentHashMap<>();

    public LockoutManager(SecurityProperties properties) {
        this.properties = properties;
    }

    /**
     * 记录一次失败；若达到阈值则锁定并返回锁到期时间戳，否则返回 null。
     * 已锁定期间的失败不延长既有锁定时长（结果确定）。
     */
    public Long recordFailure(String accountId, String source) {
        long now = System.currentTimeMillis();
        Long accountLock = recordFailureOn(byAccount, accountId, now);
        Long sourceLock = recordFailureOn(bySource, source, now);
        if (accountLock == null) {
            return sourceLock;
        }
        if (sourceLock == null) {
            return accountLock;
        }
        return Math.max(accountLock, sourceLock);
    }

    private Long recordFailureOn(ConcurrentHashMap<String, MutableState> map,
                                 String key, long now) {
        MutableState state = map.computeIfAbsent(key, k -> new MutableState());
        synchronized (state) {
            if (state.lockedUntil > now) {
                return state.lockedUntil;
            }
            prune(state, now);
            state.failures.addLast(now);
            if (state.failures.size() >= properties.getMaxFailures()) {
                state.lockedUntil = now + properties.getLockDuration().toMillis();
                state.failures.clear();
                return state.lockedUntil;
            }
            return null;
        }
    }

    /** 登录成功后清空该账号与来源的计数。 */
    public void recordSuccess(String accountId, String source) {
        byAccount.remove(accountId);
        bySource.remove(source);
    }

    /** 当前是否被锁定（账号或来源任一维度锁定即视为锁定；到期自动解除并清空计数）。 */
    public boolean isLocked(String accountId, String source) {
        long now = System.currentTimeMillis();
        return isLockedOn(byAccount, accountId, now) || isLockedOn(bySource, source, now);
    }

    private boolean isLockedOn(ConcurrentHashMap<String, MutableState> map,
                               String key, long now) {
        MutableState state = map.get(key);
        if (state == null) {
            return false;
        }
        synchronized (state) {
            if (state.lockedUntil > now) {
                return true;
            }
            if (state.lockedUntil != 0) {
                // 锁已到期：自动恢复并清空计数
                state.lockedUntil = 0;
                state.failures.clear();
            }
            prune(state, now);
            return false;
        }
    }

    private void prune(MutableState state, long now) {
        long cutoff = now - properties.getFailureWindow().toMillis();
        while (!state.failures.isEmpty() && state.failures.peekFirst() < cutoff) {
            state.failures.pollFirst();
        }
    }

    /** 快照用于持久化（仅保留未到期锁定与窗口内计数）。 */
    public LockoutSnapshot snapshot() {
        long now = System.currentTimeMillis();
        return new LockoutSnapshot(snapshotOf(byAccount, now), snapshotOf(bySource, now));
    }

    private Map<String, LockState> snapshotOf(ConcurrentHashMap<String, MutableState> map, long now) {
        Map<String, LockState> out = new HashMap<>();
        map.forEach((key, state) -> {
            synchronized (state) {
                prune(state, now);
                long lockedUntil = state.lockedUntil > now ? state.lockedUntil : 0L;
                if (lockedUntil != 0 || !state.failures.isEmpty()) {
                    out.put(key, new LockState(List.copyOf(state.failures), lockedUntil));
                }
            }
        });
        return out;
    }

    /** 恢复：丢弃已到期锁定（锁定绝不超过既定到期时间）。 */
    public void restore(LockoutSnapshot snapshot) {
        if (snapshot == null) {
            return;
        }
        long now = System.currentTimeMillis();
        byAccount.clear();
        bySource.clear();
        restoreInto(byAccount, snapshot.byAccount(), now);
        restoreInto(bySource, snapshot.bySource(), now);
    }

    private void restoreInto(ConcurrentHashMap<String, MutableState> map,
                             Map<String, LockState> saved, long now) {
        if (saved == null) {
            return;
        }
        saved.forEach((key, lockState) -> {
            MutableState state = new MutableState();
            long cutoff = now - properties.getFailureWindow().toMillis();
            for (Long t : lockState.failures()) {
                if (t != null && t >= cutoff) {
                    state.failures.addLast(t);
                }
            }
            if (lockState.lockedUntil() > now) {
                state.lockedUntil = lockState.lockedUntil();
            }
            if (state.lockedUntil != 0 || !state.failures.isEmpty()) {
                map.put(key, state);
            }
        });
    }
}
