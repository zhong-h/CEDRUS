from typing import Dict, Tuple, List
from functools import lru_cache
from collections import defaultdict
import csv

q = 2**64

#tsec, hashbytes, zb = 128, 16, 8
#tsec, hashbytes, zb = 192, 24, 8
tsec, hashbytes, zb = 256, 32, 8

if tsec == 128:
    max_sign_s = 2109422*2
    max_size_s = 6304
    max_vrfy_s = 11710
    max_sign_f = 115271*2
    max_size_f = 14340
    max_vrfy_f = 4971


if tsec == 192:
    max_sign_s = 3733821*2
    max_size_s = 13384
    max_vrfy_s = 9070
    max_sign_f = 187668*2
    max_size_f = 31424
    max_vrfy_f = 7158

elif tsec == 256:
    max_sign_s = 3316446*2
    max_size_s = 25228
    max_vrfy_s = 13597
    max_sign_f = 361537*2
    max_size_f = 46212
    max_vrfy_f = 8034


def compute_mincost_ary(h,d):
    y=h%d
    if y == 0:
        h_ary = [2**int(h/d)]*d
    else:
        h1 = int(h/d)
        h2 = math.ceil(h/d)
        k = h-h1*d
        h_ary = [2**h1]*(d-k) + [2**h2]*k
    return h_ary

def compute_c_sum(w_ary, l, s):
    dp = [[0] * (s + 1) for _ in range(l + 1)]
    dp[0][0] = 1
    for i in range(1, l + 1):
        for j in range(s + 1):
            w=w_ary[i-1]
            dp[i][j] = sum(dp[i - 1][j - k] for k in range(min(w - 1, j) + 1))
    return dp[l][s]


import math


def wots_c():
    final_results = []
    two_pow_tsec = 2 ** tsec
    for zero_bit in range(zb + 1):
        diff = tsec - zero_bit
        start_l = math.ceil(diff / 8)
        end_l = diff // 2
        for l in range(start_l, end_l):
            print(zero_bit, l)
            w_ary = compute_mincost_ary(diff, l)
            sum_w = sum(w_ary)
            diff_sum_l = sum_w - l
            S_wn = diff_sum_l // 2
            vrfy_cost_wots = (diff_sum_l + 1) // 2
            sign_cost_wots = S_wn + l + two_pow_tsec / compute_c_sum(w_ary, l, S_wn)
            sign_cost_ht = sum_w + 1
            final_results.append([w_ary, zero_bit, l, sign_cost_wots, sign_cost_ht, vrfy_cost_wots])

    return final_results

def sec(h, k, t):
    lam = 2.0 ** (64 - h)

    log_denom_fts = math.lgamma(t + 1) - math.lgamma(t - k + 1)

    total_prob = 0.0

    for i in range(1, 200):
        x = min(t, k * i)

        log_poisson = -lam + i * math.log(lam) - math.lgamma(i + 1)

        log_num_fts = math.lgamma(x + 1) - math.lgamma(x - k + 1)

        log_fts = log_num_fts - log_denom_fts

        log_term = log_poisson + log_fts

        total_prob += math.exp(log_term)

    if total_prob == 0.0:
        return float('inf')

    return -math.log2(total_prob)

def compute_mincost(h,d):
    y=h%d
    if y == 0:
        h_ary = [int(h/d)]*d
    else:
        h1 = int(h/d)
        h2 = math.ceil(h/d)
        k = h-h1*d
        h_ary = [h1]*(d-k) + [h2]*k
    sum_h = 0
    for i in h_ary:
        sum_h += 2 ** i
    return sum_h

def find_t(h,k,a):
    low = k * 2 ** (a-1)
    high = k * 2 ** a
    best_t = None
    tmp_sec = None

    while low <= high:
        mid = (low + high) // 2
        tmp_sec = sec(h, k, mid)
        if tmp_sec >= tsec:
            best_t = mid
            high = mid - 1
        else:
            low = mid + 1
    return best_t, tmp_sec

@lru_cache(maxsize=None)
def comb_cached(n: int, k: int) -> int:
    if n < 0 or k < 0 or k > n:
        return 0
    return math.comb(n, k)

def comb(n: int, k: int) -> int:
    return comb_cached(n, k)

@lru_cache(maxsize=None)
def pair_terms(x: int, j: int):
    """
    Return all nonzero (s, P(x,j,s)) pairs for even x.

    x = 2n leaves grouped into n sibling pairs
    j = number of selected leaves
    s = number of fully selected sibling pairs
    """
    if x % 2 != 0 or j < 0 or j > x:
        return ()

    n = x // 2
    s_min = max(0, j - n)
    s_max = j // 2
    if s_min > s_max:
        return ()

    den = comb_cached(x, j)
    if den == 0:
        return ()

    s = s_min
    p = (
        comb_cached(n, j - s)
        * comb_cached(j - s, s)
        * (1 << (j - 2 * s))
    ) / den

    out = [(s, p)]

    for s in range(s_min, s_max):
        p *= ((j - 2 * s) * (j - 2 * s - 1)) / (
            4.0 * (s + 1) * (n - j + s + 1)
        )
        out.append((s + 1, p))

    return tuple(out)

def P(x: int, j: int, s: int) -> float:
    if x % 2 != 0 or j < 0 or s < 0 or j > x:
        return 0.0
    for ss, pp in pair_terms(x, j):
        if ss == s:
            return pp
    return 0.0

@lru_cache(maxsize=None)
def M(ell: int, L: int, R: int, kL: int, kR: int, c: int = 0) -> Dict[int, float]:
    if ell == 0:
        return {0: 1.0}

    if not (0 <= kL <= L and 0 <= kR <= R):
        return {}

    out: Dict[int, float] = defaultdict(float)

    if L % 2 == 0:
        if c == 0:
            left_terms = pair_terms(L, kL)
            right_terms = pair_terms(R, kR)

            for rL, wL in left_terms:
                for rR, wR in right_terms:
                    singles = (kL + kR) - 2 * (rL + rR)
                    nxt = M(ell - 1, L // 2, R // 2, kL - rL, kR - rR, 0)
                    w = wL * wR
                    for m_sub, p_sub in nxt.items():
                        out[singles + m_sub] += w * p_sub

        elif c == +1:
            if R < 1 or kR < 1:
                return {}

            left_terms = pair_terms(L, kL)

            if R == 1:
                for rL, wL in left_terms:
                    singles = (kL + kR) - 2 * rL
                    nxt = M(ell - 1, L // 2, 0, kL - rL, kR, +1)
                    for m_sub, p_sub in nxt.items():
                        out[singles + m_sub] += wL * p_sub
            else:
                denom = comb_cached(R - 1, kR - 1)
                if denom == 0:
                    return {}

                wY1 = comb_cached(R - 2, kR - 2) / denom
                wY0 = comb_cached(R - 2, kR - 1) / denom

                right_terms_y1 = pair_terms(R - 2, kR - 2)  # y = 1
                right_terms_y0 = pair_terms(R - 2, kR - 1)  # y = 0

                for rL, wL in left_terms:
                    if wY1:
                        for rRprime, wRprime in right_terms_y1:
                            rR = 1 + rRprime
                            singles = (kL + kR) - 2 * (rL + rR)
                            nxt = M(ell - 1, L // 2, R // 2, kL - rL, kR - rR, +1)
                            w = wL * wY1 * wRprime
                            for m_sub, p_sub in nxt.items():
                                out[singles + m_sub] += w * p_sub

                    if wY0:
                        for rRprime, wRprime in right_terms_y0:
                            rR = rRprime
                            singles = (kL + kR) - 2 * (rL + rR)
                            nxt = M(ell - 1, L // 2, R // 2, kL - rL, kR - rR, +1)
                            w = wL * wY0 * wRprime
                            for m_sub, p_sub in nxt.items():
                                out[singles + m_sub] += w * p_sub

        else:  # c == -1
            left_terms = pair_terms(L, kL)

            if R == 0:
                if kR != 0:
                    return {}
                for rL, wL in left_terms:
                    singles = kL - 2 * rL
                    nxt = M(ell - 1, L // 2, 0, kL - rL, 0, -1)
                    for m_sub, p_sub in nxt.items():
                        out[singles + m_sub] += wL * p_sub

            elif R == 1:
                if kR != 0:
                    return {}
                for rL, wL in left_terms:
                    singles = kL - 2 * rL
                    nxt = M(ell - 1, L // 2, 0, kL - rL, 0, -1)
                    for m_sub, p_sub in nxt.items():
                        out[singles + m_sub] += wL * p_sub

            else:
                denom = comb_cached(R - 1, kR)
                if denom == 0:
                    return {}

                wZ0 = comb_cached(R - 2, kR) / denom
                wZ1 = comb_cached(R - 2, kR - 1) / denom

                right_terms_z0 = pair_terms(R - 2, kR)      # z = 0
                right_terms_z1 = pair_terms(R - 2, kR - 1)  # z = 1

                for rL, wL in left_terms:
                    if wZ0:
                        for rRprime, wRprime in right_terms_z0:
                            singles = (kL + kR) - 2 * (rL + rRprime)
                            nxt = M(ell - 1, L // 2, R // 2, kL - rL, kR - rRprime, -1)
                            w = wL * wZ0 * wRprime
                            for m_sub, p_sub in nxt.items():
                                out[singles + m_sub] += w * p_sub

                    if wZ1:
                        for rRprime, wRprime in right_terms_z1:
                            singles = (kL + kR) - 2 * (rL + rRprime)
                            nxt = M(ell - 1, L // 2, R // 2, kL - rL, kR - rRprime, +1)
                            w = wL * wZ1 * wRprime
                            for m_sub, p_sub in nxt.items():
                                out[singles + m_sub] += w * p_sub

    else:
        denomL = comb_cached(L, kL)
        if denomL == 0:
            return {}

        if c == 0:
            denomR = comb_cached(R, kR)
            if denomR == 0:
                return {}

            for xL in (0, 1):
                w_xL = comb_cached(L - 1, kL - xL) / denomL if 0 <= kL - xL <= L - 1 else 0.0
                if w_xL == 0.0:
                    continue

                for xR in (0, 1):
                    w_xR = comb_cached(R - 1, kR - xR) / denomR if 0 <= kR - xR <= R - 1 else 0.0
                    if w_xR == 0.0:
                        continue

                    kL_in = kL - xL
                    kR_in = kR - xR
                    boundary_merge = xL * xR

                    left_terms = pair_terms(L - 1, kL_in)
                    right_terms = pair_terms(R - 1, kR_in)

                    for rL, wL in left_terms:
                        for rR, wR in right_terms:
                            singles = (kL + kR) - 2 * (rL + rR + boundary_merge)
                            kL_next = kL - xL - rL
                            kR_next = kR - xR - rR + (xL + xR - boundary_merge)
                            L_next = (L - 1) // 2
                            R_next = (R - 1) // 2 + 1
                            c_next = +1 if (xL + xR) >= 1 else -1
                            nxt = M(ell - 1, L_next, R_next, kL_next, kR_next, c_next)
                            w = w_xL * w_xR * wL * wR
                            for m_sub, p_sub in nxt.items():
                                out[singles + m_sub] += w * p_sub

        elif c == +1:
            if R < 1 or kR < 1:
                return {}

            right_terms = pair_terms(R - 1, kR - 1)

            for xL in (0, 1):
                w_xL = comb_cached(L - 1, kL - xL) / denomL if 0 <= kL - xL <= L - 1 else 0.0
                if w_xL == 0.0:
                    continue

                kL_in = kL - xL
                boundary_merge = xL
                left_terms = pair_terms(L - 1, kL_in)

                for rL, wL in left_terms:
                    for rR, wR in right_terms:
                        singles = (kL + kR) - 2 * (rL + rR + boundary_merge)
                        kL_next = kL - xL - rL
                        kR_next = kR - rR
                        L_next = (L - 1) // 2
                        R_next = (R - 1) // 2 + 1
                        nxt = M(ell - 1, L_next, R_next, kL_next, kR_next, +1)
                        w = w_xL * wL * wR
                        for m_sub, p_sub in nxt.items():
                            out[singles + m_sub] += w * p_sub

        else:  # c == -1
            if R < 1:
                return {}

            right_terms = pair_terms(R - 1, kR)

            for xL in (0, 1):
                w_xL = comb_cached(L - 1, kL - xL) / denomL if 0 <= kL - xL <= L - 1 else 0.0
                if w_xL == 0.0:
                    continue

                kL_in = kL - xL
                left_terms = pair_terms(L - 1, kL_in)

                for rL, wL in left_terms:
                    for rR, wR in right_terms:
                        singles = (kL + kR) - 2 * (rL + rR)
                        kL_next = kL - xL - rL
                        kR_next = kR - rR + xL
                        L_next = (L - 1) // 2
                        R_next = (R - 1) // 2 + 1
                        c_next = +1 if xL == 1 else -1
                        nxt = M(ell - 1, L_next, R_next, kL_next, kR_next, c_next)
                        w = w_xL * wL * wR
                        for m_sub, p_sub in nxt.items():
                            out[singles + m_sub] += w * p_sub

    return dict(out)

def pmf_leftfilled(t: int, k: int) -> Dict[int, float]:
    if not (1 <= k <= t):
        return {}

    h = (t - 1).bit_length()
    p = 1 << (h - 1) if h > 0 else 1
    L = t - p
    x = 2 * L

    pmf: Dict[int, float] = defaultdict(float)

    denom = comb_cached(t, k)
    if denom == 0:
        return {}

    j_lo = max(0, k - (t - x))
    j_hi = min(k, x)

    for j in range(j_lo, j_hi + 1):
        left_num = comb_cached(x, j)
        right_num = comb_cached(t - x, k - j)
        if left_num == 0 or right_num == 0:
            continue

        wj = (left_num * right_num) / denom

        for s, ws in pair_terms(x, j):
            singles_bottom = j - 2 * s

            upper = M(
                max(h - 1, 0),
                L if h > 0 else 0,
                (p - L) if h > 0 else 0,
                j - s,
                k - j,
                0,
            )

            w = wj * ws
            for m_up, p_up in upper.items():
                pmf[singles_bottom + m_up] += w * p_up

    return dict(pmf)

def interleave_cost_table(t, k):
    pmf = pmf_leftfilled(t, k)
    if not pmf:
        return []

    run = 0.0
    M_max = max(pmf)
    table: List[Tuple[int, float]] = []

    for m in range(M_max + 1):
        run += pmf.get(m, 0.0)
        if run <= 0.0:
            continue
        if run > 1.0:
            run = 1.0
        table.append((m, -math.log2(run)))

    return table

def run_script():
    print("start searching wots")
    wots_list = wots_c()
    print("wots done...")
    with open("cedrus+c-fp-256.csv", mode="w", newline='') as outfile:
        writer = csv.writer(outfile)
        writer.writerow(['h', 'd', 't', 'k', 'w_ary', 'l', 'zero_bit', 'm-max', 'Size', 'sig_speed', 'vrfy_speed', 'sec'])
        for h in range(61,69):
            for k in range(2,70):
                base_vrfy_pors_fp = 2 * k
                size_part = (1 + h + k) * hashbytes
                for a in range(2,19):
                    if sec(h,k,2**a*k)>=tsec:
                        t,sec_level = find_t(h,k,a)
                        table = interleave_cost_table(t,k)
                        base_sign_pors_fp = 3 * t - 1
                        for d in range(2,h):
                            print(h,k,t,d)
                            size_counter = 4 * (d + 1)
                            sign_cost_ht = compute_mincost(h, d) - d
                            for wots in wots_list:  # wots = [w_ary,l,zero_bit,sign_speed,vrfy_speed]
                                sign_cost_wots = d * wots[3]
                                sign_cost_hypertree = sign_cost_ht * wots[4]
                                vrfy_cost_hypertree = d * wots[5] + h
                                size_hypertree = d * wots[2] * hashbytes
                                tmp = None
                                check_f_bound = True
                                for m_max, lg in reversed(table):
                                    add_work = (2.0 ** lg) - 1.0
                                    tmp_sign_hash = 1 + sign_cost_hypertree + sign_cost_wots + base_sign_pors_fp + add_work
                                    if tmp_sign_hash >= max_sign_s:
                                        if tmp is not None:
                                            add_work_best = (2.0 ** tmp[1]) - 1.0
                                            size = tmp[0] * hashbytes + size_part + size_hypertree + size_counter
                                            if size <= max_size_s:
                                                vrfy_hash = 1 + vrfy_cost_hypertree + base_vrfy_pors_fp + tmp[0]
                                                if vrfy_hash <= max_vrfy_s:
                                                    sign_hash = 1 + sign_cost_hypertree + sign_cost_wots + base_sign_pors_fp + add_work_best
                                                    writer.writerow([
                                                        h, d, t, k, wots[0], wots[2], wots[1],
                                                        tmp[0], size, int(sign_hash), int(vrfy_hash), sec_level
                                                    ])
                                        break
                                    if check_f_bound and tmp_sign_hash >= max_sign_f:
                                        if tmp is None:
                                            check_f_bound = False
                                        else:
                                            add_work_best = (2.0 ** tmp[1]) - 1.0
                                            size = tmp[0] * hashbytes + size_part + size_hypertree + size_counter
                                            if size <= max_size_f:
                                                vrfy_hash = 1 + vrfy_cost_hypertree + base_vrfy_pors_fp + tmp[0]
                                                if vrfy_hash <= max_vrfy_f:
                                                    sign_hash = 1 + sign_cost_hypertree + sign_cost_wots + base_sign_pors_fp + add_work_best
                                                    writer.writerow([
                                                        h, d, t, k, wots[0], wots[2], wots[1],
                                                        tmp[0], size, int(sign_hash), int(vrfy_hash), sec_level
                                                    ])
                                            break
                                    tmp = [m_max, lg]
                        break

run_script()
