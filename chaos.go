package main

import (
	"fmt"
	"path/filepath"
	"sync"
)

// Barrier 可重用屏障:两个线程必须同时到达后才能各自继续。
type Barrier struct {
	mu    sync.Mutex
	cond  *sync.Cond
	count int
	n     int
	gen   int
}

func NewBarrier(n int) *Barrier {
	b := &Barrier{n: n}
	b.cond = sync.NewCond(&b.mu)
	return b
}

func (b *Barrier) Await() {
	b.mu.Lock()
	b.count++
	if b.count == b.n {
		b.count = 0
		b.gen++
		b.cond.Broadcast()
	} else {
		g := b.gen
		for g == b.gen {
			b.cond.Wait()
		}
	}
	b.mu.Unlock()
}

// ChaosResult 一个并发故障场景的结论。
type ChaosResult struct {
	Name     string `json:"name"`
	Expect   string `json:"expect"`
	Observed string `json:"observed"`
	Pass     bool   `json:"pass"`
	Proof    Proof  `json:"proof"`
}

// RunChaos 依次制造三类故障,每类都在独立落盘目录中运行并重放恢复。
func RunChaos(base string) []ChaosResult {
	return []ChaosResult{
		chaosRevokeBeforeCommit(filepath.Join(base, "chaos", "s1-revoke-first")),
		chaosLostReceipt(filepath.Join(base, "chaos", "s2-lost-receipt")),
		chaosDigestConflict(filepath.Join(base, "chaos", "s3-digest-conflict")),
	}
}

// S1 撤销先提交:撤销先落盘,随后旧签核代的承诺必须被拒绝;
// 即使竞态写入方强行补写承诺与回执,恢复重放也不得误收旧包。
func chaosRevokeBeforeCommit(dir string) ChaosResult {
	res := ChaosResult{
		Name:   "s1-revoke-before-commit",
		Expect: "撤销先提交后,旧签核代承诺被拒;强写承诺+回执的包恢复后仍不通过",
	}
	st := NewStore(dir)
	rootD := NewRoot("root-D", "chaos-s1")
	if err := st.WriteRoot(rootD); err != nil {
		res.Observed = err.Error()
		return res
	}
	rev := makeReviewer("rev-D1", signLink(rootD.Priv, rootD.ID, "rev-D1", mustHexPubOf("rev-D1")))
	if err := st.WriteReviewer(rev); err != nil {
		res.Observed = err.Error()
		return res
	}
	digest, err := st.WriteEvidence("PKG-C1", []byte("stale payload PKG-C1\n"))
	if err != nil {
		res.Observed = err.Error()
		return res
	}
	// 撤销生效前签发的旧封签(签核代 2)。
	seal, err := makeSeal(st, rev, "seal-C1-old", "PKG-C1", "CASE-C1", digest, 2)
	if err != nil {
		res.Observed = err.Error()
		return res
	}
	if err := st.AppendSeal(seal); err != nil {
		res.Observed = err.Error()
		return res
	}

	bar := NewBarrier(2)
	revoked := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	var commitErr error
	go func() { // 撤销线程
		defer wg.Done()
		bar.Await()
		if err := st.AppendRevocation(rootD, 2, "root-D key compromised at gen 2"); err != nil {
			commitErr = err
		}
		close(revoked) // 保证撤销严格先于承诺
	}()
	go func() { // 承诺线程
		defer wg.Done()
		bar.Await()
		<-revoked
		commitErr = st.TryCommit("PKG-C1", []string{"seal-C1-old"})
	}()
	wg.Wait()
	if commitErr == nil {
		res.Observed = "commit unexpectedly succeeded after revocation"
		return res
	}
	// 竞态写入方绕过校验强写承诺与回执,模拟崩溃前的脏写。
	if err := st.ForceCommit("PKG-C1", digest, []string{"seal-C1-old"}); err != nil {
		res.Observed = err.Error()
		return res
	}
	if err := st.ForceReceipt("PKG-C1", digest); err != nil {
		res.Observed = err.Error()
		return res
	}
	// 恢复:只从落盘目录重放。
	state, err := Replay(dir)
	if err != nil {
		res.Observed = err.Error()
		return res
	}
	d := Decide(state, "PKG-C1")
	res.Proof = d.Proof
	if d.Pass {
		res.Observed = "recovered state wrongly accepted the stale package"
		return res
	}
	res.Pass = true
	res.Observed = fmt.Sprintf("commit rejected (%v); replay after forced commit+receipt still rejects: rule=%s",
		commitErr, d.Rule)
	return res
}

// S2 承诺后回执丢失:承诺落盘、回执未写即崩溃;恢复后包不得生效,
// 迟到的回执也必须按恢复时的撤销状态重新校验而被拒。
func chaosLostReceipt(dir string) ChaosResult {
	res := ChaosResult{
		Name:   "s2-lost-receipt",
		Expect: "承诺后回执丢失→恢复后不生效;迟到回执落在撤销之后→重放仍否决",
	}
	st := NewStore(dir)
	rootE := NewRoot("root-E", "chaos-s2")
	if err := st.WriteRoot(rootE); err != nil {
		res.Observed = err.Error()
		return res
	}
	rv1 := makeReviewer("rev-E1", signLink(rootE.Priv, rootE.ID, "rev-E1", mustHexPubOf("rev-E1")))
	rv2 := makeReviewer("rev-E2", signLink(rootE.Priv, rootE.ID, "rev-E2", mustHexPubOf("rev-E2")))
	for _, rv := range []Reviewer{rv1, rv2} {
		if err := st.WriteReviewer(rv); err != nil {
			res.Observed = err.Error()
			return res
		}
	}
	digest, err := st.WriteEvidence("PKG-C2", []byte("payload PKG-C2\n"))
	if err != nil {
		res.Observed = err.Error()
		return res
	}
	var ids []string
	for i, rv := range []Reviewer{rv1, rv2} {
		s, err := makeSeal(st, rv, fmt.Sprintf("seal-C2-%d", i+1), "PKG-C2", "CASE-C2", digest, 1)
		if err != nil {
			res.Observed = err.Error()
			return res
		}
		if err := st.AppendSeal(s); err != nil {
			res.Observed = err.Error()
			return res
		}
		ids = append(ids, s.SealID)
	}
	bar := NewBarrier(2)
	var wg sync.WaitGroup
	wg.Add(2)
	var commitErr error
	go func() { // 承诺线程:承诺落盘后"崩溃",回执永远丢失
		defer wg.Done()
		commitErr = st.TryCommit("PKG-C2", ids)
		bar.Await() // 崩溃点:不回写回执
	}()
	go func() { // 撤销线程:在对方崩溃窗口内撤销签核代 1
		defer wg.Done()
		bar.Await()
		_ = st.AppendRevocation(rootE, 1, "root-E retired gen 1 during crash window")
	}()
	wg.Wait()
	if commitErr != nil {
		res.Observed = "commit failed unexpectedly: " + commitErr.Error()
		return res
	}
	// 第一次恢复:承诺在、回执丢失。
	state, err := Replay(dir)
	if err != nil {
		res.Observed = err.Error()
		return res
	}
	d1 := Decide(state, "PKG-C2")
	if d1.Pass || d1.Rule != "receipt-missing" {
		res.Observed = fmt.Sprintf("after crash: pass=%v rule=%s, want pass=false rule=receipt-missing", d1.Pass, d1.Rule)
		return res
	}
	// 迟到回执:正常路径必须拒(封签已撤销);强写后重放也必须拒。
	lateErr := st.WriteReceipt("PKG-C2")
	if lateErr == nil {
		res.Observed = "late receipt unexpectedly accepted after revocation"
		return res
	}
	if err := st.ForceReceipt("PKG-C2", digest); err != nil {
		res.Observed = err.Error()
		return res
	}
	state2, err := Replay(dir)
	if err != nil {
		res.Observed = err.Error()
		return res
	}
	d2 := Decide(state2, "PKG-C2")
	res.Proof = d2.Proof
	if d2.Pass {
		res.Observed = "recovered state wrongly accepted package via late forced receipt"
		return res
	}
	res.Pass = true
	res.Observed = fmt.Sprintf("crash recovery: rule=%s; late receipt rejected (%v); forced receipt replay: rule=%s",
		d1.Rule, lateErr, d2.Rule)
	return res
}

// S3 同编号摘要冲突:两个线程对同一包编号承诺不同摘要;
// 恢复重放必须识别冲突并整体否决,不得任选其一。
func chaosDigestConflict(dir string) ChaosResult {
	res := ChaosResult{
		Name:   "s3-same-number-digest-conflict",
		Expect: "同编号两份承诺摘要冲突,恢复后整体否决",
	}
	st := NewStore(dir)
	rootF := NewRoot("root-F", "chaos-s3")
	if err := st.WriteRoot(rootF); err != nil {
		res.Observed = err.Error()
		return res
	}
	digestA, err := st.WriteEvidence("PKG-C3", []byte("payload A for PKG-C3\n"))
	if err != nil {
		res.Observed = err.Error()
		return res
	}
	digestB := sha256HexOf("payload B for PKG-C3 (never landed)")
	bar := NewBarrier(2)
	var wg sync.WaitGroup
	wg.Add(2)
	errs := make([]error, 2)
	go func() { defer wg.Done(); bar.Await(); errs[0] = st.ForceCommit("PKG-C3", digestA, nil) }()
	go func() { defer wg.Done(); bar.Await(); errs[1] = st.ForceCommit("PKG-C3", digestB, nil) }()
	wg.Wait()
	for _, e := range errs {
		if e != nil {
			res.Observed = e.Error()
			return res
		}
	}
	// 再补一份回执,模拟其中一方试图完成两阶段。
	if err := st.ForceReceipt("PKG-C3", digestA); err != nil {
		res.Observed = err.Error()
		return res
	}
	state, err := Replay(dir)
	if err != nil {
		res.Observed = err.Error()
		return res
	}
	d := Decide(state, "PKG-C3")
	res.Proof = d.Proof
	if d.Pass || d.Rule != "digest-conflict" {
		res.Observed = fmt.Sprintf("pass=%v rule=%s, want pass=false rule=digest-conflict", d.Pass, d.Rule)
		return res
	}
	res.Pass = true
	res.Observed = fmt.Sprintf("two conflicting commits on PKG-C3 detected; replay rejects: rule=%s", d.Rule)
	return res
}

func sha256HexOf(s string) string { return sha256Hex([]byte(s)) }
