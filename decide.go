package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ---------- 封签有效性(提交路径与裁决共用) ----------

type sealInfo struct {
	Seal   Seal
	RootID string
}

// validSeals 在重放状态 st 上校验 pkgNo 的全部封签。
// 返回有效封签(按 Seq 升序)与每枚无效封签的否决原因。
func validSeals(st *State, pkgNo, digest string) (valid []sealInfo, invalid map[string]string) {
	invalid = map[string]string{}
	for _, s := range st.Seals {
		if s.PkgNo != pkgNo {
			continue
		}
		if s.EvidenceDigest != digest {
			invalid[s.SealID] = "evidence-digest-mismatch"
			continue
		}
		rf, ok := st.Reviewers[s.ReviewerID]
		if !ok {
			invalid[s.SealID] = "unknown-reviewer"
			continue
		}
		ch, err := hashFile(st.ReviewerPaths[s.ReviewerID])
		if err != nil || ch != s.ChainHash {
			invalid[s.SealID] = "chain-hash-mismatch"
			continue
		}
		rootID, err := verifyChain(st, rf)
		if err != nil {
			invalid[s.SealID] = "chain-invalid: " + err.Error()
			continue
		}
		if !ed25519.Verify(mustHex(rf.PubHex), []byte(sealPayload(s)), mustHex(s.SigHex)) {
			invalid[s.SealID] = "bad-signature"
			continue
		}
		if s.Generation <= st.Revoked[rootID] {
			invalid[s.SealID] = fmt.Sprintf("revoked-generation: seal gen %d <= revoked gen %d (root %s)",
				s.Generation, st.Revoked[rootID], rootID)
			continue
		}
		valid = append(valid, sealInfo{Seal: s, RootID: rootID})
	}
	return valid, invalid
}

func distinctReviewers(valid []sealInfo) map[string]bool {
	m := map[string]bool{}
	for _, v := range valid {
		m[v.Seal.ReviewerID] = true
	}
	return m
}

// ---------- 裁决与最短证据 ----------

type ProofFile struct {
	Path   string `json:"path"`   // 相对证据目录,正斜杠
	SHA256 string `json:"sha256"` // 文件内容哈希,可用 certutil 独立核对
}

type ProofSeal struct {
	SealID     string `json:"seal_id"`
	ReviewerID string `json:"reviewer_id"`
	RootID     string `json:"root_id"`
	Generation int    `json:"generation"`
	File       string `json:"file"`
	FileSHA256 string `json:"file_sha256"`
}

// Proof 可由独立工具核对的最短批准/否决证据。
type Proof struct {
	Statement string            `json:"statement"`
	Seals     []ProofSeal       `json:"seals,omitempty"`
	Files     []ProofFile       `json:"files,omitempty"`
	Extra     map[string]string `json:"extra,omitempty"`
}

type Decision struct {
	PkgNo string `json:"pkg_no"`
	Claim string `json:"claim"` // 包面自称,如「已审定」
	Pass  bool   `json:"pass"`
	Rule  string `json:"rule"`
	Proof Proof  `json:"proof"`
}

func rel(dir, p string) string {
	r, err := filepath.Rel(dir, p)
	if err != nil {
		return filepath.ToSlash(p)
	}
	return filepath.ToSlash(r)
}

func proofFile(dir, p string) ProofFile {
	h, err := hashFile(p)
	if err != nil {
		h = "unreadable:" + err.Error()
	}
	return ProofFile{Path: rel(dir, p), SHA256: h}
}

func proofSeal(st *State, si sealInfo) ProofSeal {
	p := st.SealFiles[si.Seal.SealID]
	h, _ := hashFile(p)
	return ProofSeal{
		SealID: si.Seal.SealID, ReviewerID: si.Seal.ReviewerID, RootID: si.RootID,
		Generation: si.Seal.Generation, File: rel(st.Dir, p), FileSHA256: h,
	}
}

// Decide 对单个证据包作出裁决,只依据重放状态。
func Decide(st *State, pkgNo string) Decision {
	d := Decision{PkgNo: pkgNo, Claim: "已审定"}
	reject := func(rule, stmt string, proof Proof) Decision {
		d.Rule, d.Pass = rule, false
		proof.Statement = stmt
		d.Proof = proof
		return d
	}
	digest, ok := st.Evidence[pkgNo]
	if !ok {
		return reject("no-evidence", "证据载荷未落盘", Proof{})
	}
	commits := st.Commits[pkgNo]
	if len(commits) == 0 {
		return reject("no-commit", "无承诺记录", Proof{})
	}
	// 同编号摘要冲突:任一承诺摘要与证据摘要不一致即整体否决。
	seen := map[string]bool{}
	conflict := false
	for _, c := range commits {
		seen[c.EvidenceDigest] = true
		if c.EvidenceDigest != digest {
			conflict = true
		}
	}
	if len(seen) > 1 || conflict {
		pf := Proof{Extra: map[string]string{"evidence_digest": digest}}
		for i, c := range commits {
			pf.Files = append(pf.Files, proofFile(st.Dir, st.CommitFiles[pkgNo][i]))
			pf.Extra[fmt.Sprintf("commit_%d_digest", c.Seq)] = c.EvidenceDigest
		}
		return reject("digest-conflict",
			fmt.Sprintf("编号 %s 存在 %d 份承诺,摘要互相冲突,全部不予承认", pkgNo, len(commits)), pf)
	}
	rec, ok := st.Receipts[pkgNo]
	if !ok {
		return reject("receipt-missing",
			"承诺已落盘但回执丢失,包不生效(承诺-回执两阶段不满足)", Proof{
				Files: []ProofFile{proofFile(st.Dir, st.CommitFiles[pkgNo][0])},
			})
	}
	if rec.EvidenceDigest != digest {
		return reject("receipt-digest-mismatch", "回执摘要与证据摘要不一致", Proof{
			Files: []ProofFile{proofFile(st.Dir, st.ReceiptFiles[pkgNo])},
		})
	}
	valid, invalid := validSeals(st, pkgNo, digest)
	if len(distinctReviewers(valid)) < 2 {
		extra := map[string]string{}
		for id, why := range invalid {
			extra[id] = why
		}
		pf := Proof{Extra: extra}
		// 若某枚封签因签核代被撤销而失效,附上对应撤销记录作为最短否决证据。
		for _, s := range st.Seals {
			if s.PkgNo != pkgNo {
				continue
			}
			if why, bad := invalid[s.SealID]; bad && strings.HasPrefix(why, "revoked-generation") {
				if rf, ok2 := st.Reviewers[s.ReviewerID]; ok2 {
					if rootID, err := verifyChain(st, rf); err == nil {
						if rp, ok3 := st.RevPaths[rootID]; ok3 {
							pf.Files = append(pf.Files, proofFile(st.Dir, rp))
						}
					}
				}
			}
		}
		return reject("insufficient-valid-seals",
			fmt.Sprintf("有效封签不足两枚(有效 %d,无效 %d)", len(distinctReviewers(valid)), len(invalid)), pf)
	}
	s1, s2 := firstTwoReviewers(valid)
	if s1.RootID == s2.RootID {
		return reject("shared-root",
			fmt.Sprintf("两名复核人 %s、%s 的委托链同受根 %s 控制,不构成独立批准",
				s1.Seal.ReviewerID, s2.Seal.ReviewerID, s1.RootID),
			Proof{Seals: []ProofSeal{proofSeal(st, s1), proofSeal(st, s2)}})
	}
	d.Pass, d.Rule = true, "approved"
	d.Proof = Proof{
		Statement: fmt.Sprintf("两枚封签分别归属独立根 %s 与 %s,签核代均未被撤销,摘要与证据一致",
			s1.RootID, s2.RootID),
		Seals: []ProofSeal{proofSeal(st, s1), proofSeal(st, s2)},
		Extra: map[string]string{"evidence_digest": digest},
	}
	return d
}

func firstTwoReviewers(valid []sealInfo) (sealInfo, sealInfo) {
	seen := map[string]bool{}
	var picked []sealInfo
	for _, v := range valid {
		if !seen[v.Seal.ReviewerID] {
			seen[v.Seal.ReviewerID] = true
			picked = append(picked, v)
		}
	}
	return picked[0], picked[1]
}

// ---------- 报告与独立核对 ----------

type Report struct {
	Kind       string            `json:"kind"`
	Note       string            `json:"note"`
	Decisions  []Decision        `json:"decisions"`
	Chaos      []ChaosResult     `json:"chaos"`
	Exhaustive ExhaustiveResult  `json:"exhaustive"`
	Scale      ScaleResult       `json:"scale"`
	Inventory  map[string]string `json:"inventory"` // 相对路径 -> SHA-256
}

func buildInventory(dir string) (map[string]string, error) {
	inv := map[string]string{}
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || info.Name() == "report.json" {
			return err
		}
		h, err := hashFile(p)
		if err != nil {
			return err
		}
		inv[rel(dir, p)] = h
		return nil
	})
	return inv, err
}

func writeReport(dir string, r *Report) error {
	inv, err := buildInventory(dir)
	if err != nil {
		return err
	}
	r.Inventory = inv
	return writeJSON(filepath.Join(dir, "report.json"), r)
}

// VerifyReport 独立核对:只读落盘目录与 report.json,重放并重算全部结论。
// 不复用运行期内存,等同第三方工具逐条验证。
func VerifyReport(dir string) bool {
	ok := true
	fail := func(format string, a ...any) {
		ok = false
		fmt.Printf("  [FAIL] "+format+"\n", a...)
	}
	b, err := os.ReadFile(filepath.Join(dir, "report.json"))
	if err != nil {
		fmt.Println("verify: cannot read report.json:", err)
		return false
	}
	var rep Report
	if err := json.Unmarshal(b, &rep); err != nil {
		fmt.Println("verify: bad report.json:", err)
		return false
	}
	// 1. 清单哈希逐文件重算。
	inv, err := buildInventory(dir)
	if err != nil {
		fmt.Println("verify:", err)
		return false
	}
	for p, h := range rep.Inventory {
		if inv[p] != h {
			fail("inventory hash mismatch: %s", p)
		}
	}
	for p := range inv {
		if _, ok := rep.Inventory[p]; !ok {
			fail("file not covered by report inventory: %s", p)
		}
	}
	fmt.Printf("  inventory: %d files hashed and matched\n", len(rep.Inventory))
	// 2. 独立重放并重算每条裁决(裁决对象位于 scenario 证据目录)。
	st, err := Replay(filepath.Join(dir, "scenario"))
	if err != nil {
		fmt.Println("verify: replay failed:", err)
		return false
	}
	for _, d := range rep.Decisions {
		got := Decide(st, d.PkgNo)
		if got.Pass != d.Pass || got.Rule != d.Rule {
			fail("decision mismatch on %s: report=(%v,%s) recomputed=(%v,%s)",
				d.PkgNo, d.Pass, d.Rule, got.Pass, got.Rule)
			continue
		}
		// 3. 证据内每枚封签独立验签。
		for _, ps := range d.Proof.Seals {
			rf, ok := st.Reviewers[ps.ReviewerID]
			if !ok {
				fail("proof seal %s: unknown reviewer", ps.SealID)
				continue
			}
			var seal *Seal
			for i := range st.Seals {
				if st.Seals[i].SealID == ps.SealID {
					seal = &st.Seals[i]
					break
				}
			}
			if seal == nil || !ed25519.Verify(mustHex(rf.PubHex), []byte(sealPayload(*seal)), mustHex(seal.SigHex)) {
				fail("proof seal %s: signature does not verify", ps.SealID)
			}
		}
		fmt.Printf("  decision %-8s pass=%-5v rule=%s  [recomputed OK]\n", d.PkgNo, d.Pass, d.Rule)
	}
	// 4. 并发场景、穷举、大规模核验的结论性断言。
	for _, c := range rep.Chaos {
		if !c.Pass {
			fail("chaos scenario %s did not hold", c.Name)
		}
	}
	if rep.Exhaustive.Mismatches != 0 {
		fail("exhaustive mismatches: %d", rep.Exhaustive.Mismatches)
	}
	if !rep.Scale.Match || rep.Scale.FullReads != rep.Scale.TotalRecords {
		fail("scale check inconsistent")
	}
	if rep.Scale.TargetedReads >= rep.Scale.FullReads {
		fail("targeted reverify read no fewer records than full recheck")
	}
	fmt.Printf("  chaos=%d scenarios held, exhaustive=%d combos 0 mismatch, scale: targeted=%d full=%d match=%v\n",
		len(rep.Chaos), rep.Exhaustive.Combinations,
		rep.Scale.TargetedReads, rep.Scale.FullReads, rep.Scale.Match)
	if ok {
		fmt.Println("VERIFY OK: 报告全部结论可由落盘证据独立复算")
	}
	return ok
}

// sortedKeys 供报告稳定输出。
func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
