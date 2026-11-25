package main

import (
	"fmt"
	"path/filepath"
)

// ExhaustiveResult 小样本穷举结论。
type ExhaustiveResult struct {
	Combinations int      `json:"combinations"`
	Mismatches   int      `json:"mismatches"`
	Details      []string `json:"mismatch_details,omitempty"`
}

// RunExhaustive 穷举 6 个布尔维度共 64 种签核组合:
//
//	bit0 两根是否独立  bit1 封签1签名有效  bit2 封签2签名有效
//	bit3 摘要一致      bit4 签核代未撤销    bit5 回执齐备
//
// 每种组合独立落盘、独立重放,裁决结果与真值表逐一对照。
func RunExhaustive(base string) ExhaustiveResult {
	res := ExhaustiveResult{}
	for bits := 0; bits < 64; bits++ {
		independent := bits&1 != 0
		sig1OK := bits&2 != 0
		sig2OK := bits&4 != 0
		digestOK := bits&8 != 0
		notRevoked := bits&16 != 0
		receiptOK := bits&32 != 0
		wantPass := independent && sig1OK && sig2OK && digestOK && notRevoked && receiptOK

		dir := filepath.Join(base, "exhaustive", fmt.Sprintf("case-%02d", bits))
		pass, rule, err := runOneCombo(dir, independent, sig1OK, sig2OK, digestOK, notRevoked, receiptOK)
		res.Combinations++
		if err != nil {
			res.Mismatches++
			res.Details = append(res.Details, fmt.Sprintf("case-%02d: %v", bits, err))
			continue
		}
		if pass != wantPass {
			res.Mismatches++
			res.Details = append(res.Details,
				fmt.Sprintf("case-%02d: got pass=%v rule=%s, want pass=%v", bits, pass, rule, wantPass))
		}
	}
	return res
}

func runOneCombo(dir string, independent, sig1OK, sig2OK, digestOK, notRevoked, receiptOK bool) (bool, string, error) {
	st := NewStore(dir)
	rootG := NewRoot("root-G", "exhaustive")
	rootH := NewRoot("root-H", "exhaustive")
	for _, r := range []Root{rootG, rootH} {
		if err := st.WriteRoot(r); err != nil {
			return false, "", err
		}
	}
	g1 := makeReviewer("rev-G1", signLink(rootG.Priv, rootG.ID, "rev-G1", mustHexPubOf("rev-G1")))
	g2 := makeReviewer("rev-G2", signLink(rootG.Priv, rootG.ID, "rev-G2", mustHexPubOf("rev-G2")))
	h1 := makeReviewer("rev-H1", signLink(rootH.Priv, rootH.ID, "rev-H1", mustHexPubOf("rev-H1")))
	for _, rv := range []Reviewer{g1, g2, h1} {
		if err := st.WriteReviewer(rv); err != nil {
			return false, "", err
		}
	}
	digest, err := st.WriteEvidence("PKG-X", []byte("payload PKG-X\n"))
	if err != nil {
		return false, "", err
	}
	sealDigest := digest
	if !digestOK {
		sealDigest = sha256HexOf("tampered digest")
	}
	second := g2
	if independent {
		second = h1
	}
	s1, err := makeSeal(st, g1, "seal-X-1", "PKG-X", "CASE-X", sealDigest, 1)
	if err != nil {
		return false, "", err
	}
	s2, err := makeSeal(st, second, "seal-X-2", "PKG-X", "CASE-X", sealDigest, 1)
	if err != nil {
		return false, "", err
	}
	if !sig1OK {
		s1.SigHex = s1.SigHex[:len(s1.SigHex)-2] + "00" // 破坏签名
	}
	if !sig2OK {
		s2.SigHex = s2.SigHex[:len(s2.SigHex)-2] + "00"
	}
	// 全部走强写路径:穷举测的是重放裁决,不是提交期校验。
	if err := st.ForceSeal(s1); err != nil {
		return false, "", err
	}
	if err := st.ForceSeal(s2); err != nil {
		return false, "", err
	}
	if !notRevoked {
		if err := st.AppendRevocation(rootG, 1, "exhaustive revoke G"); err != nil {
			return false, "", err
		}
		if err := st.AppendRevocation(rootH, 1, "exhaustive revoke H"); err != nil {
			return false, "", err
		}
	}
	if err := st.ForceCommit("PKG-X", digest, []string{"seal-X-1", "seal-X-2"}); err != nil {
		return false, "", err
	}
	if receiptOK {
		if err := st.ForceReceipt("PKG-X", digest); err != nil {
			return false, "", err
		}
	}
	state, err := Replay(dir)
	if err != nil {
		return false, "", err
	}
	d := Decide(state, "PKG-X")
	return d.Pass, d.Rule, nil
}
