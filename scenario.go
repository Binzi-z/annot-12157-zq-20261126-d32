package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// makeReviewer 生成复核人:chain 从根出发,可经中间人再到本人。
func makeReviewer(id string, chain ...Link) Reviewer {
	sum := sha256.Sum256([]byte("reviewer|" + id))
	priv := ed25519.NewKeyFromSeed(sum[:])
	return Reviewer{ID: id, Chain: chain, Priv: priv, Pub: priv.Public().(ed25519.PublicKey)}
}

// makeSeal 由复核人对(接收方, 证据摘要, 签核代)签发封签。
func makeSeal(st *Store, rv Reviewer, sealID, pkgNo, recipient, digest string, generation int) (Seal, error) {
	ch, err := st.reviewerChainHash(rv.ID)
	if err != nil {
		return Seal{}, err
	}
	s := Seal{
		SealID: sealID, PkgNo: pkgNo, Recipient: recipient,
		EvidenceDigest: digest, Generation: generation,
		ReviewerID: rv.ID, ChainHash: ch,
	}
	s.SigHex = hex.EncodeToString(ed25519.Sign(rv.Priv, []byte(sealPayload(s))))
	return s, nil
}

// BuildScenario 构造题面场景:两个都自称「已审定」的包。
// PKG-0001: 两名复核人分别归属根 A、根 B(真正独立)。
// PKG-0002: 两名复核人 rev-3 直签自根 C,rev-4 经中间人 mid-C 委托——
//
//	表面两条链,实际同受根 C 一个委托链控制。
func BuildScenario(dir string) ([]Decision, error) {
	st := NewStore(dir)
	rootA := NewRoot("root-A", "scenario")
	rootB := NewRoot("root-B", "scenario")
	rootC := NewRoot("root-C", "scenario")
	for _, r := range []Root{rootA, rootB, rootC} {
		if err := st.WriteRoot(r); err != nil {
			return nil, err
		}
	}
	// 中间人 mid-C:根 C 的把兄弟,只为让 rev-4 的链看起来与 rev-3 不同。
	midSum := sha256.Sum256([]byte("mid|mid-C"))
	midPriv := ed25519.NewKeyFromSeed(midSum[:])
	midPub := midPriv.Public().(ed25519.PublicKey)

	rev1 := makeReviewer("rev-1", signLink(rootA.Priv, rootA.ID, "rev-1", mustHexPubOf("rev-1")))
	rev2 := makeReviewer("rev-2", signLink(rootB.Priv, rootB.ID, "rev-2", mustHexPubOf("rev-2")))
	rev3 := makeReviewer("rev-3", signLink(rootC.Priv, rootC.ID, "rev-3", mustHexPubOf("rev-3")))
	rev4 := makeReviewer("rev-4",
		signLink(rootC.Priv, rootC.ID, "mid-C", midPub),
		signLink(midPriv, "mid-C", "rev-4", mustHexPubOf("rev-4")),
	)
	for _, rv := range []Reviewer{rev1, rev2, rev3, rev4} {
		if err := st.WriteReviewer(rv); err != nil {
			return nil, err
		}
	}
	type pkg struct {
		no, recipient string
		payload       []byte
		seals         [2]Reviewer
	}
	pkgs := []pkg{
		{"PKG-0001", "CASE-0001", []byte("evidence payload for PKG-0001\n"), [2]Reviewer{rev1, rev2}},
		{"PKG-0002", "CASE-0002", []byte("evidence payload for PKG-0002\n"), [2]Reviewer{rev3, rev4}},
	}
	for _, p := range pkgs {
		digest, err := st.WriteEvidence(p.no, p.payload)
		if err != nil {
			return nil, err
		}
		var ids []string
		for i, rv := range p.seals {
			s, err := makeSeal(st, rv, fmt.Sprintf("seal-%s-%d", p.no, i+1), p.no, p.recipient, digest, 1)
			if err != nil {
				return nil, err
			}
			if err := st.AppendSeal(s); err != nil {
				return nil, err
			}
			ids = append(ids, s.SealID)
		}
		if err := st.TryCommit(p.no, ids); err != nil {
			return nil, err
		}
		if err := st.WriteReceipt(p.no); err != nil {
			return nil, err
		}
	}
	state, err := Replay(dir)
	if err != nil {
		return nil, err
	}
	var out []Decision
	for _, p := range pkgs {
		out = append(out, Decide(state, p.no))
	}
	return out, nil
}

// mustHexPubOf 与 makeReviewer 使用同一种子派生复核人公钥。
func mustHexPubOf(reviewerID string) ed25519.PublicKey {
	sum := sha256.Sum256([]byte("reviewer|" + reviewerID))
	priv := ed25519.NewKeyFromSeed(sum[:])
	return priv.Public().(ed25519.PublicKey)
}

// pkgNos 返回目录中全部有承诺记录的包编号,供报告遍历。
func pkgNos(st *State) []string {
	return sortedKeys(st.Commits)
}
