package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// ---------- 通用哈希 ----------

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func hashFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return sha256Hex(b), nil
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("bad hex %q: %v", s, err))
	}
	return b
}

// ---------- 域模型 ----------

// Root 签核根。Priv 只留在内存,落盘只含公钥。
type Root struct {
	ID   string
	Pub  ed25519.PublicKey
	Priv ed25519.PrivateKey
}

func NewRoot(id, seed string) Root {
	sum := sha256.Sum256([]byte("root|" + id + "|" + seed))
	priv := ed25519.NewKeyFromSeed(sum[:])
	return Root{ID: id, Priv: priv, Pub: priv.Public().(ed25519.PublicKey)}
}

type rootFile struct {
	RootID string `json:"root_id"`
	PubHex string `json:"pub_hex"`
}

// Link 委托链一跳:FromID 把签核权委托给 ToID(公钥 ToPubHex)。
type Link struct {
	FromID   string `json:"from_id"`
	ToID     string `json:"to_id"`
	ToPubHex string `json:"to_pub_hex"`
	SigHex   string `json:"sig_hex"`
}

func linkPayload(l Link) string {
	return strings.Join([]string{"delegate", l.FromID, l.ToID, l.ToPubHex}, "|")
}

func signLink(fromPriv ed25519.PrivateKey, fromID, toID string, toPub ed25519.PublicKey) Link {
	l := Link{FromID: fromID, ToID: toID, ToPubHex: hex.EncodeToString(toPub)}
	l.SigHex = hex.EncodeToString(ed25519.Sign(fromPriv, []byte(linkPayload(l))))
	return l
}

type reviewerFile struct {
	ReviewerID string `json:"reviewer_id"`
	Chain      []Link `json:"chain"`
	PubHex     string `json:"pub_hex"`
}

// Reviewer 复核人,Chain 从根出发逐级委托到本人。
type Reviewer struct {
	ID    string
	Chain []Link
	Pub   ed25519.PublicKey
	Priv  ed25519.PrivateKey
}

func (r Reviewer) ChainRootID() string { return r.Chain[0].FromID }

// Seal 封签:引用接收方、证据摘要、签核代。
type Seal struct {
	Seq            int    `json:"seq"`
	SealID         string `json:"seal_id"`
	PkgNo          string `json:"pkg_no"`
	Recipient      string `json:"recipient"`
	EvidenceDigest string `json:"evidence_digest"`
	Generation     int    `json:"generation"`
	ReviewerID     string `json:"reviewer_id"`
	ChainHash      string `json:"chain_hash"`
	SigHex         string `json:"sig_hex"`
}

func sealPayload(s Seal) string {
	return strings.Join([]string{
		"seal", s.PkgNo, s.Recipient, s.EvidenceDigest,
		strconv.Itoa(s.Generation), s.ReviewerID, s.ChainHash,
	}, "|")
}

// Revocation 撤销:使 RootID 在 Generation 及更早签核代上的封签失效。
type Revocation struct {
	Seq        int    `json:"seq"`
	RootID     string `json:"root_id"`
	Generation int    `json:"generation"`
	Reason     string `json:"reason"`
	SigHex     string `json:"sig_hex"`
}

func revocationPayload(r Revocation) string {
	return strings.Join([]string{"revoke", r.RootID, strconv.Itoa(r.Generation), r.Reason}, "|")
}

// Commit 承诺(两阶段的第一阶段)。
type Commit struct {
	Seq            int      `json:"seq"`
	PkgNo          string   `json:"pkg_no"`
	EvidenceDigest string   `json:"evidence_digest"`
	SealIDs        []string `json:"seal_ids"`
}

// Receipt 回执(第二阶段;承诺+回执齐备且重放时仍有效才算生效)。
type Receipt struct {
	Seq            int    `json:"seq"`
	PkgNo          string `json:"pkg_no"`
	EvidenceDigest string `json:"evidence_digest"`
}

// ---------- 落盘存储 ----------

// Store 目录布局:
//
//	roots/<root>.json  reviewers/<rev>.json  evidence/<pkg>.bin
//	seals/<seq>-<id>.json  revocations/<seq>-<root>.json
//	commits/<pkg>-<digest8>-<seq>.json  receipts/<pkg>.json
type Store struct {
	Dir string
	mu  sync.Mutex
}

func NewStore(dir string) *Store { return &Store{Dir: dir} }

func (s *Store) sub(name string) string {
	p := filepath.Join(s.Dir, name)
	if err := os.MkdirAll(p, 0o755); err != nil {
		panic(err)
	}
	return p
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// nextSeqLocked 调用方须持有 s.mu。
func (s *Store) nextSeqLocked(sub string) int {
	entries, err := os.ReadDir(filepath.Join(s.Dir, sub))
	if err != nil {
		return 1
	}
	return len(entries) + 1
}

func (s *Store) WriteRoot(r Root) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeJSON(filepath.Join(s.sub("roots"), r.ID+".json"),
		rootFile{RootID: r.ID, PubHex: hex.EncodeToString(r.Pub)})
}

func (s *Store) WriteReviewer(rv Reviewer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeJSON(filepath.Join(s.sub("reviewers"), rv.ID+".json"),
		reviewerFile{ReviewerID: rv.ID, Chain: rv.Chain, PubHex: hex.EncodeToString(rv.Pub)})
}

// WriteEvidence 写入证据载荷,返回其 SHA-256 摘要。
func (s *Store) WriteEvidence(pkgNo string, payload []byte) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.WriteFile(filepath.Join(s.sub("evidence"), pkgNo+".bin"), payload, 0o644); err != nil {
		return "", err
	}
	return sha256Hex(payload), nil
}

// reviewerChainHash 复核人委托链文件的内容哈希,封签据此绑定具体链。
func (s *Store) reviewerChainHash(reviewerID string) (string, error) {
	return hashFile(filepath.Join(s.Dir, "reviewers", reviewerID+".json"))
}

// AppendSeal 校验后追加封签;校验失败不落盘。
func (s *Store) AppendSeal(seal Seal) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := Replay(s.Dir)
	if err != nil {
		return err
	}
	if _, ok := st.Evidence[seal.PkgNo]; !ok {
		return fmt.Errorf("seal rejected: no evidence for %s", seal.PkgNo)
	}
	if st.Evidence[seal.PkgNo] != seal.EvidenceDigest {
		return fmt.Errorf("seal rejected: digest mismatch for %s", seal.PkgNo)
	}
	if _, err := s.validateSealLocked(st, seal); err != nil {
		return fmt.Errorf("seal rejected: %w", err)
	}
	seal.Seq = s.nextSeqLocked("seals")
	return writeJSON(filepath.Join(s.sub("seals"),
		fmt.Sprintf("%04d-%s.json", seal.Seq, seal.SealID)), seal)
}

// ForceSeal 不做校验直接落盘,仅用于构造故障/穷举样本。
func (s *Store) ForceSeal(seal Seal) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	seal.Seq = s.nextSeqLocked("seals")
	return writeJSON(filepath.Join(s.sub("seals"),
		fmt.Sprintf("%04d-%s.json", seal.Seq, seal.SealID)), seal)
}

func (s *Store) AppendRevocation(root Root, generation int, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rev := Revocation{
		Seq:        s.nextSeqLocked("revocations"),
		RootID:     root.ID,
		Generation: generation,
		Reason:     reason,
	}
	rev.SigHex = hex.EncodeToString(ed25519.Sign(root.Priv, []byte(revocationPayload(rev))))
	return writeJSON(filepath.Join(s.sub("revocations"),
		fmt.Sprintf("%04d-%s.json", rev.Seq, rev.RootID)), rev)
}

// TryCommit 第一阶段承诺:校验封签当前有效且不与既有承诺冲突。
func (s *Store) TryCommit(pkgNo string, sealIDs []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := Replay(s.Dir)
	if err != nil {
		return err
	}
	digest, ok := st.Evidence[pkgNo]
	if !ok {
		return fmt.Errorf("commit rejected: no evidence for %s", pkgNo)
	}
	for _, c := range st.Commits[pkgNo] {
		if c.EvidenceDigest != digest {
			return fmt.Errorf("commit rejected: digest conflict on %s", pkgNo)
		}
	}
	valid, invalid := validSeals(st, pkgNo, digest)
	_ = invalid
	byID := map[string]sealInfo{}
	for _, v := range valid {
		byID[v.Seal.SealID] = v
	}
	for _, id := range sealIDs {
		if _, ok := byID[id]; !ok {
			return fmt.Errorf("commit rejected: seal %s not currently valid", id)
		}
	}
	c := Commit{Seq: s.nextSeqLocked("commits"), PkgNo: pkgNo,
		EvidenceDigest: digest, SealIDs: sealIDs}
	return writeJSON(filepath.Join(s.sub("commits"),
		fmt.Sprintf("%s-%s-%04d.json", pkgNo, digest[:8], c.Seq)), c)
}

// ForceCommit 不校验直接落盘,模拟绕过校验的竞态写入方。
func (s *Store) ForceCommit(pkgNo, digest string, sealIDs []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := Commit{Seq: s.nextSeqLocked("commits"), PkgNo: pkgNo,
		EvidenceDigest: digest, SealIDs: sealIDs}
	return writeJSON(filepath.Join(s.sub("commits"),
		fmt.Sprintf("%s-%s-%04d.json", pkgNo, digest[:8], c.Seq)), c)
}

// WriteReceipt 第二阶段回执:写入前按当前撤销状态重新校验。
func (s *Store) WriteReceipt(pkgNo string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := Replay(s.Dir)
	if err != nil {
		return err
	}
	digest, ok := st.Evidence[pkgNo]
	if !ok {
		return fmt.Errorf("receipt rejected: no evidence for %s", pkgNo)
	}
	commits := st.Commits[pkgNo]
	if len(commits) != 1 {
		return fmt.Errorf("receipt rejected: want exactly 1 commit, have %d", len(commits))
	}
	if commits[0].EvidenceDigest != digest {
		return fmt.Errorf("receipt rejected: commit digest mismatch")
	}
	valid, _ := validSeals(st, pkgNo, digest)
	if len(distinctReviewers(valid)) < 2 {
		return fmt.Errorf("receipt rejected: fewer than 2 currently valid seals")
	}
	r := Receipt{Seq: s.nextSeqLocked("receipts"), PkgNo: pkgNo, EvidenceDigest: digest}
	return writeJSON(filepath.Join(s.sub("receipts"), pkgNo+".json"), r)
}

// ForceReceipt 不校验直接落盘,模拟恢复期的迟到回执。
func (s *Store) ForceReceipt(pkgNo, digest string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := Receipt{Seq: s.nextSeqLocked("receipts"), PkgNo: pkgNo, EvidenceDigest: digest}
	return writeJSON(filepath.Join(s.sub("receipts"), pkgNo+".json"), r)
}

// validateSealLocked 提交路径用的单封签校验,返回链根。
func (s *Store) validateSealLocked(st *State, seal Seal) (string, error) {
	rf, ok := st.Reviewers[seal.ReviewerID]
	if !ok {
		return "", fmt.Errorf("unknown reviewer %s", seal.ReviewerID)
	}
	ch, err := s.reviewerChainHash(seal.ReviewerID)
	if err != nil {
		return "", err
	}
	if ch != seal.ChainHash {
		return "", fmt.Errorf("chain hash mismatch")
	}
	rootID, err := verifyChain(st, rf)
	if err != nil {
		return "", err
	}
	if !ed25519.Verify(mustHex(rf.PubHex), []byte(sealPayload(seal)), mustHex(seal.SigHex)) {
		return "", fmt.Errorf("bad seal signature")
	}
	if seal.Generation <= st.Revoked[rootID] {
		return "", fmt.Errorf("generation %d revoked (<= %d)", seal.Generation, st.Revoked[rootID])
	}
	return rootID, nil
}

// ---------- 重放 ----------

// State 从落盘目录重放出的全部生效事实。
type State struct {
	Dir           string
	Roots         map[string]rootFile
	Reviewers     map[string]reviewerFile
	ReviewerPaths map[string]string
	Revoked       map[string]int           // rootID -> 已撤销的最高签核代
	Revocations   map[string]Revocation    // rootID -> 最高代撤销记录
	RevPaths      map[string]string        // rootID -> 该撤销记录文件
	Seals         []Seal                   // 按 Seq 升序
	SealFiles     map[string]string        // sealID -> 文件路径
	Evidence      map[string]string        // pkgNo -> 证据摘要
	Commits       map[string][]Commit      // pkgNo -> 承诺(按 Seq 升序)
	CommitFiles   map[string][]string      // pkgNo -> 承诺文件
	Receipts      map[string]Receipt       // pkgNo -> 回执
	ReceiptFiles  map[string]string        // pkgNo -> 回执文件
}

// Replay 只从实际落盘目录重建状态,不依赖任何进程内存。
func Replay(dir string) (*State, error) {
	st := &State{
		Dir: dir,
		Roots: map[string]rootFile{}, Reviewers: map[string]reviewerFile{},
		ReviewerPaths: map[string]string{}, Revoked: map[string]int{},
		Revocations: map[string]Revocation{}, RevPaths: map[string]string{},
		SealFiles: map[string]string{}, Evidence: map[string]string{},
		Commits: map[string][]Commit{}, CommitFiles: map[string][]string{},
		Receipts: map[string]Receipt{}, ReceiptFiles: map[string]string{},
	}
	readJSONs := func(sub string, each func(path string, b []byte)) error {
		entries, err := os.ReadDir(filepath.Join(dir, sub))
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		for _, e := range entries {
			p := filepath.Join(dir, sub, e.Name())
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			each(p, b)
		}
		return nil
	}
	if err := readJSONs("roots", func(p string, b []byte) {
		var f rootFile
		if json.Unmarshal(b, &f) == nil {
			st.Roots[f.RootID] = f
		}
	}); err != nil {
		return nil, err
	}
	if err := readJSONs("reviewers", func(p string, b []byte) {
		var f reviewerFile
		if json.Unmarshal(b, &f) == nil {
			st.Reviewers[f.ReviewerID] = f
			st.ReviewerPaths[f.ReviewerID] = p
		}
	}); err != nil {
		return nil, err
	}
	var revs []Revocation
	revPath := map[int]string{}
	if err := readJSONs("revocations", func(p string, b []byte) {
		var r Revocation
		if json.Unmarshal(b, &r) == nil {
			revs = append(revs, r)
			revPath[r.Seq] = p
		}
	}); err != nil {
		return nil, err
	}
	sort.Slice(revs, func(i, j int) bool { return revs[i].Seq < revs[j].Seq })
	for _, r := range revs {
		// 撤销记录本身须由根签名才生效。
		rf, ok := st.Roots[r.RootID]
		if !ok || !ed25519.Verify(mustHex(rf.PubHex), []byte(revocationPayload(r)), mustHex(r.SigHex)) {
			continue
		}
		if r.Generation > st.Revoked[r.RootID] {
			st.Revoked[r.RootID] = r.Generation
			st.Revocations[r.RootID] = r
			st.RevPaths[r.RootID] = revPath[r.Seq]
		}
	}
	if err := readJSONs("seals", func(p string, b []byte) {
		var sl Seal
		if json.Unmarshal(b, &sl) == nil {
			st.Seals = append(st.Seals, sl)
			st.SealFiles[sl.SealID] = p
		}
	}); err != nil {
		return nil, err
	}
	sort.Slice(st.Seals, func(i, j int) bool { return st.Seals[i].Seq < st.Seals[j].Seq })
	entries, err := os.ReadDir(filepath.Join(dir, "evidence"))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	for _, e := range entries {
		p := filepath.Join(dir, "evidence", e.Name())
		h, err := hashFile(p)
		if err != nil {
			return nil, err
		}
		st.Evidence[strings.TrimSuffix(e.Name(), ".bin")] = h
	}
	if err := readJSONs("commits", func(p string, b []byte) {
		var c Commit
		if json.Unmarshal(b, &c) == nil {
			st.Commits[c.PkgNo] = append(st.Commits[c.PkgNo], c)
			st.CommitFiles[c.PkgNo] = append(st.CommitFiles[c.PkgNo], p)
		}
	}); err != nil {
		return nil, err
	}
	for k := range st.Commits {
		sort.Slice(st.Commits[k], func(i, j int) bool { return st.Commits[k][i].Seq < st.Commits[k][j].Seq })
	}
	if err := readJSONs("receipts", func(p string, b []byte) {
		var r Receipt
		if json.Unmarshal(b, &r) == nil {
			st.Receipts[r.PkgNo] = r
			st.ReceiptFiles[r.PkgNo] = p
		}
	}); err != nil {
		return nil, err
	}
	return st, nil
}

// verifyChain 校验委托链并返回链根 ID。
func verifyChain(st *State, rf reviewerFile) (string, error) {
	if len(rf.Chain) == 0 {
		return "", fmt.Errorf("empty delegation chain")
	}
	first := rf.Chain[0]
	root, ok := st.Roots[first.FromID]
	if !ok {
		return "", fmt.Errorf("chain head %s is not a known root", first.FromID)
	}
	if !ed25519.Verify(mustHex(root.PubHex), []byte(linkPayload(first)), mustHex(first.SigHex)) {
		return "", fmt.Errorf("bad delegation signature at chain head")
	}
	prev := first
	for _, l := range rf.Chain[1:] {
		if l.FromID != prev.ToID {
			return "", fmt.Errorf("chain broken at %s", l.FromID)
		}
		if !ed25519.Verify(mustHex(prev.ToPubHex), []byte(linkPayload(l)), mustHex(l.SigHex)) {
			return "", fmt.Errorf("bad delegation signature at %s", l.FromID)
		}
		prev = l
	}
	if prev.ToID != rf.ReviewerID || prev.ToPubHex != rf.PubHex {
		return "", fmt.Errorf("chain does not terminate at reviewer %s", rf.ReviewerID)
	}
	return first.FromID, nil
}
