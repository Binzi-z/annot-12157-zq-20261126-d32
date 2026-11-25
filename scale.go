package main

import (
	"fmt"
	"math/rand"
)

// ScaleResult 六万条分案件记录上的一次撤销核验结论。
type ScaleResult struct {
	TotalRecords    int    `json:"total_records"`
	TotalCases      int    `json:"total_cases"`
	RevokedRoot     string `json:"revoked_root"`
	RevokedRefs     int    `json:"revoked_refs"`
	DirectCases     int    `json:"direct_cases"` // 直接引用被撤证据的案件
	SharedCases     int    `json:"shared_cases"` // 仅经共享证据引用波及
	TargetedReads   int    `json:"targeted_reads"`
	FullReads       int    `json:"full_reads"`
	AffectedRecords int    `json:"affected_records"`
	Match           bool   `json:"match_full_recheck"` // 定向核验与全量重新核验一致
}

type caseRecord struct {
	CaseID int
	RecID  int
	Root   string
	Refs   []string
}

// RunScale 生成 3000 案件 × 20 条 = 60000 条记录(确定性种子),
// 撤销一个根,定向核验只读取有直接/共享证据引用的案件,
// 再与全量重新核验对照。索引随写入增量维护,不计入撤销时读取。
func RunScale() ScaleResult {
	// 每个案件有主签根(90% 记录),另有少量跨根记录;
	// 证据引用分两类:案件内独有引用,与跨案件共享引用(约 10% 记录引用共享池)。
	const cases, per = 3000, 20
	rng := rand.New(rand.NewSource(20261126))
	roots := []string{"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9"}
	const sharedPool = 2000

	records := make([][]caseRecord, cases) // caseID -> records
	refToCases := map[string]map[int]bool{}
	for c := 0; c < cases; c++ {
		primary := roots[c%len(roots)]
		for i := 0; i < per; i++ {
			root := primary
			if rng.Intn(100) < 10 {
				root = roots[rng.Intn(len(roots))]
			}
			var refs []string
			if rng.Intn(100) < 10 {
				refs = append(refs, fmt.Sprintf("shared-%d", rng.Intn(sharedPool)))
			} else {
				refs = append(refs, fmt.Sprintf("uniq-%d-%d", c, i))
			}
			rec := caseRecord{CaseID: c, RecID: i, Root: root, Refs: refs}
			records[c] = append(records[c], rec)
			for _, r := range refs {
				if refToCases[r] == nil {
					refToCases[r] = map[int]bool{}
				}
				refToCases[r][c] = true
			}
		}
	}

	// 撤销根 r3:其全部记录所引用的证据一并失效。
	const revokedRoot = "r3"
	revokedRefs := map[string]bool{}
	directCases := map[int]bool{}
	for c := 0; c < cases; c++ {
		for _, rec := range records[c] {
			if rec.Root == revokedRoot {
				directCases[c] = true
				for _, r := range rec.Refs {
					revokedRefs[r] = true
				}
			}
		}
	}
	// 受影响案件 = 直接引用 ∪ 共享引用(引用了任一被撤证据的案件)。
	affectedCases := map[int]bool{}
	for r := range revokedRefs {
		for c := range refToCases[r] {
			affectedCases[c] = true
		}
	}
	shared := 0
	for c := range affectedCases {
		if !directCases[c] {
			shared++
		}
	}

	invalid := func(rec caseRecord) bool {
		if rec.Root == revokedRoot {
			return true
		}
		for _, r := range rec.Refs {
			if revokedRefs[r] {
				return true
			}
		}
		return false
	}

	// 定向核验:只读取受影响案件的记录。
	targeted := map[[2]int]bool{}
	targetedReads := 0
	for c := range affectedCases {
		for _, rec := range records[c] {
			targetedReads++
			if invalid(rec) {
				targeted[[2]int{rec.CaseID, rec.RecID}] = true
			}
		}
	}
	// 全量重新核验:读取全部 60000 条。
	full := map[[2]int]bool{}
	fullReads := 0
	for c := 0; c < cases; c++ {
		for _, rec := range records[c] {
			fullReads++
			if invalid(rec) {
				full[[2]int{rec.CaseID, rec.RecID}] = true
			}
		}
	}
	match := len(targeted) == len(full)
	for k := range full {
		if !targeted[k] {
			match = false
			break
		}
	}
	return ScaleResult{
		TotalRecords: cases * per, TotalCases: cases,
		RevokedRoot: revokedRoot, RevokedRefs: len(revokedRefs),
		DirectCases: len(directCases), SharedCases: shared,
		TargetedReads: targetedReads, FullReads: fullReads,
		AffectedRecords: len(full), Match: match,
	}
}

// formatScale 供命令行摘要输出。
func formatScale(s ScaleResult) string {
	return fmt.Sprintf("records=%d cases=%d revokedRefs=%d direct=%d shared=%d targetedReads=%d fullReads=%d affected=%d match=%v",
		s.TotalRecords, s.TotalCases, s.RevokedRefs, s.DirectCases, s.SharedCases,
		s.TargetedReads, s.FullReads, s.AffectedRecords, s.Match)
}
