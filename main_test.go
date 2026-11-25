package main

import (
	"path/filepath"
	"testing"
)

// 两个「已审定」包:独立双根的通过,同一委托链的被否决。
func TestScenario(t *testing.T) {
	dir := t.TempDir()
	ds, err := BuildScenario(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ds) != 2 {
		t.Fatalf("want 2 decisions, got %d", len(ds))
	}
	if !ds[0].Pass || ds[0].Rule != "approved" {
		t.Errorf("PKG-0001 should pass, got %+v", ds[0])
	}
	if ds[1].Pass || ds[1].Rule != "shared-root" {
		t.Errorf("PKG-0002 should be rejected as shared-root, got %+v", ds[1])
	}
	// 否决证据必须指向同一个根。
	if ds[1].Proof.Seals[0].RootID != ds[1].Proof.Seals[1].RootID {
		t.Errorf("shared-root proof seals disagree: %+v", ds[1].Proof.Seals)
	}
}

// 三类并发故障:恢复重放后均不误收旧包。
func TestChaos(t *testing.T) {
	for _, c := range RunChaos(t.TempDir()) {
		if !c.Pass {
			t.Errorf("%s: %s", c.Name, c.Observed)
		}
	}
}

// 64 种签核组合穷举,裁决与真值表零偏差。
func TestExhaustive(t *testing.T) {
	res := RunExhaustive(t.TempDir())
	if res.Combinations != 64 {
		t.Fatalf("want 64 combos, got %d", res.Combinations)
	}
	if res.Mismatches != 0 {
		t.Fatalf("mismatches: %v", res.Details)
	}
}

// 六万条记录:定向核验读取更少且与全量重新核验一致。
func TestScale(t *testing.T) {
	s := RunScale()
	if s.TotalRecords != 60000 || s.FullReads != 60000 {
		t.Fatalf("scale size wrong: %+v", s)
	}
	if !s.Match {
		t.Fatal("targeted reverify disagrees with full recheck")
	}
	if s.TargetedReads >= s.FullReads {
		t.Fatalf("targeted reads %d not below full %d", s.TargetedReads, s.FullReads)
	}
	if s.DirectCases == 0 || s.SharedCases == 0 {
		t.Fatalf("expected both direct and shared cases: %+v", s)
	}
}

// 端到端:run 产出报告后,verify 独立复算通过。
func TestRunThenVerify(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "out")
	if err := runAll(dir); err != nil {
		t.Fatal(err)
	}
	if !VerifyReport(dir) {
		t.Fatal("independent verification failed")
	}
}

// 每次测试运行在包目录刷新 out/ 证据目录与报告,供人工与独立工具核对。
func TestProduceArtifacts(t *testing.T) {
	dir := "out"
	if err := runAll(dir); err != nil {
		t.Fatal(err)
	}
	if !VerifyReport(dir) {
		t.Fatal("independent verification failed")
	}
}
