package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func usage() {
	fmt.Println(`证据包仲裁(仅 Go 标准库,Windows)
用法:
  evarb run [dir]     运行全部场景并在 dir(默认 out)生成证据目录与 report.json
  evarb verify <dir>  独立核对:重放落盘目录,重算报告全部结论
附:report.json 的 inventory 含每个证据文件的 SHA-256,
    可用 certutil -hashfile <文件> SHA256 逐条独立核对。`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "run":
		dir := "out"
		if len(os.Args) > 2 {
			dir = os.Args[2]
		}
		if err := runAll(dir); err != nil {
			fmt.Fprintln(os.Stderr, "run:", err)
			os.Exit(1)
		}
	case "verify":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "verify <dir>")
			os.Exit(2)
		}
		if !VerifyReport(os.Args[2]) {
			os.Exit(1)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func runAll(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	// 1. 双「已审定」合成场景。
	decisions, err := BuildScenario(filepath.Join(dir, "scenario"))
	if err != nil {
		return fmt.Errorf("scenario: %w", err)
	}
	fmt.Println("== 合成场景裁决 ==")
	for _, d := range decisions {
		fmt.Printf("  %s 自称[%s] -> pass=%v rule=%s\n  最短证据: %s\n",
			d.PkgNo, d.Claim, d.Pass, d.Rule, d.Proof.Statement)
	}
	// 2. 两线程加屏障的三类并发故障。
	chaos := RunChaos(dir)
	fmt.Println("== 并发故障与恢复 ==")
	for _, c := range chaos {
		fmt.Printf("  [%v] %s\n      %s\n", c.Pass, c.Name, c.Observed)
	}
	// 3. 小样本穷举。
	ex := RunExhaustive(dir)
	fmt.Printf("== 穷举 ==\n  %d 种签核组合, 不一致 %d 起\n", ex.Combinations, ex.Mismatches)
	// 4. 六万条分案件记录。
	sc := RunScale()
	fmt.Printf("== 大规模核验 ==\n  %s\n", formatScale(sc))
	// 5. 汇总报告(含全部落盘文件清单哈希)。
	rep := &Report{
		Kind: "evidence-package-arbitration/v1",
		Note: "结论可由 `evarb verify <dir>` 独立复算;inventory 内哈希可用 certutil -hashfile <文件> SHA256 逐条核对。",
		Decisions: decisions, Chaos: chaos, Exhaustive: ex, Scale: sc,
	}
	if err := writeReport(dir, rep); err != nil {
		return err
	}
	fmt.Println("报告已写入", filepath.Join(dir, "report.json"))
	return nil
}
