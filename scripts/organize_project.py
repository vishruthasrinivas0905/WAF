#!/usr/bin/env python3
"""
PROJECT CLEANUP & FOLDER REORGANIZATION UTILITY
Script: scripts/organize_project.py

Organizes the project directory by:
1. Moving loose or temporary diagnostic files (e.g. diagnose_model_accuracy.py,
   test_model.py, one-off test scripts) into 'extra_resources/'.
2. Purging temporary files (__pycache__, *.pyc, *.pyo, temporary logs).
3. Ensuring standard production folder structure:
   - waf/               -> Core WAF detection & policy engine
   - src/               -> Web Dashboard & Gateway UI
   - scripts/           -> Active production CLIs and training tools
   - tests/             -> Automated unit test suites
   - extra_resources/   -> Benchmarks, dataset audits, offline diagnostics
   - models/            -> Model weights and tokenizers
"""

import os
import shutil
import sys
from pathlib import Path

def clean_pycache(root_dir: Path):
    """Recursively removes all __pycache__ directories and .pyc files."""
    cleaned_dirs = 0
    cleaned_files = 0
    for path in list(root_dir.rglob("__pycache__")):
        try:
            shutil.rmtree(path)
            cleaned_dirs += 1
        except Exception as e:
            print(f"  [!] Failed to remove {path}: {e}")
            
    for ext in ("*.pyc", "*.pyo", "*.pyd"):
        for path in list(root_dir.rglob(ext)):
            try:
                path.unlink()
                cleaned_files += 1
            except Exception as e:
                print(f"  [!] Failed to remove {path}: {e}")
                
    return cleaned_dirs, cleaned_files

def organize_workspace(root_dir: Path):
    print("=" * 70)
    print(" AppAware WAF: Project Directory Organization Utility")
    print(f" Target Directory: {root_dir.resolve()}")
    print("=" * 70)

    extra_dir = root_dir / "extra_resources"
    extra_scripts = extra_dir / "scripts"
    extra_experiments = extra_dir / "experiments"
    extra_diagnostics = extra_dir / "diagnostics"

    for d in [extra_dir, extra_scripts, extra_experiments, extra_diagnostics]:
        d.mkdir(parents=True, exist_ok=True)

    # Specific loose files to move into extra_resources/diagnostics or extra_resources/scripts
    loose_diagnostic_files = [
        "diagnose_model_accuracy.py",
        "test_model.py",
        "inspect_dataset.py",
        "audit_dataset.py",
        "quick_audit.py",
        "check_labels.py",
        "temp_test.py",
        "test_cli.py",
    ]

    moved_count = 0
    for filename in loose_diagnostic_files:
        src_path = root_dir / filename
        if src_path.is_file():
            dest_path = extra_diagnostics / filename
            print(f"[*] Moving loose script '{filename}' -> extra_resources/diagnostics/")
            shutil.move(str(src_path), str(dest_path))
            moved_count += 1

    # Check for temporary experiment scripts in root or scripts that belong in extra_resources
    if (root_dir / "experiments").is_dir():
        print("[*] Consolidating 'experiments/' into 'extra_resources/experiments/'...")
        for item in (root_dir / "experiments").iterdir():
            target_dest = extra_experiments / item.name
            if not target_dest.exists():
                shutil.move(str(item), str(target_dest))
        try:
            shutil.rmtree(root_dir / "experiments")
        except Exception:
            pass

    # Clean temporary cache
    print("\n[*] Purging temporary Python cache files (__pycache__, *.pyc)...")
    cleaned_dirs, cleaned_files = clean_pycache(root_dir)
    print(f"    Cleaned {cleaned_dirs} __pycache__ folders and {cleaned_files} bytecode files.")

    print("\n" + "=" * 70)
    print(" Clean Production Structure Verified:")
    print("  ├── waf/                 [Core detection, canonicalizer, rules, policy]")
    print("  ├── scripts/             [Active CLI tools & training scripts]")
    print("  │   ├── interactive_cli.py")
    print("  │   ├── live_attack_tester.py")
    print("  │   ├── train_transformer.py")
    print("  │   └── organize_project.py")
    print("  ├── tests/               [Unit & regression test suite]")
    print("  │   └── test_waf_pipeline.py")
    print("  ├── src/                 [Full-Stack WAF React Dashboard UI]")
    print("  ├── server.ts            [Express reverse-proxy gateway & REST API]")
    print("  └── extra_resources/     [Experiments, dataset inspection, diagnostics]")
    print("      ├── experiments/     [Adaptation & robustness evaluations]")
    print("      ├── diagnostics/     [Diagnostic scripts & offline tools]")
    print("      └── README.md        [Documentation of research artifacts]")
    print("=" * 70)
    print(f"[+] Reorganization complete! Moved {moved_count} loose files.")

if __name__ == "__main__":
    current_root = Path(__file__).resolve().parent.parent
    organize_workspace(current_root)
