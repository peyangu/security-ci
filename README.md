# security-ci

個人開発のリポジトリで使い回す、共通セキュリティCIです。人間・AIエージェント・依存パッケージのどこから来た変更でも、危険なものを機械的に検知して、マージやリリースの前で止めます。

- **OSV-Scanner**（依存の脆弱性・悪意あるパッケージ）、**Semgrep**（危険なコード。Electron 向けの自前ルール付き）、**Gitleaks**（シークレット）を実行し、1つのゲートで判定します
- **壊れたら止める**：スキャナの失敗、結果の欠落、スコア不明の脆弱性、壊れた例外ファイルは、すべてブロックします
- **抑制は1か所だけ**：`nosemgrep` や `.gitleaksignore` は効きません。例外は `.security/exceptions.json` だけで、理由と90日以内の期限が必須です
- **PR は持ち込んだ分だけ、main・週次・リリースは全件**でブロックします
- **AI監査エージェント**（任意）：セキュリティ回帰テストを書かせ、権限を分けたジョブで検証してから PR にします

## 使い方

```bash
git clone https://github.com/peyangu/security-ci
node security-ci/scripts/install.mjs path/to/your-repo
```

各リポジトリには短い呼び出し側だけが入り、判定ロジックとルールはこのリポジトリのコミットに SHA で固定されます。あとは `security / gate` を main の必須チェックにしてください。

設計・運用ルール・ロードマップは [docs/SECURITY_CI.md](docs/SECURITY_CI.md) にあります。
