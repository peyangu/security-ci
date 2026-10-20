# 共通セキュリティCI — 設計・運用・ロードマップ

> 前提：**「AIが安全なコードを書くこと」には期待しない。** 人間・AIエージェント・依存パッケージのどこから来た変更でも、
> 危険なものが混入したら **機械的に検知し、マージ／公開の前で止める**。止まった理由と例外は全部記録に残す。

対象：個人開発の全リポジトリ。このリポジトリ（`peyangu/security-ci`）が判定ロジックとルールを持ち、各リポジトリは SHA 固定で呼び出すだけにする。最初の適用先は `DERELICT`。

---

## 1. 設計原則

| # | 原則 | 具体的には |
|---|---|---|
| P1 | **書き手を信用しない** | AIエージェントの出力・自分のコミット・依存パッケージを同じ基準で検査する。AIが書いたテストもAI以外の仕組みで検証する |
| P2 | **Fail-closed** | スキャナが落ちた・結果ファイルがない・例外ファイルが壊れている・未採点の脆弱性 → すべて「ブロック」扱い |
| P3 | **抑制は1か所・期限付き** | `nosemgrep` / `gitleaks:allow` / `.gitleaksignore` / `osv-scanner.toml` などの散在する抑制は**無効化**。例外は `.security/exceptions.json` だけ、理由と期限（最長90日）が必須 |
| P4 | **判定する側を判定される側から切り離す** | 判定ロジックとルールはこの中央リポジトリにあり、各リポジトリは SHA 固定で取り込む（PRで判定側を書き換えられない）。中央リポジトリ自身のPRは「PRのベース側」のゲートで判定 |
| P5 | **最小権限** | すべてのワークフローは `permissions: {}` 起点。書き込み権限を持つジョブはAIの出力を実行しない。Actionは全てコミットSHA固定 |
| P6 | **公開経路は1本** | リリース成果物は `release.yml` だけが作る。セキュリティゲートを通らない限りビルドすら走らない |

## 2. 何を止めるか（脅威モデル）

| 混入経路 | 例 | 検知 | 止める場所 |
|---|---|---|---|
| 脆弱な依存 | Electron 31 の既知CVE、`tar` のパストラバーサル | OSV-Scanner / Dependabot alerts | PR（新規分）・リリース（全件） |
| 悪意ある依存 | typosquat、乗っ取られたパッケージ（OSVの `MAL-*`） | OSV-Scanner（MAL は常に critical） / Dependabot cooldown 7日 | 同上 |
| 危険なコードパターン | `nodeIntegration: true`、未検証URLでの `shell.openExternal`、`eval`、`innerHTML` | Semgrep（registry + 自前Electronルール） | PR（新規分）・リリース（全件） |
| シークレットの混入 | APIキー・トークンのコミット | Gitleaks（PRは差分コミット、週次/リリースは全履歴） | PR・リリース |
| CI自体の改ざん | AIがテストを通すためにゲートや例外を書き換える | ベース側ゲートで判定、`.github/` `.security/` 変更をPRサマリで警告、CODEOWNERS | PR |
| AIエージェントの暴走 | 範囲外のファイル変更、テスト内からのキー持ち出し | パッチガード（パス・内容の機械検査）、ジョブ分離 | AI提案PRの作成前 |
| 未検証の成果物公開 | ローカルビルドをそのままSteamへ | リリースは main 上のタグ＋ゲート通過時のみ | リリース |

## 3. 全体構成

```
                  ┌──────────────── reusable-security-scan.yml ────────────────┐
 PR / merge queue │ context ─┬─ osv       (lockfile; PR時はbaseとの差分)        │
 push main        │          ├─ semgrep   (PR時は --baseline-commit で新規のみ)  │──► gate.mjs ──► 🛑/✅
 weekly (Mon)     │          └─ gitleaks  (PR時はPRのコミットのみ / 他は全履歴)   │    (fail-closed,
 tag v*           └─────────────────────────────────────────────────────────────┘     exceptions適用)

 security.yml        PR・main・merge_group → 必須ステータスチェックでマージをブロック
 release.yml         tag → preflight(main上か/version一致) → security(full) → build(win) → draft release
 security-weekly.yml 週次 full scan → Issue更新 / npm audit fix PR / AIテスト生成（任意）
 ai-security-audit   手動実行のAIテスト生成
 dependabot.yml      依存とActionsの更新PR（cooldown付き）＋脆弱性アラート
```

### ファイル一覧

**このリポジトリ（中央）**

| パス | 役割 |
|---|---|
| `.github/workflows/reusable-security-scan.yml` | 共通スキャン本体（OSV / Semgrep / Gitleaks → ゲート） |
| `.github/workflows/reusable-security-report.yml` | 週次の `security-report` Issue 更新 |
| `.github/workflows/reusable-deps-fix.yml` | 週次の lockfile 修正PR |
| `.github/workflows/reusable-ai-security-tests.yml` | AI監査エージェント（3ジョブ分離） |
| `.github/workflows/security.yml` | このリポジトリ自身のゲート（自己適用） |
| `security/gate.mjs` | 判定ロジック（依存ゼロのNode） |
| `security/install-scanners.sh` | スキャナのバイナリをSHA256検証付きで導入 |
| `security/semgrep/electron.yml` | 自前ルール（Electron hardening・動的コード実行） |
| `security/guard-ai-patch.mjs` | AI出力パッチの機械検査 |
| `security/ai-audit-prompt.md` | AIエージェントへの指示（出力契約）。リポジトリ固有の補足は各リポジトリの `.security/ai-audit-context.md` |
| `templates/` | 各リポジトリに入れる呼び出し側一式 |
| `examples/release-electron-windows.yml` | Electron（Windows）向けリリースの例 |
| `scripts/install.mjs` | 雛形の導入と、SHA の付け替え |

**各リポジトリ（呼び出し側）**

| パス | 役割 |
|---|---|
| `.github/workflows/security.yml` | PR / main 用（必須チェック `security / gate`） |
| `.github/workflows/security-weekly.yml` | 週次スキャン・Issue・修正PR・AIテスト |
| `.github/workflows/ai-security-audit.yml` | AIテスト生成の手動実行 |
| `.github/workflows/release.yml` | タグ起点のリリース（任意。ゲート不通過ならビルドしない） |
| `.github/dependabot.yml` / `.github/CODEOWNERS` | 依存更新・アラート／セキュリティ関連パスのレビュー必須化 |
| `.security/exceptions.json` | リポジトリ固有の例外（唯一の抑制手段） |
| `.security/ai-audit-context.md` | AIエージェント向けのリポジトリ固有メモ（任意） |
| `tests/security/` | セキュリティ回帰テスト（`npm run test:security`） |

## 4. ブロック規則

- **閾値**：`fail-on: high`（CVSS 7.0以上、Semgrep `ERROR`、Gitleaks全件、抑制ファイルの存在）。
- **重大度の対応**

  | ツール | critical | high | medium | low |
  |---|---|---|---|---|
  | OSV | CVSS ≥ 9.0、または `MAL-*`（悪意あるパッケージ） | ≥ 7.0、**スコア不明も high**（fail-closed） | ≥ 4.0 | それ未満 |
  | Semgrep | ルールの `metadata.gate-severity: critical` | `ERROR` | `WARNING` | `INFO` |
  | Gitleaks | 全件（push された時点で漏洩扱い） | | | |

- **モード**
  - `pr`：その変更が**持ち込んだもの**だけでブロック（OSVはbaseとのdiff、Semgrepは `--baseline-commit`、GitleaksはPRのコミット範囲）。既存の問題でPRが全部止まって運用が崩壊するのを防ぐ。
  - `full`（main push / 週次 / リリース）：**存在するもの全件**でブロック。リリースは「残っている危険」があれば止まる。
- **Fail-closed で止まる条件**：結果ファイル欠落、想定外の終了コード、Semgrepのルール/設定エラー、例外ファイルの不正（必須項目欠落・期限90日超）、ゲート自体のクラッシュ。

## 5. 例外運用

`.security/exceptions.json`：

```json
{
  "exceptions": [
    {
      "key": "osv:GHSA-xxxx-xxxx-xxxx:electron",
      "reason": "Electron 37 への移行PR #NN で解消予定。影響する API（xxx）は未使用",
      "expires": "2026-12-15",
      "owner": "peyangu"
    }
  ]
}
```

- `key` はゲートのサマリに出る値をそのまま使う：`osv:<ID>:<package>` / `semgrep:<rule-id>:<path>` / `gitleaks:<fingerprint>` / `bypass-file:<path>`。
- `reason` と `expires`（YYYY-MM-DD、**今日から90日以内**）は必須。期限切れは自動で効かなくなり再びブロックする。
- 使われていない例外はサマリで警告 → 消す。
- 例外の追加は**単独のPR**で行い、理由を本文に書く（AIエージェントにはこのファイルを触らせない。ガードで拒否される）。

## 6. AI監査エージェント（セキュリティテスト生成）

エージェントは「便利だが信用しない部品」として扱う。

| ジョブ | 権限 | シークレット | やること |
|---|---|---|---|
| `generate` | contents: read | ANTHROPIC_API_KEY | Claude（既定 `claude-opus-5-5`）が週次スキャン結果とコードを読み、`tests/security/**/*.ts` にテストを書く。**Bash・Web は禁止**。出力は全差分をパッチ化 |
| `verify` | contents: read | なし | ガード（パス・ファイルモード・`child_process`/ネットワーク/`process.env`/動的コード等を拒否）→ 適用 → `npm ci --ignore-scripts` → テスト実行。キャッシュ無効 |
| `propose` | contents/pull-requests: write | （App鍵） | エージェントのコードは実行しない。再ガード → PR作成。失敗テストがあれば `[VULN?]` の draft PR |

- テストが**落ちる＝脆弱性の可能性**。`// VULN:` コメントで影響を説明させる。アサーションを弱めて通すのは禁止（プロンプト＋レビューチェックリスト）。
- 有効化：リポジトリ変数 `AI_SECURITY_AUDIT=true`、シークレット `ANTHROPIC_API_KEY`。モデルは変数 `AI_AUDIT_MODEL` で変更可（コスト重視なら `claude-sonnet-5-5` など）。
- ガードはパッチを「間引かない」。範囲外が1つでもあれば全体を捨てる（暴走を見える化するため）。

## 7. 週次スキャンと修正PR

毎週月曜 09:17 JST：

1. `full` スキャン（コード変更がなくても新しい advisory は毎週出る）。
2. `security-report` ラベルの Issue を更新（ブロック中なら一覧、クリーンなら close）。
3. `npm audit fix --package-lock-only --ignore-scripts` で**lockfileのみ・semver互換のみ**の修正PR（install script は実行しない。メジャー更新は Dependabot か手作業）。
4. （有効時）AIテスト生成 → PR。

> **重要**：`GITHUB_TOKEN` で作ったPRでは他のワークフローが起動しない＝**そのPRのゲートが走らない**。
> GitHub App（推奨）を作り、`SECURITY_BOT_APP_ID`（変数）と `SECURITY_BOT_PRIVATE_KEY`（シークレット）を設定すること。トークンは `contents`/`pull-requests` の書き込みに絞って発行している。

## 8. 初期セットアップ手順（リポジトリごと）

呼び出し側を入れる（security-ci を clone した場所で）：

```bash
node scripts/install.mjs ../<repo>             # templates/ を入れて、今の HEAD の SHA に固定
node scripts/install.mjs ../<repo> --release   # Electron(Windows) のリリース例も入れる
node scripts/install.mjs ../<repo> --update    # security-ci を更新した後、SHA だけ付け替える
```

`uses: …@<sha>` と `toolkit-ref: <sha>` は必ず同じ SHA にそろえる（スクリプトが両方書き換える）。Dependabot はこの2か所を片方しか更新できないので、テンプレートの `dependabot.yml` で security-ci を対象外にしてある。

GitHub 設定（UIで1回だけ）：

1. **Settings → Code security**：Dependabot alerts / Dependabot security updates / Secret scanning + **Push protection** / Private vulnerability reporting を ON。
2. **Settings → Rules → Rulesets（main）**：
   - Require a pull request（直接 push 禁止）、Require status checks：`security / gate`（+ 既存のビルド系）
   - Require review from Code Owners（`.github/` `.security/` `electron/` などに効く。※自分のPRは自分で承認できないので、個人開発では「bypass は自分だけ・使ったら理由をPRに書く」運用）
   - Block force pushes
3. **Rulesets（tags `v*`）**：作成・削除を自分だけに制限（release.yml の起点を守る）。
4. **Settings → Actions → General**：Workflow permissions を *Read repository contents* に。App を使わない場合のみ *Allow GitHub Actions to create and approve pull requests* を ON。
5. 変数／シークレット：`SECURITY_BOT_APP_ID`・`SECURITY_BOT_PRIVATE_KEY`（推奨）、`AI_SECURITY_AUDIT`・`ANTHROPIC_API_KEY`・`AI_AUDIT_MODEL`（任意）。

導入直後の初回トリアージ：

1. `security-weekly` を手動実行（workflow_dispatch）→ Issue に全件が出る。
2. 修正できるもの → 修正PR。すぐ直せないもの → 期限付き例外（理由に「いつ・何で直すか」）。
3. 例外が 0 件に近づくまで毎週 Issue を見る。

## 9. 適用先

| リポジトリ | 状態 |
|---|---|
| `DERELICT` | 初回適用中（初回スキャン結果は DERELICT の `docs/SECURITY_CI.md`） |

## 10. ロードマップ

### Phase 0 — 本変更（済）
- [x] Dependabot（npm / Actions、cooldown、グルーピング）
- [x] OSV-Scanner / Semgrep / Gitleaks の共通 reusable workflow、fail-closed ゲート
- [x] PR は新規分・main/週次/リリースは全件でブロック、リリースはゲート通過必須
- [x] 期限付き例外、インライン抑制の無効化、抑制ファイルの検知
- [x] AI監査エージェント（3ジョブ分離・パッチガード）とセキュリティ回帰テストの土台
- [x] 週次スキャン → Issue / lockfile 修正PR

### Phase 1 — 安定化（〜2週間）
- [ ] GitHub 設定（§8）を適用し、`security / gate` を必須チェック化
- [ ] 初回トリアージ：`openExternal` の URL 許可リスト化、`npm audit fix`、Electron/electron-builder/Vite のメジャー更新計画、残りは期限付き例外
- [ ] GitHub App を作成して自動PRでもゲートが走るようにする
- [ ] ワークフロー自体の静的解析（`zizmor` / `actionlint`）をゲートに追加（AIが書いた workflow の injection・権限過大を止める）
- [ ] Electron 専用スキャナ（Doyensec Electronegativity）の追加検討

### Phase 2 — 全リポジトリ共通化（〜1か月）
- [x] 中央リポジトリ `peyangu/security-ci` を作成し、`reusable-*.yml` と判定スクリプトを移設。**呼び出し側はSHA固定**
- [x] 各リポジトリは短い caller（`security.yml` / `security-weekly.yml` / `ai-security-audit.yml` / 任意で `release.yml`）と `.security/` だけ持つ
- [x] 中央リポジトリ自体に同じゲートを適用（自己適用）
- [ ] 中央リポジトリに ruleset（PR必須・`security / gate` 必須・force push 禁止）
- [ ] 導入・SHA付け替えスクリプトに加えて、新規リポジトリ用テンプレートリポジトリ化
- [ ] 言語別プリセット（Node/TS・Python・Go）を `semgrep-configs` の既定値として用意
- [ ] スキャナのバージョン更新を Renovate の regex manager で自動PR化（`install-scanners.sh` の version+sha）

### Phase 3 — サプライチェーンと公開物（〜3か月）
- [ ] SBOM（CycloneDX）をリリースに添付、OSV でリリース済みSBOMを週次再スキャン
- [ ] `actions/attest-build-provenance` によるビルド来歴（SLSA provenance）と成果物ハッシュの公開
- [ ] Windows コード署名（署名鍵は Environment＋必須レビューで保護）
- [ ] リリース用 Environment（手動承認ゲート）と Steam アップロードの自動化（未署名・未attest の成果物は拒否）
- [ ] OpenSSF Scorecard の週次実行

### Phase 4 — AIエージェントの成熟（継続）
- [ ] PR ラベル（例 `ai-audit`）起動での差分限定テスト生成（コスト上限付き）
- [ ] ブロック中の Semgrep 指摘に対する**修正案PR**生成（テスト先行：AIが書いたテストが落ちる→修正PRで通る、を機械検証）
- [ ] AI生成テストの品質指標（ミューテーションテストで「本当に検知できるか」を測る）
- [ ] エージェントの実行ログ（ツール呼び出し）を artifact として保存・監査

### 運用KPI（月1で見る）
| 指標 | 目標 |
|---|---|
| 未解決 critical の滞留 | 7日以内に修正 or 例外 |
| 未解決 high の滞留 | 30日以内 |
| 有効な例外数 | 減少傾向、期限切れ 0 |
| ゲートを bypass したマージ | 0（あれば理由を記録） |
| 週次ジョブの失敗（スキャナエラー） | 0 |

## 11. 既知の限界

- 判定ロジックとルールは中央にあり PR から書き換えられないが、**呼び出し側のワークフロー**（`security.yml` など）は各リポジトリにあるので、PR でそれ自体を消す・別の参照先に向けることはできる。`.github/` 変更の警告と CODEOWNERS で緩和している。根本対策は GitHub の組織向け「必須ワークフロー」だが、個人アカウントでは使えない。
- Semgrep のパターンマッチは意味を理解しない。`openExternal` の「URLに触れる if があれば検証済み」とみなす等、ヒューリスティックがある。
- 個人開発では Code Owner レビューを自分で満たせない。bypass は可能だが、使った事実が残るようにする。
- OSV の CVSS は「到達可能性」を考慮しない。dev 依存・未使用コードパスでもブロックする（意図的に保守側）。判断は例外の `reason` に書く。
- `npm audit fix` は npm の advisory DB、ゲートは OSV を見るため、件数が一致しないことがある。
