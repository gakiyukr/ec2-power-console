**本程序所有程式碼均爲 Codex 編寫，本項目純屬自用，如想要開發新功能請自行 fork 咨詢 AI。**

# EC2 Workers Web Console
這是一個部署在 Cloudflare Workers 上的簡易網頁控制台，用來管理 AWS EC2 實例。

它適合這種情境：

- 想用網頁而不是命令列操作 EC2
- 想集中管理多個地區、多台機器
- 想查看目前狀態與 `Public IPv4 DNS`
- 想快速執行 `開機 / 關機`

## 主要功能

- 密碼登入保護
- 支援多個 AWS 地區
- 支援每個地區多台 EC2
- 頁面按地區分組顯示
- 可手動刷新所有機器狀態
- 可對單台機器執行開機與關機

## 使用前準備

在部署之前，你需要準備：

- 一個 Cloudflare 帳號
- 一組可操作 EC2 的 AWS 金鑰（建議使用 IAM 策略限制權限範圍）
- 你要管理的 EC2 實例 ID
- 對應的 AWS 地區
- Node.js 與 npm

**AWS IAM 最小權限建議**：

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:StartInstances",
        "ec2:StopInstances"
      ],
      "Resource": "arn:aws:ec2:*:*:instance/*",
      "Condition": {
        "StringEquals": {
          "ec2:ResourceTag/ManagedBy": "ec2-power-console"
        }
      }
    }
  ]
}
```

建議在你的 EC2 實例上添加標籤 `ManagedBy=ec2-power-console` 以限制操作範圍。

## 先設定要管理的機器

請打開 [src/index.js](C:/Users/gakiyukr/Documents/Codex/2026-05-27/aws-ec2-ip/src/index.js)，修改最上方的 `TARGETS` 清單。

格式如下：

```js
const TARGETS = [
  { region: "us-west-2", instanceId: "i-0123456789abcdef0", name: "SEA-1" },
  { region: "ap-northeast-1", instanceId: "i-0fedcba9876543210", name: "TOKYO-1" }
];
```

欄位說明：

- `region`：必填，AWS 地區
- `instanceId`：必填，EC2 實例 ID
- `name`：可選，你想在頁面上顯示的名稱

如果你不填 `name`，系統會自動用其他資訊補上顯示名稱。

## 設定環境變量

### 本地開發

1. 複製環境變量範例文件：

```bash
cp .env.example .env
```

2. 編輯 `.env` 文件，填入實際值：

```bash
# 應用密碼 - 用於登入網頁控制台
APP_PASSWORD=your-strong-password-here

# Session 簽名密鑰 - 建議使用強隨機字符串（至少 32 字符）
# 可以用以下命令生成: openssl rand -base64 32
SESSION_SECRET=your-long-random-string-at-least-32-chars

# AWS 憑證
AWS_ACCESS_KEY_ID=YOUR_AWS_ACCESS_KEY
AWS_SECRET_ACCESS_KEY=YOUR_AWS_SECRET_KEY
```

### 生產環境部署

正式部署到 Cloudflare Workers 時，請使用 `wrangler secret` 命令安全地設置環境變量：

```bash
wrangler secret put APP_PASSWORD
wrangler secret put SESSION_SECRET
wrangler secret put AWS_ACCESS_KEY_ID
wrangler secret put AWS_SECRET_ACCESS_KEY
```

執行每個命令後，系統會提示你輸入對應的值。這些值會加密存儲在 Cloudflare 中，不會出現在代碼或配置文件裡。

**環境變量說明**：

- `APP_PASSWORD`：登入網頁時要輸入的密碼（建議使用強密碼）
- `SESSION_SECRET`：用來簽名和驗證登入 session 的密鑰（建議至少 32 字符的隨機字符串）
- `AWS_ACCESS_KEY_ID`：AWS Access Key
- `AWS_SECRET_ACCESS_KEY`：AWS Secret Key

**安全提醒**：
- 切勿將 `.env` 文件提交到版本控制系統
- `SESSION_SECRET` 應該使用加密學安全的隨機字符串
- 定期輪換 AWS 憑證
- 使用 IAM 策略限制 AWS 憑證的權限範圍

## 部署方式

如果你還沒有安裝 Wrangler，可以先安裝：

```text
npm install -D wrangler
```

接著登入 Cloudflare：

```text
npx wrangler login
```

然後部署：

```text
npx wrangler deploy
```

部署完成後，你會拿到一個 Worker 網址。直接用瀏覽器打開它即可。

## 使用方式

1. 打開 Worker 網址
2. 輸入你設定的 `APP_PASSWORD`
3. 首頁會先列出你在 `TARGETS` 裡設定的機器清單
4. 頁面初始狀態不會自動查 AWS，所以會先顯示占位內容
5. 按 `全部刷新` 後，頁面才會去抓取各機器目前狀態與 `Public IPv4 DNS`
6. 你可以對單台機器執行：
   - `開機`
   - `關機`

## 目前行為說明

- 頁面會按地區分組顯示機器
- `全部刷新` 會按地區批量查詢 AWS，避免每台機器各打一個請求
- 每台機器也有自己的操作按鈕
- 如果你新增、刪除或修改機器，請更新 `TARGETS` 後重新部署

## 注意事項

- 這個專案把機器清單寫在代碼裡，不是從 AWS 自動發現
- 真正需要保密的是 Cloudflare secrets，不是實例 ID
- 如果 AWS 金鑰曾經外洩，請立刻輪換

## 安全特性

本項目實現了以下安全措施：

- ✅ **Session 安全**：使用 HMAC-SHA256 簽名，24 小時自動過期
- ✅ **防時序攻擊**：使用恆定時間比較驗證簽名
- ✅ **登入速率限制**：基於 IP 的失敗登入限制（5 次失敗後封鎖 15 分鐘）
- ✅ **安全 Cookie**：HttpOnly、Secure、SameSite=Strict 屬性
- ✅ **內容安全策略**：CSP headers 防止 XSS 攻擊
- ✅ **輸入驗證**：只允許操作預先配置的 EC2 實例
- ✅ **HTML 轉義**：防止注入攻擊
- ✅ **記憶體管理**：定期清理過期的登入失敗記錄

## 本機檢查

如果你在本地修改了程式，可以用下面兩個命令檢查：

```text
npm test
node --check src/index.js
```
