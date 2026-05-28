**本程序所有程式碼均爲 Codex 編寫，本項目純屬自用，如想要開發新功能請自行 fork 咨詢 AI。**

# EC2 Workers Web Console
這是一個部署在 Cloudflare Workers 上的簡易網頁控制台，用來管理 AWS EC2 實例。

它適合這種情境：

- 想用網頁而不是命令列操作 EC2
- 想集中管理多個地區、多台機器
- 想查看目前狀態與 `Public IPv4 DNS`
- 想快速執行 `開機 / 關機 / 重新啟動`

## 主要功能

- 密碼登入保護
- 支援多個 AWS 地區
- 支援每個地區多台 EC2
- 頁面按地區分組顯示
- 可手動刷新所有機器狀態
- 可對單台機器執行開機、關機與重新啟動

## 使用前準備

在部署之前，你需要準備：

- 一個 Cloudflare 帳號
- 一組可操作 EC2 的 AWS 金鑰
- 你要管理的 EC2 實例 ID
- 對應的 AWS 地區
- Node.js 與 npm

AWS 金鑰至少需要能呼叫這些 EC2 API：

- `DescribeInstances`
- `StartInstances`
- `StopInstances`

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

## 設定 Cloudflare Secrets

部署前請先設定這 4 個 secrets：

```text
wrangler secret put APP_PASSWORD
wrangler secret put SESSION_SECRET
wrangler secret put AWS_ACCESS_KEY_ID
wrangler secret put AWS_SECRET_ACCESS_KEY
```

它們的用途如下：

- `APP_PASSWORD`：你登入網頁時要輸入的密碼
- `SESSION_SECRET`：用來保護登入 session 的簽名密鑰
- `AWS_ACCESS_KEY_ID`：AWS Access Key
- `AWS_SECRET_ACCESS_KEY`：AWS Secret Key

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
   - `重新啟動`

## 目前行為說明

- 頁面會按地區分組顯示機器
- `全部刷新` 會按地區批量查詢 AWS，避免每台機器各打一個請求
- 每台機器也有自己的操作按鈕
- 如果你新增、刪除或修改機器，請更新 `TARGETS` 後重新部署

## 注意事項

- 這個專案把機器清單寫在代碼裡，不是從 AWS 自動發現
- 真正需要保密的是 Cloudflare secrets，不是實例 ID
- 如果 AWS 金鑰曾經外洩，請立刻輪換
- 目前 `重新啟動` 比較接近「先送出停止流程」，之後請手動刷新並視情況再次開機

## 本機檢查

如果你在本地修改了程式，可以用下面兩個命令檢查：

```text
npm test
node --check src/index.js
```
