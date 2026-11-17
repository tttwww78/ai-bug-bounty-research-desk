# AI 漏洞赏金研究台（Windows）

这是一个本地研究工作台，帮助新手把“学会一个安全知识点”变成“留下可复核的研究记录”。AI 负责整理资料、提出待验证假设和帮忙写报告；授权判断、目标侧操作、漏洞确认和最终提交都由你本人负责。

## 新手三步

1. **先登录并确认授权**：你在自己的浏览器登录补天并选择项目，然后把项目规则链接、精确域名、允许路径和规则中关于频率/禁止行为的文字填进第 1 步。研究台不接管浏览器；范围没弄清就停在这里。没有补天项目时可选择 PortSwigger 官方练习。
2. **再分析资料**：仅导入已脱敏的 HAR、Burp XML、OpenAPI JSON 或必要的 Spring Controller 源码。下载提示词，粘贴给豆包、WorkBuddy、ChatGPT 或你常用的 AI；工具只提取元数据/静态注解，AI 输出是待验证线索，不是漏洞结论。
3. **最后人工复现和整理**：只在明确允许的范围内，用自己控制的测试账号或本地靶场验证。记录预期/实际结果和脱敏证据；本人再次核对规则后，手动提交平台。

想先练习再碰真实项目：从 [PortSwigger Web Security Academy](https://portswigger.net/web-security) 的免费交互实验开始；也可以在本机隔离环境运行 [OWASP Juice Shop](https://github.com/juice-shop/juice-shop)。这些是练习环境，不会自动授权你测试其他网站。

在应用第 1 步选择“PortSwigger 官方练习实验”后，先打开一个练习，把实验页面的完整 HTTPS 地址粘贴进去。应用只接受精确的 `*.web-security-academy.net` 实验主机并保存具体主机名，不会扫描。选择“本地靶场”只登记你已经运行的本机环境，不会自动安装或启动 Juice Shop。

打开后左侧只有“开始、三步流程、提交记录、帮助”六个入口；首页会显示进度和建议的下一步。第 1 步优先登记补天授权项目，也可选 PortSwigger 练习、本地靶场或其他官方项目。**本地靶场选项只登记你自己的环境，不会替你安装或启动靶场。**

## 运行

需要 Windows、Python 3.11 和网络连接（首次安装依赖时）。把 ZIP 解压到有可用空间的磁盘，双击 `run_windows.bat`，浏览器打开 `http://127.0.0.1:8501`。服务仅绑定本机回环地址；临时文件、依赖缓存和虚拟环境都放在解压目录，不占系统临时目录。

也可手动运行：

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py --server.address 127.0.0.1
```

数据默认放在 `data/`：SQLite 台账、截图证据和导入记录。该目录没有加密；不要把数据库、证据或 `.streamlit/secrets.toml` 上传到公开仓库/网盘。

如果系统盘空间不足，可在 PowerShell 设置数据目录后从同一个窗口启动：`$env:AI_BUG_BOUNTY_DATA_DIR = 'F:\BugBountyData'`，然后运行 `.\run_windows.bat`。

## 能做与不能做

- 管理授权范围和规则链接；导入 HAR、Burp XML、OpenAPI JSON、Java Controller。
- HAR/Burp 仅保留请求元数据；查询参数中像凭据、账号和个人信息的值会脱敏，URL 路径里的 UUID/长数字会替换。Java 源码只在内存中提取注解，不写入磁盘。
- 用 AI 分析项目资料，维护线索、人工验证状态、报告草稿、截图和提交/奖励台账。
- 补天登录和选项目在你自己的浏览器中完成；研究台只保存你手工填写并确认的规则信息。
- 可选一次 HTTPS HEAD 可达性检查：必须再次勾选确认；只允许精确主机名和 443 端口，不接受查询参数，不带 Cookie/Token，不跟随重定向。
- **不提供目标扫描、目录爆破、口令测试、漏洞利用、第三方数据读取或自动提交。**AI 只分析你导入的脱敏资料和你确认填写的项目规则。

填写授权项目时，路径规则只支持 `/api`、`/api/*` 这类形式；复杂或不清楚的规则会拒绝执行。空白路径代表你确认了整个精确域名都在范围内。程序无法替你核对官方规则；勾选框只是你的确认记录。

可选 AI API 调用会把当前项目的规则摘要、域名、接口清单和线索发给你填写的服务商；API Key 也会通过 HTTPS `Authorization` 请求头发送给该服务，但不写入本地数据库。远程 API 必须使用 HTTPS；本机模型可用本地 HTTP 地址。调用前必须勾选发送确认。不要放入密码、Cookie、Token、真实账号数据或不应外传的代码。

## 研究记录质量

每条线索都应留下：授权来源、观察事实、推断、未知项、误报可能、人工验证步骤、预期结果、实际结果和脱敏证据。AI 置信度不代表严重度或漏洞成立。平台奖励以官方当前规则和实际审核/到账状态为准，不从短视频宣传数字推算收入。

## 参考资料

- [OWASP Web Security Testing Guide（WSTG）](https://github.com/OWASP/wstg)：测试方法参考；引用测试项时应带版本号。
- [OWASP API Security Top 10](https://owasp.org/API-Security/)：接口安全风险分类参考。
- [OWASP ASVS](https://github.com/OWASP/ASVS)：验证要求参考，稳定版目前为 5.0.0。
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)：免费课程和交互实验。
- [OWASP Juice Shop](https://github.com/juice-shop/juice-shop)：故意包含漏洞的本地训练应用。

## 安全与隐私

- 只按项目官方当前规则操作；规则变更后先更新本地记录。
- API 调用是显式选择的第三方数据传输，不应将本地软件理解成数据不会离开电脑。
- 截图和数据库可能包含敏感信息；先脱敏、最小化保存并自行备份。
- HEAD 检查只是可达性检查，不代表目标存在漏洞，也不会验证漏洞。
- 本工具不能替代法律意见、平台政策或人工复现。
