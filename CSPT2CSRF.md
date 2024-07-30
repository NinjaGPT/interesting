# Exploiting Client-Side Path Traversal
### CSRF is dead, long live CSRF
#### Author: Maxence Schmitt
#### Translator: Chris Z
---
***第1页***

# 客户端路径遍历漏洞利用
### CSRF已死，CSRF万岁

#### 作者: Maxence Schmitt
#### 翻译：Chris Z
#### 原文: https://www.doyensec.com/resources/Doyensec_CSPT2CSRF_Whitepaper.pdf

---
***第2页***

```
目录：
Abstract (概念)                 -- 03页
Introduction (介绍)             -- 04页
Results (结果)                  -- 09页
Practical Outcome (实际成果)     -- 13页
Recommendations (修复建议)       -- 28页
Burp Suite Extension (Burp扩展) -- 32页
Conclusion (总结)               -- 35页
References (参考)               -- 36页
```
---
***第3页***


***ABSTRACT (概念)***

为了为用户提供更安全的浏览体验，IETF 提议的“逐步改进的 Cookies”引发了一些重要的变化，以解决跨站请求伪造（CSRF）和其他客户端问题。不久之后，Chrome 和其他主要浏览器实施了推荐的更改并引入了 SameSite 属性。安全研究人员可能会认为实施了 CSRF 令牌和这些保护措施的应用程序可以免受 CSRF 攻击。
在本文中，我将介绍如何利用客户端路径遍历（CSPT）来执行 CSRF（CSPT2CSRF），即使已经实施了所有行业最佳实践的 CSRF 保护措施。这项工作是对 CSPT 和 CSRF 进行了广泛研究的结果；我们将讨论理论和实际方面的内容，并介绍一些影响主要网络产品的漏洞。
这篇技术白皮书与一个 Burp Suite 插件一起发布，以帮助您发现和利用 CSPT2CSRF。

---
***第4页***

***INTRODUCTION (介绍)***

---

***第5页***

<img width="522" alt="image" src="https://github.com/user-attachments/assets/2cc6c43f-d8f1-4012-9372-8938ebd874eb">

### Client-Side Path Traversal (CSPT) 定义

每个安全研究人员都应该了解什么是路径遍历漏洞。这种漏洞使攻击者能够使用像 ../../../../ 这样的`payload`读取目标目录之外的数据。与读取服务器文件的服务器端路径遍历攻击不同，客户端路径遍历攻击则专注于利用这种弱点向意图之外的 API 端点发出请求。尽管这类漏洞在服务器端非常流行，但客户端路径遍历的案例却很少被广泛公开。我们发现的第一个参考资料是 Philippe Harewood 在 Facebook 漏洞赏金计划中报告的一个漏洞。从那时起，我们只发现了少数有关客户端路径遍历的参考资料：
```
➧ Sam Curry 在 2021 年发布的一条推文
➧ Johan Carlsson 在 GitLab 中发现的一键 CSRF 漏洞
➧ Medi 发现的 CSS 注入漏洞，被提名为 2022 年 Portswigger 十大 Web 黑客技术之一
➧ Antoine Roly 发现的 CSRF 漏洞
```
除了 OWASP 关于客户端 CSRF 的参考资料，我们还找到了 Soheil Khodayari 和 Giancarlo Pellegrino 的一篇研究论文。

这些案例和研究表明，虽然客户端路径遍历漏洞相对不常见，但它们仍然构成了严重的安全风险，值得进一步关注和研究。
```
1 https://www.facebook.com/notes/996734990846339/
2 https://x.com/samwcyo/status/1437030056627523590
3 https://gitlab.com/gitlab-org/gitlab/-/issues/365427
4 https://mr-medi.github.io/research/2022/11/04/practical-client-side-path-traversal-attacks.html
5 https://portswigger.net/research/top-10-web-hacking-techniques-of-2022
6 https://erasec.be/blog/client-side-path-manipulation/
7
https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#deali ng-with-client-side-csrf-attacks-important
8 https://www.usenix.org/system/files/sec21-khodayari.pdf
```
---
***第6页***

***描述***


如今，具有后端 API 和动态前端（如 React 或 Angular）的 Web 应用程序架构已经很常见。
<img width="956" alt="image" src="https://github.com/user-attachments/assets/c9b1b4c3-4c59-43b2-b1d9-c87953b0a8fa">


在这种情况下，控制 `{USER_INPUT}` 值的攻击者可以执行路径遍历，将受害者的请求路由到另一个端点。

<img width="961" alt="image" src="https://github.com/user-attachments/assets/00e3b638-1ff9-457d-b2ff-ad5bf62dcb56">

攻击者可以迫使受害者执行这个意外的请求。这就是客户端路径遍历（CSPT）的起点。客户端路径遍历可以分为两部分。source是 CSPT 的触发点，而sink是可以通过这个 CSPT 到达的可利用端点。

---
***第7页***

为了理解我们如何使用 CSPT 作为攻击向量，必须定义污染源(source)和污染汇(sink)。

### SOURCE

Source是代表受害者触发 HTTP 请求的动作。我们预期攻击者控制一个输入以执行 CSPT。这个输入必须反映在后续 HTTP 请求的路径部分，以便定位未预期的端点。
由于这是一个客户端漏洞，这样的源可以采取任何形式，不同类型的 CSPT 包括：
```
➧ 反射型：page?id=XXXXXXXX
➧ 基于DOM：page#id=XXXXXXXXX 或任何从 DOM 可访问的数据（例如URL路径）
➧ 存储型：从数据库读取的输入
```
由于我们预期前端会触发另一个调用，我们可以假设源页面的内容类型为 text/html。有时触发 CSPT 可能会很复杂，需要用户交互。根据我们的经验，1-click CSPT 漏洞是最常见的类型。

### SINK

由于我们正在重新路由合法的 API 请求，攻击者只能控制 HTTP 请求的路径。例如：
```
➧ Host:    如果source正在访问 api.doyensec.com 后端，你将无法定位到另一个主机。
➧ HTTP方法: 通过 CSPT 你无法改变请求的 HTTP 方法。然而，完全有可能找到使用 GET、POST、PATCH、PUT 或 DELETE 方法的汇。
➧ Headers： source可以添加后端所需的一些附加头部信息（例如，CSRF Token和身份验证Token）。
➧ 请求体Body：source可能在请求中包含请求体内容。CSPT 无法控制请求体内容，除非请求体内容基于其他用户输入。
```
sink是一个可到达的端点，具有相同的限制条件。它将定义攻击者可以利用关联source执行的操作。确实，在同一个应用程序中，有可能找到另一个 CSPT source，例如，具有不同的 HTTP 方法或不同的请求体内容，因此会产生不同的影响。

假设source发送以下 JSON 数据：


<img width="388" alt="image" src="https://github.com/user-attachments/assets/f83ee300-01de-4aa6-be2a-ad63efb87db6">

---
***第8页***

在这种情况下，只有接受这些数据的端点才会被视为可到达的sink, 常见的绕过此限制的方法：
```
➧ 如果后端在接受额外的 JSON 参数方面比较宽松，那么任何不需要 user_id、channel_id 或 post_root_id 参数的端点仍然会被执行。根据我们的经验，大多数 API 并不强制执行严格的 JSON 架构，即使存在额外的参数也会处理请求。
➧ 由于我们可以控制请求路径，在大多数情况下，我们可以控制source发送的查询参数。在这种情况下，我们可以添加会被后端读取的参数。注意：使用这些查询参数，可能覆盖请求体内容中定义的参数。
```
一旦识别出所有sink的限制条件，所有满足这些要求的可到达端点都可以被列出，并且可以定义 CSPT 的影响。可以通过手动从文档中、从 JavaScript 代码中或使用 Burp Suite 的 Bambda 功能来列出所有的sink。


---
***第9页***

***RESULTS (结果)***

---
***第10页***

### CSPT的利用

攻击者可以迫使受害者在选择的端点上触发 HTTP 请求。即使有一些限制（例如Host、Method、Body、Headers），也可能被利用。在这篇白皮书中，我们将重点介绍使用客户端路径遍历（CSPT）来触发 CSRF 攻击（CSPT2CSRF）。

CSPT 重新路由合法的 HTTP 请求，前端可能会添加执行 API 调用所需的令牌（例如，身份验证Token、CSRF Token）。因此，它可以用于绕过现有的防护措施来防止 CSRF 攻击。如果攻击者能够找到有影响的sink，就可以使用 CSPT 作为攻击向量，在现代浏览器上执行 CSRF 攻击。因此，我们将这种新技术命名为 CSPT2CSRF。

***例子***

例如，假设一个管理笔记的网站。在这个例子中，终端用户可以通过访问以下 URL 来通过其 ID（例如 1337）访问特定的笔记：
```
GET /notes/draft?id=1337
```
前端自动向 API 发出以下请求以获取笔记的详细信息：

```
POST /api/v1/note/1337/details 
Host: xxx 
Authorization: Bearer <REDACTED> 
{}

```

---
***第11页***

<img width="710" alt="image" src="https://github.com/user-attachments/assets/8d9ba1d6-097e-4d63-a59c-565948ce1d43">

在这种情况下，攻击者可以执行客户端路径遍历来访问另一个 API 端点。实际上，CSPT 源如下：

```
GET /notes/draft?id=1337/../../anotherEndpoint?

```
前端读取查询参数并发出以下请求：


```
POST /api/v1/note/1337/../../anotherEndpoint?/details 
Host: www.doyensec.com 
Authorization: Bearer <REDACTED> 
CSRF-Token: <REDACTED> 
{}

```
<img width="766" alt="image" src="https://github.com/user-attachments/assets/657914fd-7a94-49f9-9783-2ed177c8d4cd">

---
***第12页***

为了确定是否可以利用此漏洞并评估其影响，我们需要识别可到达的sink。在这个例子中，所有潜在的sink必须符合以下限制：
```
➧ Host：www.doyensec.com
➧ HTTP方法：POST
➧ Headers：Authorization，CSRF-Token
➧ 请求体Body：{}
```
因此，攻击者可以使用此 CSPT 对兼容的sink执行 CSRF 攻击（CSPT2CSRF）。根据触发source和可到达sink的复杂性，发现的严重性有所不同。

### 与标准 CSRF 的区别


CSPT2CSRF 与标准 CSRF 之间存在一些区别：
```
➧ 它在现代浏览器上是可利用的。
➧ 现有的 CSRF 保护措施（例如 CSRF Token）无效。
➧ 利用受限于由source定义的兼容sink。
➧ 可以发现 GET/POST/PATCH/PUT/DELETE 类型的 CSRF。例如，DELETE CSRF 开辟了新的攻击向量（例如，调用 API 以删除管理员的 MFA）。
➧ 它可能是 1-click CSRF（即点击一个按钮/链接）。
➧ 在同一个应用程序中可以找到多个 CSPT source，导致不同的漏洞，需要不同的修复，可能获得多个赏金。
➧ 每个 CSPT2CSRF 需要描述（source和sink）以识别漏洞的复杂性和严重性。
```
---
***第13页***

***PRACTICAL OUTCOME (实际成果)***

---
***第14页***

前面的部分定义了关于 CSPT 的理论：
```
➧ 什么是 CSPT？
➧ 什么是 source？
➧ 什么是 sink？
➧ 如何利用它触发 CSPT2CSRF？
```
在本节中，我们将展示影响主要网络平台和产品的真实世界漏洞。在过去的一年中，我们能够发现许多可利用的 CSPT2CSRF，这是因为：
```
➧ 它被安全研究人员和开发人员忽视了。实际上，前端没有进行任何控制来防止 CSPT。
➧ 没有工具可以找到 CSPT 并识别可利用的 sink。
➧ CSRF 保护措施仅基于 SameSite cookies 和 CSRF Token，因此可以通过 CSPT2CSRF 绕过这些保护措施。
```
在我们今年发现的所有 CSPT2CSRF 漏洞中，本文只会描述一小部分，以展示一些知名应用程序中的不同类型的 CSPT2CSRF：
```
➧ Rocket.Chat 中带有 POST sink 的 1-click CSPT2CSRF。
➧ Mattermost 中带有 POST sink 的标准 CSPT2CSRF。
➧ Mattermost 中带有 GET sink 的更复杂的 CSPT2CSRF 利用。
```
https://www.rocket.chat/
https://mattermost.com/


---
***第15页***

### 1-click CSPT2CSRF with a POST sink 


第一个案例研究是影响 Rocket.Chat 应用程序的低严重性 CSPT2CSRF。Rocket.Chat 是一个开源的通信平台。
这个 CSPT2CSRF 的特点是一个 1-click CSPT2CSRF。目前这个问题已经修复。

### Source 描述 


当用户访问 `/marketplace/private/install?id=INJECTION&url=https://google.com` 页面时，会向他们显示一个表单。如果用户点击 `Install` 按钮，前端会读取 id 值并提交一个 `POST` 请求到 `/api/apps/INJECTION`。
<img width="1567" alt="image" src="https://github.com/user-attachments/assets/734016e6-9246-48e8-b3e0-326a388e6328">
以下代码是与该页面相关的前端实现：`https://github.com/RocketChat/Rocket.Chat/blob/6.5.8/apps/meteor/client/views/marketplace/AppInstallPage.js`
```javascript
const appId = useSearchParameter('id');
const queryUrl = useSearchParameter('url');
const [installing, setInstalling] = useState(false);
const endpointAddress = appId ? `/apps/${appId}` : '/apps';
const downloadApp = useEndpoint('POST', endpointAddress);
```
这段代码从搜索参数中读取 id，并将该值连接到端点 URL。如果受害者点击 Install 按钮，请求将发送到这个端点。

攻击者可以利用这个流程，以受害者的授权在选择的端点上发出 POST HTTP 请求。这可以通过使用一个恶意的 id 值（例如 `../../../any_endpoint`）来构造一个恶意的 `endpointAddress` 来实现。

使用这个 source，可以在选择的端点上触发一个 one-click CSPT2CSRF。

---
***第16页***

### Sink 描述


由于攻击者只能控制通过 POST 请求发送的请求体参数中的 url 值，因此该问题导致了一个有限的 CSPT2CSRF。
如上所示，发送到 CSRF 端点的请求体如下：

```javascript
{
    "url": "https://google.com",
    "downloadOnly": true
}
```
后端在接受额外的 JSON 参数方面比较宽松。它没有实施严格的 JSON 结构验证。即使一个端点不需要 url 或 downloadId JSON 参数，请求仍然会被执行。后端也不允许将 JSON 参数更改为 GET 参数。

因此，有效的 CSPT2CSRF sink 需要满足以下条件：
```
➧ POST 端点
➧ 除了 url 和 downloadOnly 之外没有强制性的请求体参数
➧ 攻击者可以控制路径参数
➧ 攻击者可以传递额外的 GET 参数
```
以下是非详细的可能的 sink 列表：
```
➧ /api/v1/livechat/department/:id/unarchive
➧ /api/v1/livechat/department/:id/archive
➧ /api/v1/dns.resolve.txt?url=open.rocket.chat
➧ /api/v1/users.logoutOtherClients
➧ /api/v1/users.2fa.enableEmail
```
以下是使用 CSPT2CSRF 使受害者注销的无害 POC：

受害者访问：
```
/marketplace/private/install?id=../../../api/v1/users.logoutOtherClients&url=https://google.com
```
受害者点击 `Install`。
CSPT2CSRF 将 HTTP 请求发送到所需的端点。

---
***第17页***

<img width="1230" alt="image" src="https://github.com/user-attachments/assets/4ef80134-7f37-4837-bb04-27694614aed2">

虽然我们能够演示一个有效的 CSPT2CSRF 漏洞，但我们认为该漏洞的严重性较低，这是由于：
```
➧ 复杂性：受害者必须被迫点击一个恶意链接并点击一个按钮
➧ 影响：已识别的可利用 sinks 并不具有很大影响
```
这个漏洞是一个简单的示例，展示了一个 1-click CSPT2CSRF。然而，这一发现难以利用且影响较低。在下一节中，我们将看到一个具有更大影响且需要更少用户交互的 CSPT2CSRF。

---
***第18页***

### CSPT2CSRF with a POST sink in Mattermost


Mattermost 是一个为团队通信和协作设计的开源平台。Mattermost 允许团队实时通信、共享文件，并在一个私密且可定制的环境中协作项目。
这是我们在 Mattermost 中发现的一个先进的 CSPT2CSRF 示例，具有一个 POST sink。漏洞标识符为 CVE-2023-45316，它影响以下版本的 Mattermost：
```
➧ <=9.2.1, <=9.1.2, <=9.0.3, <=8.1.5, <=7.8.14
```
此漏洞在以下版本中已修复：
```
➧ 9.2.2, 9.1.3, 9.0.4, 8.1.6, 7.8.15
```
### Source 描述


当用户访问以下页面时：

```
/<team>/channels/<channel>?telem_action=<action>&forceRHSOpen&telem_run_id=<telem_run_id>
```
前端会读取 `telem_run_id` 并提交一个 POST 请求到：

```
/plugins/playbooks/api/v0/telemetry/run/<telem_run_id>
```
以下代码是与此页面相关的前端实现，位于 `mattermost-plugin-playbooks` 项目中：
```
https://github.com/mattermost/mattermost-plugin-playbooks/blob/v1.39.0/webapp/src/rhs_opener.ts#L54-L64
```

```javascript
const searchParams = new URLSearchParams(url.searchParams);
if (searchParams.has('telem_action') && searchParams.has('telem_run_id')) {
    // 记录并删除telemetry
    const action = searchParams.get('telem_action') || '';
    const runId = searchParams.get('telem_run_id') || '';
    telemetryEventForPlaybookRun(runId, action);
    searchParams.delete('telem_action');
    searchParams.delete('telem_run_id');
    browserHistory.replace({
        pathname: url.pathname,
        search: searchParams.toString()
    });
}
```
`telemetryEventForPlaybookRun` 将 `playbookRunID` 值连接到路径并执行一个 POST 请求：
```
https://github.com/mattermost/mattermost-plugin-playbooks/blob/v1.39.0/webapp/src/client.ts#L489-L494
```
---
***第19页***

```javascript
export async function telemetryEventForPlaybookRun(playbookRunID: string, action:
telemetryRunAction) {
    await doFetchWithoutResponse(`${apiUrl}/telemetry/run/${playbookRunID}`, {
        method: 'POST',
        body: JSON.stringify({action}),
    });
}
```
从源代码中可以识别出一个潜在的 CSPT2CSRF。


要利用此漏洞，必须在 telem_run_id 参数中设置payload。使用这个source，攻击者能够在选定的端点上触发 CSPT2CSRF。

### Sink 描述


由于攻击者只能控制通过 POST 请求发送的请求体参数（telem_action 查询参数）的值，因此该问题导致了一个有限的 CSRF。
如上所示，发送到 CSRF 端点的请求体如下：

```javascript
{
    "action": "todo_overduestatus_clicked"
}
```
Mattermost 后端服务器在接受额外的 JSON 参数方面比较宽松。即使一个端点不需要 action 参数，请求仍然会被执行。

Mattermost 后端不允许将 JSON 参数更改为 GET 参数。因此，有效的 CSPT2CSRF sink 需要满足以下条件：
```
➧ POST 端点
➧ 除了 action 之外没有强制性的请求体参数
➧ 攻击者可以控制路径(path)参数
➧ 攻击者可以传递额外的 GET 参数
```
有影响力的 sink 可以从文档中找到，或者使用我们的 Burp Suite 插件找到。

***重现步骤***


对于一个 POC，我们将执行一个对无害 API 端点的 POST 请求：`/api/v4/caches/invalidate`

***前提条件：***
```
➧ 受害者必须以系统管理员身份登录
```
---
***第20页***


1.受害者访问以下链接：
```
http://localhost:8065/doyensec/channels/channelname?telem_action=under_control&forceRHSOpen&telem_run_id=../../../../../../api/v4/caches/invalidate
```
通过这个链接，受害者会触发一个 CSPT2CSRF 漏洞，发送一个 POST 请求到 `/api/v4/caches/invalidate`，利用 telem_run_id 参数进行路径遍历。
<img width="1403" alt="image" src="https://github.com/user-attachments/assets/b00d9d77-786b-4743-ad60-3b9f149d10b9">

2. 观察到发送到目标端点 `api/v4/caches/invalidate` 的 HTTP POST 请求，验证 CSPT2CSRF

<img width="1238" alt="image" src="https://github.com/user-attachments/assets/6d7e99a8-05dd-401f-ac58-f5bb125bfb60">

### 找到另一个可以利用的 sink 以实现 RCE（远程代码执行）

本地部署的 Mattermost 实例提供了从 URL 部署插件的功能。该端点的定义如下，可以在这里找到：
```
https://api.mattermost.com/#tag/plugins/operation/InstallPluginFromUrl
```


---
***第21页***

![image](https://github.com/user-attachments/assets/a8b0972b-f0e6-4c97-b09e-4a0ef99dd5cb)

这个端点与我们的 sink 兼容，因为：
```
➧ 它是一个 POST 请求
➧ 可以使用路径遍历添加 plugin_download_url 查询参数
➧ 后端在接受额外的请求体参数方面比较宽松
```
攻击者可以利用它上传一个恶意插件并在 Mattermost 服务器上获得 RCE（远程代码执行）。


***注意 1***：插件默认不会启用，但存在另一个兼容的 sink 来启用插件（`POST http://your-mattermost-url.com/api/v4/plugins/{plugin_id}/enable`）。

***注意 2***：`install_from_url` 端点在云实例上不可用，并且在本地部署中可能默认未启用。

以下是其他一些具有一定影响的 sink 的非详尽列表：
```
➧ /api/v4/plugins/install_from_url
➧ /api/v4/plugins/{plugin_id}/enable
➧ /api/v4/plugins/{plugin_id}/disable
➧ /api/v4/users/{user_id}/demote
➧ /api/v4/users/{user_id}/promote
➧ /api/v4/bots/{bot_user_id}/assign/{user_id}
➧ /api/v4/restart
➧ /api/v4/oauth/apps/{app_id}/regen_secret
➧ /api/v4/elasticsearch/purge_indexes
➧ /api/v4/jobs/{job_id}/cancel
```

---
***第22页***

### CSPT2CSRF with a GET sink


***解释***


起初，不太可能出现具有 GET sink 的 CSPT2CSRF。实际上，GET 请求不应执行任何状态改变的操作。
然而，如果你的 source 发送 GET 请求以读取一些 JSON 数据，然后基于这些 JSON 数据执行操作，这种设计可能会被利用：

<img width="921" alt="image" src="https://github.com/user-attachments/assets/17c509af-e33d-4ec7-9f8f-72427e433884">


在这个例子中，如果我们能找到一个返回一些可控数据的 GET sink，我们可以制作一个恶意的 JSON 响应来控制 POST 请求。实际上，在 id 值中注入有效负载将通过 POST sink 执行 CSPT2CSRF：

<img width="940" alt="image" src="https://github.com/user-attachments/assets/dc892675-7501-4227-9bc7-08b48ea69604">


找到这样的 GET sink 比我们预期的更常见。许多应用程序在同一个 API 上暴露端点以上传和下载数据，因此与 GET CSPT2CSRF 兼容

---
***第23页***


通过制作恶意的 JSON 响应，我们可以将 CSPT2CSRF 链接起来找到一个有影响力的 POST sink。我们发现了多种这种情况的用例，下一节将描述其中一个例子。


### CSPT2CSRF with a GET sink in Mattermost


在审计 Mattermost 时，我们发现了另一个 CSPT2CSRF。它影响与其他 CSPT2CSRF 相同的版本。由于修复方法不同，因此被列为一个独立的漏洞。该漏洞的编号是 CVE-2023-6458。

### Source 描述

当用户访问 `/<TEAM_NAME>/channels/<CHANNEL_NAME>` 页面时，前端将读取频道名称并尝试将用户添加到频道中（如果尚未加入）。

该功能和相关的 HTTP 请求可以在以下截图中看到：

<img width="1249" alt="image" src="https://github.com/user-attachments/assets/0453a392-ccf5-459f-9533-292649efd363">


使用团队 doyensec 和频道 channelname 执行以下工作流程:


![image](https://github.com/user-attachments/assets/25f5c9cb-e5e9-4f4c-8025-3d435e17ac5d)


---
***第24页***

以下是工作流程请求的解释：
```
1. 用户请求访问  doyensec 团队中的 channelname 频道。
2. 前端请求 /api/v4/teams/name/<team_name>/channels/name/<channel_name> 以验证 doyensec 团队中是否存在名为 channelname 的频道。
3. 根据频道是否存在，返回与频道相关的数据或 404 HTTP 响应代码。
4. 如果频道存在（例如，HTTP 代码 200），前端会验证用户是否已经加入频道。它读取频道 ID（例如，yd3mijddnbytuywenmuaprrswe）并发出 GET 请求到 /api/v4/channels/<channel_id>/members/<user_id>
5. 如果用户未在频道中，端点返回 HTTP 代码 404。
6. 然后前端通过向 /api/v4/channels/<channel_id>/members 发出 POST 请求来添加用户。
```

我们确认在 `channel_name` 中存在一个带有 GET sink 的 CSPT，通过使用 URL 编码：

<img width="1583" alt="image" src="https://github.com/user-attachments/assets/c1fd80ff-c8bc-445d-a040-a800d0e33d5a">

我们认为，如果我们能够利用它返回我们拥有的数据，我们可能可以在所需的端点上触发 POST 请求。
要利用此漏洞，payload必须设置在 `channel_id` 值中，但 Mattermost 中的 ID 在创建时是随机生成的，无法修改。
然而，攻击者可以使用 `/api/v4/files` 端点上传一个恶意的 JSON 文件。请求时，该文件将以 `application/json` 形式提供。

恶意的 JSON payload 必须格式化为类似于频道响应数据（`/api/v4/teams/name/<team_name>/channels/name/<channel_name>`），其中包含指向目标 CSRF 端点（例如，`../caches/invalidate`?）的恶意 id：

```json
{
  "id": "../caches/invalidate?",
  "type": "O",
  "display_name": "fakeChannel",
  "name": "fakeChannel",
  "header": "",
  "purpose": ""
}
```
带有恶意 id 的假频道可以通过 `/api/v4/files/<file_id>` 访问。要执行该漏洞，攻击者必须强制前端加载这个恶意数据，而不是 `/api/v4/teams/name/<team_name>/channels/name/<channel_name>`

这可以通过在 Web 应用程序中构造一个 CSPT payload URL 来实现，例如 ***/<team_name>/channels/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2ffiles%2f<file_id>***，如果在Mattermost内共享，或者如果攻击来自外部网站，则使用双url编码。

---
***第25页***


如果受害者点击该链接，工作流程的请求将如下：

<img width="1090" alt="image" src="https://github.com/user-attachments/assets/70ff75b1-419e-451c-b813-9dd446e9acad">

1. 前端请求：
`/api/v4/teams/name/<team_name>/channels/name/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2ffiles%2f<file_id>` 这等同于请求：`/api/v4/files/<file_id>`


2. 返回包含恶意 channel_id 数据的假频道数据。

3. 前端认为该频道存在，并将验证用户是否已经加入该频道。它读取恶意的 channel_id（例如，`../caches/invalidate`?），并发出 GET 请求到：
`/api/v4/channels/../caches/invalidate?/members/<user_id>` 这等同于发出 GET 请求到 `/api/v4/caches/invalidate`

4. 该端点上不存在 GET 方法，因此后端返回 HTTP 404 代码。
   
5.前端尝试通过向 `/api/v4/channels/../caches/invalidate?/members` 发出 POST 请求来添加用户，这等同于在 `/api/v4/caches/invalidate` 上发出 POST 请求。这确认了 CSRF payload已被执行。

使用这个 source，攻击者能够在选定的端点（例如，`/api/v4/caches/invalidate`）上触发一个 one-click CSRF。

作为攻击者，使用file gadget，可以链式触发两个 CSPT2CSRF：

***第一个 CSPT2CSRF：***

```
➧ Source：URL 中的 channel_name；受害者需要点击链接以触发前端路由。
➧ Sink：API 上的 GET 请求。
```

***第二个 CSPT2CSRF：***

```
➧ Source：来自频道 JSON 数据的 id。
➧ Sink：API 上的 POST 请求。
```

### POST sink 描述


这个问题导致了一个有限的 CSRF，因为攻击者无法控制 POST 请求发送的请求体。
如上所述，发送到 CSRF 端点的请求体如下：
```json
{
  "user_id": "<VICTIM_USER_ID>",
  "channel_id": "<CSRF_ENDPOINT>",
   "post_root_id": ""
}
```


---
***第26页***

因此，该 CSPT2CSRF 的有效 sinks 需要满足以下条件：
```
➧ POST 端点
➧ 除了 user_id、channel_id、post_root_id 之外没有强制性的请求体参数
➧ user_id 是受害者的 ID
➧ 攻击者可以传递额外的查询参数
```
所以，之前针对 Mattermost 漏洞识别的所有有效 sinks 对这个 CSPT 也是有效的

---
***第27页***

### Other CSPT impacts not covered in this whitepaper


***利用 GET sink 的 CSPT2CSRF 进行 XSS 攻击***
前端可能会期望读取由后端清理的数据。攻击者可以利用带有 GET sink 的 CSPT2CSRF，从恶意 JSON 数据中返回 XSS payload。

***与开放重定向链式攻击***
如果 sink 主机上存在Open Redirection漏洞，你可能能够窃取数据和身份验证/CSRF Token，fetch API 会转发前端设置的 Header 信息。


---
***第28页***

***RECOMMENDATIONS (修复建议)***

---
***第29页***

### CSPT2CSRF 修复措施


使用 CSRF 令牌和 SameSite cookies 对防止此漏洞无效。为修复 CSPT，可以采取多种措施：
```
➧ 后端必须强制执行 JSON 结构验证。确实，对接受的 JSON 参数严格要求可以大大减少兼容的 sinks，从而减少此类攻击的影响。
➧ 前端必须对用户输入进行清理，以防止路径遍历攻击，当其被用作路径参数时尤其如此。
```


问题在于大多数前端应用程序使用的 API 客户端实现并没有保护路径遍历。例如，在用于生成不同语言 API 客户端的 `https://github.com/OpenAPITools/openapi-generator` 项目中，我们没有发现针对字符串参数的路径遍历清理。

前端开发人员不了解这种不安全的反模式。这个抽象层隐藏了某些参数可以用作路径参数的事实。在以下示例中，很难看出 deleteUser 函数的 username 参数是作为路径参数发送的，因此需要进行路径遍历清理：
`https://github.com/OpenAPITools/openapi-generator/blob/master/samples/client/petstore/typescript-angular-v16-provided-in-root/builds/default/api/user.service.ts#L319-L382`

---
***第30页***

```javascript
/**
* Delete user
* This can only be done by the logged in user.
* @param username The name that needs to be deleted
* @param observe set whether or not to return the data Observable as the
body, response or events. defaults to returning the body.
* @param reportProgress flag to report request and response progress. */


public deleteUser(username: string, observe?: 'body', reportProgress?: boolean, options?: {httpHeaderAccept?: undefined, context?: HttpContext}): Observable<any>;
public deleteUser(username: string, observe?: 'response', reportProgress?: boolean, options?: {httpHeaderAccept?: undefined, context?: HttpContext}): Observable<HttpResponse<any>>;
public deleteUser(username: string, observe?: 'events', reportProgress?: boolean, options?: {httpHeaderAccept?: undefined, context?: HttpContext}): Observable<HttpEvent<any>>;
public deleteUser(username: string, observe: any = 'body', reportProgress: boolean = false, options?: {httpHeaderAccept?: undefined, context?: HttpContext}): Observable<any> {
if (username === null || username === undefined) {
throw new Error('Required parameter username was null or undefined
when calling deleteUser.'); }
<... STRIPPED ...>
let localVarPath = `/user/${this.configuration.encodeParam({name: "username", value: username, in: "path", style: "simple", explode: false, dataType: "string", dataFormat: undefined})}`;
return this.httpClient.request<any>('delete', `${this.configuration.basePath}${localVarPath}`,
{
context: localVarHttpContext,
responseType: <any>responseType_,
withCredentials: this.configuration.withCredentials, headers: localVarHeaders,
observe: observe,
reportProgress: reportProgress
} );
```

我们认为这种混淆是 CSPT2CSRF 漏洞如此普遍的原因，这也是为什么我们建议在客户端 API 代码中实施适当的类型验证和路径遍历缓解措施的原因

---
***第31页***

***Burp Suite Extension (Burp Suite扩展)***

---
***第32页***

正如前面部分所解释的，不同类型的输入可以导致不同类型的客户端路径遍历漏洞（例如，基于 DOM 的、反射型、存储型），因此使用现成的工具来发现这些漏洞可能并不容易。出于这个原因，我们构建了一个工具来帮助安全研究人员和开发人员识别潜在的 CSPT2CSRF 漏洞。

### CSPT Burp Suite 扩展


CSPT 是一个开源的 Burp Suite 扩展，用于查找和利用客户端路径遍历漏洞。它可以在以下网址获得：
`https://github.com/doyensec/CSPTBurpExtension`

CSPT Burp 扩展实现了不同的工具来识别潜在的 sources 和潜在的 sinks。
```
➧ CSPT 标签将读取 Proxy 历史记录，以查找 URL 路径中查询参数的反射。
➧ False Positive List 标签用于定义必须从搜索中排除的模式。
➧ 一个被动扫描器，将在请求路径中查找 canary 值。
➧ 根据主机请求和 HTTP 方法列出所有可利用的 sinks 的功能。
```
<img width="1627" alt="image" src="https://github.com/user-attachments/assets/992a6996-72d6-46fc-bb13-00abf109168a">
使用此扩展，查找 CSPT2CSRF 的过程如下：


### 查找 source：

```
➧ 爬取应用程序以通过请求填充 Proxy 历史记录。
➧ 使用 Burp 扩展扫描 CSPT。
➧ 使用 canary Token 值确认 source 是否有效。
```

---
***第33页***

### 查找有影响力的 sink：

```
从一个有效的 sink 中，识别所有具有相同限制的 sinks。可以通过代码审查、API 文档以及使用 Burp Suite Bambda 功能过滤代理请求来完成。
```
<img width="1015" alt="image" src="https://github.com/user-attachments/assets/f817b843-e5fa-4dd5-99a9-5a57140ce073">

***工具的局限性：***


```
➧ 除非你使用 canary Token作为输入数据，否则不会识别基于 DOM 或存储的 sources。
➧ 一些前端实现了客户端路由。此类路由不会发送 HTTP 请求到 Burp，因此除非你使用 canary Token，否则不会被我们的扩展捕获。
```

***源代码审查***


当然，手动审查前端源代码也有助于识别在 API 调用的路径参数中使用的输入值。阅读 API 文档可以帮助你了解某些 API 是否使用路径参数。

Semgrep 规则也可以成为促进此分析的好工具。这些规则必须跨文件识别在 source 和 sink 之间使用的值。需要考虑不同的前端框架实现，以识别不同的 sources（例如查询参数、URI 片段）和不同的 sinks（例如 axios、fetch、XHR 调用）。

---
***第34页***

***CONCLUSION (结论)***

---
***第35页***

***结论***


***感谢 CSPT2CSRF，CSRF 依然存在。***


我们介绍了一种利用 GET sink 的 CSPT 技术来进行 CSRF 攻击的新方法。使用恶意上传的数据作为小工具来执行二阶 CSRF 非常常见。在大多数情况下，我们至少能够执行一次 1-click CSPT2CSRF。在这篇技术白皮书中，我们对该问题进行了规范化，并发布了一款工具来帮助发现此类漏洞。我们强烈鼓励安全社区寻找 CSPT2CSRF，并希望我们的研究能够帮助研究人员发现并利用它。

虽然 CSPT2CSRF 引入了新的限制和影响，但一个应用程序可能有多个 CSPT sources，因此可能导致多个漏洞。

在过去的一年里，我们在进行多次评估时搜索了 CSPT2CSRF，并在一些知名目标中发现了多个漏洞。这表明该漏洞多年来一直被忽视。

***作者***


Maxence Schmitt

***审稿人***


Luca Carettoni
John Villamil
Anthony Trummer

***Mattermost 和 Rocket.Chat 团队***

```
➧ 感谢你们的合作和授权，允许我们使用这些漏洞作为示例。
```
---
***第36页***

***REFERENCES***

---
***第37页***

外部资源
```
➧ CSPT Burp Extension : https://github.com/doyensec/CSPTBurpExtension
➧ Portswiggertop102022statingthatCSPTitisanoverlookvulnerability: https://portswigger.net/research/top-10-web-hacking-techniques-of-2022
➧ UsingCSPTvulnerabilitytoincludeexternalCSS: https://mr-medi.github.io/research/2022/11/04/practical-client-side-path-traversal-attacks.html
➧ UsingCSPTtoexploitaCSRF: https://erasec.be/blog/client-side-path-manipulation/
➧ CSPTleadingto1-clickCSRFinGitlab: https://gitlab.com/gitlab-org/gitlab/-/issues/365427
➧ AtweetfromSamCurryaboutCSPTtoCSRFwasfoundonXbackin2021: https://x.com/samwcyo/status/1437030056627523590?lang=fr
➧ Research paper from Soheil Khodayari and Giancarlo Pellegrino: https://www.usenix.org/system/files/sec21-khodayari.pdf
➧ OWASP references about Client-Side CSRF: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat _Sheet.html#dealing-with-client-side-csrf-attacks-important
➧ CSRF by Antoine Roly: https://erasec.be/blog/client-side-path-manipulation/
```
---
***第38, 39, 40页***

***作者所在公司DOYENSEC的介绍，略***
***感兴趣可以查看官方网站https://www.doyensec.com/***
---


