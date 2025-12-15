---
title: 从“全网封杀”到“赛博地主”：我的 woftom.online 诞生记
date: 2025-12-15 17:30:00
tags: [Cloudflare, Hexo, 随笔, 折腾]
categories: [技术, 建站]
---

"Hell yeah! It's like owning a piece of land in the internet!"

这是我看着自己配置好的域名、博客和邮箱时，脑海里蹦出的第一句话。

今天是我正式成为一名“赛博地主”的日子，但获取这块地确实不容易。

<!-- more -->

## 开局不利：serverHold

几个月前，我一时兴起买下了 `woftom.online` 这个域名。当时我什么都不懂，买完就扔在那儿了。

今天心血来潮想把它用起来，结果发现无论如何都无法解析。在 Whois 查询后，我看到了一行令我心肺骤停的红字：

> **Domain Status: serverHold**

我不懂这是什么意思，查了资料才知道，这相当于我的域名被“最高法院”（注册局）给查封了！原因竟然是我当初漏掉了 ICANN 的验证邮件，甚至还因为使用了云服务器 IP 被 Spamhaus（反垃圾邮件组织）误伤了。

然后我进行申诉，由于是冤案，申诉过程还算顺利。不到一个小时，我的域名解封了！

##  遇见“赛博大善人”：Cloudflare

在这一天的折腾中，我深刻理解了为什么 `linux.do` 的老哥们都管 Cloudflare 叫“赛博大善人”。

在解决了解封问题后，我面临着两个选择：
1. 花钱买个服务器。
2. 拥抱 Cloudflare 全家桶。

我选择了后者，然后仿佛打开了新世界的大门。

### 我的技术栈

现在，你看到的这个网站，是这样运行的(十分初级)：

*   **地基 (Domain):** `woftom.online`
*   **装修 (Framework):** **Hexo** (静态网站生成器)
*   **仓库 (Storage):** **GitHub** (存放我的代码)
*   **物业 (Hosting):** **Cloudflare Pages** (自动从 GitHub 拉取代码并发布到全球)
*   **安保 (SSL):** **Cloudflare** SSL (自动为我的网站配置 HTTPS)

这一切，**全都是免费的**。而且速度飞快，全球 CDN 加速。

## 专属域名邮箱

除了博客，最让我兴奋的是我拥有了专属的域名邮箱：`drip@woftom.online`。而且我还可以无限生成，尝试发给我一封邮件!如果你也想要一个这样酷炫的邮箱地址，可以发邮件到 `admin@woftom.online` 联系我🤓。

## 领地扩张：无限的子域名

拥有域名的感觉真的很好。除了主站，我还随手部署了一个圣诞树在 `tree.woftom.online`。

只要我想，我可以部署无数个好玩的项目：`game.woftom.online`、`love.woftom.online`... 每一个子域名都是我领地上的新建筑。

## 🎉 结语

实践才是学习的最快途径！

**Hello, World! Hello, Woftom Online!**

