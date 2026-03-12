# hexo-theme-bear

此主题参考[Bear](http://www.bear-writer.com/)的阅读体验而制作。

This theme is inspired by [Bear](http://www.bear-writer.com/) which is awesome!

## Install

1. Download from GitHub
```shell
$ cd your-hexo-site
$ git clone https://github.com/gary-Shen/hexo-theme-bear themes/bear
```
2. Set the `theme` field in **your site** `_config.yml` to `bear`
```yml
theme: bear
```
3. ❤️ Install dependencies.  
The template is written in pug. So you need to install `hexo-render-pug`.
```
$ npm i hexo-render-pug
# Install your all dependencies if you didn't do this before.
$ npm i
```

## Internationalization

The theme now uses Hexo's built-in i18n system. Set the `language` field in your site-level `_config.yml` (e.g. `language: en` or `language: zh-CN`) and Hexo will pick the matching file from `themes/bear/languages/`. English (`en`), Simplified Chinese (`zh-CN`), Traditional Chinese (`zh-TW`), and Japanese (`ja`) are bundled. To add another language, duplicate `languages/en.yml`, translate the strings, and name it after the new locale code.

### Localizing configuration

- `menu` keys are looked up with `menu.<key>` and fall back to the key itself. You can still supply a simple path (`menu.home: /`), or use an object when you need more control:
  ```yml
  menu:
    home: /
    about:
      path: /about
      i18n: menu.about        # optional explicit translation key
      label:
        en: About
        zh-CN: 关于
      target: _blank          # optional target attribute
  ```
- `date_format`, and any custom `menu` labels accept either a string or an object keyed by locale codes. The theme picks the best match based on the current page language:
  ```yml
  date_format:
    en: YYYY-MM-DD
    zh-CN: YYYY年MM月DD日
    zh-TW: YYYY年MM月DD日
    ja: YYYY年MM月DD日
  ```
  
## Update

```shell
cd themes/bear
git pull
```

## [Live Demo](http://www.garyshen.com)

## Screenshot

![bear](screenshot.jpg)

## Bear in hexo-theme-bear
![bear](screenshot2.jpg)
