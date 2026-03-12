"use strict";

function collectLanguages(accumulator, value) {
  if (!value) return;
  if (Array.isArray(value)) {
    value.forEach(item => collectLanguages(accumulator, item));
    return;
  }
  const normalized = String(value).trim().toLowerCase();
  if (!normalized) return;
  if (!accumulator.includes(normalized)) {
    accumulator.push(normalized);
  }
  const short = normalized.split("-")[0];
  if (short && short !== normalized && !accumulator.includes(short)) {
    accumulator.push(short);
  }
}

hexo.extend.helper.register("preferred_languages", function preferredLanguages() {
  const languages = [];
  if (this.page) {
    collectLanguages(languages, this.page.lang);
    collectLanguages(languages, this.page.language);
  }
  collectLanguages(languages, this.config && this.config.language);
  if (!languages.includes("default")) {
    languages.push("default");
  }
  if (!languages.includes("en")) {
    languages.push("en");
  }
  return languages;
});

hexo.extend.helper.register("localize_config", function localizeConfig(value, defaultKey) {
  let fallback;
  if (defaultKey) {
    fallback = this.__(defaultKey);
    if (fallback === defaultKey) {
      fallback = undefined;
    }
  }

  if (value == null || value === "") {
    return fallback != null ? fallback : "";
  }

  if (typeof value === "string") {
    return value;
  }

  if (typeof value === "object" && !Array.isArray(value)) {
    const languages = this.preferred_languages();
    for (const language of languages) {
      const matchKey = Object.keys(value).find(key => String(key).trim().toLowerCase() === language);
      if (matchKey) {
        const result = value[matchKey];
        if (result != null && result !== "") {
          return result;
        }
      }
    }
    if ("default" in value && value.default != null) {
      return value.default;
    }
  }

  return fallback != null ? fallback : value;
});
