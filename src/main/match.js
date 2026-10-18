// Rule / host matching helpers shared by every tool.

const cache = new Map();

function globToRegExp(glob) {
  const key = 'g:' + glob;
  if (cache.has(key)) return cache.get(key);
  const src = glob.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
  const re = new RegExp('^' + src + '$', 'i');
  cache.set(key, re);
  return re;
}

function toRegExp(pattern, matchType) {
  if (matchType !== 'regex') return globToRegExp(pattern);
  const key = 'r:' + pattern;
  if (cache.has(key)) return cache.get(key);
  let re;
  try { re = new RegExp(pattern, 'i'); } catch { re = /$^/; }
  cache.set(key, re);
  return re;
}

// Match a URL against a rule pattern. Wildcard patterns without a scheme
// also match the URL with its scheme stripped, so "api.example.com/*" works.
function urlMatches(pattern, matchType, url) {
  if (!pattern) return false;
  const re = toRegExp(pattern.trim(), matchType);
  if (re.test(url)) return true;
  if (matchType !== 'regex') {
    const bare = url.replace(/^[a-z]+:\/\//i, '');
    if (re.test(bare)) return true;
    // "example.com" alone should match everything on that host
    if (!/[/*]/.test(pattern) && re.test(bare.split(/[/?]/)[0])) return true;
  }
  return false;
}

function hostMatches(pattern, host) {
  if (!pattern) return false;
  pattern = pattern.trim().replace(/^[a-z]+:\/\//i, '').replace(/[:/].*$/, '');
  return globToRegExp(pattern).test(host);
}

function ruleMatches(rule, method, url) {
  if (!rule || rule.enabled === false) return false;
  if (rule.method && rule.method !== 'ANY' && rule.method.toUpperCase() !== method.toUpperCase()) return false;
  return urlMatches(rule.pattern, rule.matchType, url);
}

function findRule(tool, method, url, predicate) {
  if (!tool || !tool.enabled) return null;
  return (tool.rules || []).find((r) => ruleMatches(r, method, url) && (!predicate || predicate(r))) || null;
}

function findRules(tool, method, url, predicate) {
  if (!tool || !tool.enabled) return [];
  return (tool.rules || []).filter((r) => ruleMatches(r, method, url) && (!predicate || predicate(r)));
}

module.exports = { urlMatches, hostMatches, ruleMatches, findRule, findRules };
