const { addonBuilder } = require("stremio-addon-sdk");
const axios = require("axios");

const manifest = {
  id: "org.stremio.CZSK.private",
  version: "1.0.0",
  name: "CZSK Private",
  description: "Private addon for Stremio that searches multiple Czech sources.",
  resources: ["stream"],
  types: ["movie", "series"],
  idPrefixes: ["tt"],
  catalogs: [],
  behaviorHints: {
    configurable: false,
    adult: false,
  }
};

const builder = new addonBuilder(manifest);
const addonInterface = builder.getInterface();

// Zde už není stream handler, protože je v server.js
// Místo toho exportujeme všechny potřebné funkce

async function searchWebshare(query, wstToken) {
    if (!wstToken) return [];
    try {
        const response = await axios.get(`https://webshare.cz/api/search/`, { params: { q: query, wst: wstToken, limit: 50, category: 'video' } });
        const files = response.data.match(/<file>[\s\S]*?<\/file>/g) || [];
        return files.map(file => {
            const nameMatch = file.match(/<name>(.*?)<\/name>/);
            const identMatch = file.match(/<ident>(.*?)<\/ident>/);
            const sizeMatch = file.match(/<size>(.*?)<\/size>/);
            return { title: nameMatch?.[1], ident: identMatch?.[1], size: sizeMatch ? parseInt(sizeMatch[1], 10) : 0, source: 'webshare' };
        }).filter(r => r.ident);
    } catch (error) { console.error("Webshare search error:", error.message); return []; }
}

async function getWebshareStreamUrl(ident, wstToken) {
    if (!wstToken || !ident) return null;
    try {
        const response = await axios.get(`https://webshare.cz/api/file_link/`, { params: { ident, wst: wstToken } });
        const linkMatch = response.data.match(/<link>(.*?)<\/link>/);
        return linkMatch ? linkMatch[1] : null;
    } catch (error) { console.error("Webshare get link error:", error.message); return null; }
}

async function searchHellspy(query) {
  try {
    const response = await axios.get(`https://api.hellspy.to/gw/search?query=${encodeURIComponent(query)}&offset=0&limit=64`);
    const items = response.data.items || [];
    return items.filter((item) => item.objectType === "GWSearchVideo").map(item => ({...item, source: 'hellspy'}));
  } catch (error) { return []; }
}

async function getStreamUrl(id, fileHash) {
  try {
    const response = await axios.get(`https://api.hellspy.to/gw/video/${id}/${fileHash}`);
    const title = response.data.title || "";
    const conversions = response.data.conversions || {};
    if (Object.keys(conversions).length === 0 && response.data.download) {
      return [{ url: response.data.download, quality: "original", title: title }];
    }
    return Object.entries(conversions).map(([quality, url]) => ({ url, quality: quality + "p", title: title }));
  } catch (error) { return []; }
}

async function getTitleFromWikidata(imdbId) {
  try {
    const baseQuery = (lang) => `SELECT ?filmLabel ?year WHERE { ?film wdt:P345 "${imdbId}". OPTIONAL { ?film wdt:P577 ?date. BIND(YEAR(?date) AS ?year) } SERVICE wikibase:label { bd:serviceParam wikibase:language "${lang}". } }`;
    const url = "https://query.wikidata.org/sparql";
    const headers = { Accept: "application/sparql-results+json" };
    const [czResponse, enResponse] = await Promise.all([
      axios.get(url, { params: { query: baseQuery("cs") }, headers }),
      axios.get(url, { params: { query: baseQuery("en") }, headers }),
    ]);
    const czResult = czResponse.data.results.bindings[0];
    const enResult = enResponse.data.results.bindings[0];
    return { czTitle: czResult?.filmLabel?.value, enTitle: enResult?.filmLabel?.value, year: czResult?.year?.value || enResult?.year?.value };
  } catch (error) { return {}; }
}

function getSeasonEpisodePatterns(season, episode) {
  const s = season.toString().padStart(2, "0");
  const e = episode.toString().padStart(2, "0");
  return [`S${s}E${e}`, `${s}x${e}`, ` - ${e}`];
}

function isLikelyEpisode(title) {
  return title ? /\bS\d{2}E\d{2}\b|\b\d{1,2}x\d{1,2}\b|\s-\s\d{1,2}\b/i.test(title) : false;
}

async function searchSeriesWithPattern(queries, season, episode, wstToken) {
  const patterns = getSeasonEpisodePatterns(season, episode);
  for (const query of queries) {
    if (!query) continue;
    const [hellspyResults, webshareResults] = await Promise.all([searchHellspy(query), searchWebshare(query, wstToken)]);
    const combined = [...hellspyResults, ...webshareResults];
    const filtered = combined.filter(r => patterns.some(p => r.title && r.title.toUpperCase().includes(p.toUpperCase())));
    if (filtered.length > 0) return filtered;
  }
  return [];
}

module.exports = {
    addonInterface,
    searchWebshare,
    getWebshareStreamUrl,
    searchHellspy,
    getStreamUrl,
    getTitleFromWikidata,
    getSeasonEpisodePatterns,
    isLikelyEpisode,
    searchSeriesWithPattern
};
