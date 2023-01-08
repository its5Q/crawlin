import std/[uri, strutils, sequtils, algorithm, sets, sugar]
import regex

const queryBlacklist: HashSet[string] = toHashSet([
    "utm_source", "csrf", "phpsessid", "sid", "utm_campaign", "utm_medium", "go", "redirect_url", "s",
    "goto", "af", "ref", "utm_term", "utm_content", "utm_expid", "fbclid", "fb_action_ids", "fb_action_types",
    "fb_source", "mc_cid", "mc_eid", "gclid", "dclid", "_ga", "campaignid", "adgroupid", "_ke",
    "cn-reloaded", "age-verified", "ao_noptimize", "usqp", "mkt_tok", "epik", "ck_subscriber_id",
    "origin", "refreshce", "xsrf"
])

const pathBlacklist: HashSet[string] = toHashSet([
    "/showcaptcha"
])

const repeatingSlashesPattern = re(r"/+")
const leadingRelPathPattern = re(r"^(?:/\.\.(?![^/]))+")

proc normalizeUri*(uri: Uri, strict: bool = false): Uri = 
    ## Normalizes provided URI by sorting query parameters,
    ## removing anchors and other modifications.
    ## 
    ## The `strict` parameter enables more transformations, for example,
    ## removing noisy query parameters like utm_source and others.
    
    result = uri
    result.scheme = result.scheme.toLower
    result.hostname = result.hostname.toLower.strip(chars= {'.'})
    result.anchor = ""

    if result.scheme == "https" and result.port == "443":
        result.port = ""
    elif result.scheme == "http" and result.port == "80":
        result.port = ""

    var query = decodeQuery(result.query).toSeq
    query.sort do (x, y: tuple[key: string, value: string]) -> int:
        result = cmp(x.key, y.key)
        if result == 0:
            result = cmp(x.value, y.value)

    result.path = result.path.replace(repeatingSlashesPattern, "/")
    result.path = result.path.replace(leadingRelPathPattern, "")

    if strict:
        query = collect:
            for x in query:
                if not (x.key.toLower in queryBlacklist): x

    result.query = encodeQuery(query)


proc isExternal*(uri1: Uri, uri2: Uri): bool =
    ## Returns `true` if the URLs have different domains
    result = uri1.hostname.toLower != uri2.hostname.toLower


proc isCrawlable*(uri: Uri): bool =
    ## Returns `true` if the URL is suitable for crawling based on blacklists
    
    if not (uri.scheme == "http" or uri.scheme == "https"):
        return false

    if uri.path in pathBlacklist:
        return false
