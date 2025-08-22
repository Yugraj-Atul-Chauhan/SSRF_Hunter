# -*- coding: utf-8 -*-
#
# Burp Suite Jython Extension: SSRF Active Scanner (Optimized Batch, One-Request-Per-Param) — VERBOSE LOGGING
# Requirements: Burp Suite Pro, Jython 2.7 (standalone jar), Collaborator configured
#
#⚠️ Use only in authorized scopes. SSRF probes may trigger outbound requests.

from burp import IBurpExtender, IScannerCheck, IScanIssue, IParameter
from java.util import ArrayList
import traceback, time, json, re, random, string

# ---------------- Configuration ----------------
EXTENSION_NAME            = "SSRF Hunter (Active) - Batch (Verbose)"
ISSUE_NAME                = "[Custom SSRF Hunter] Server-Side Request Forgery – Active"
SEVERITY                  = "High"
GLOBAL_WAIT_SECONDS       = 5.0   # one sleep per batch (after firing all requests)
TARGET_HEADERS            = [
    # You can add/remove headers here; each header gets ONE request with the payload value
    "X-Original-URL", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
    "X-Host", "X-Real-IP", "X-Http-Host-Override", "Forwarded",
    "Referer", "Origin", "Destination", "X-Callback-Url", "X-Url"
]
VERBOSE_LOGGING           = True  # chatty logs for every step
# ------------------------------------------------

def _rand_suffix(n=6):
    try:
        chars = string.ascii_lowercase + string.digits
        return "".join(random.choice(chars) for _ in range(n))
    except:
        return "err" + str(int(time.time()))

def _safe_lower(s):
    try:
        return s.lower()
    except:
        try:
            return str(s).lower()
        except:
            return ""

def _is_json_content(headers):
    try:
        for h in headers:
            hl = _safe_lower(h)
            if hl.startswith("content-type:") and "application/json" in hl:
                return True
        return False
    except:
        return False

def _is_xml_content(headers):
    try:
        for h in headers:
            hl = _safe_lower(h)
            if hl.startswith("content-type:") and ("xml" in hl):
                return True
        return False
    except:
        return False

def _content_type(headers):
    try:
        for h in headers:
            if h.lower().startswith("content-type:"):
                return h.split(":", 1)[1].strip().lower()
        return ""
    except:
        return ""

def _extract_token_from_domain(domain):
    # "abc123.oastify.com" -> "abc123"
    try:
        return str(domain).split(".", 1)[0]
    except:
        return str(domain)

class BurpExtender(IBurpExtender, IScannerCheck):

    # ===== Register =====
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName(EXTENSION_NAME)
        callbacks.registerScannerCheck(self)

        try:
            self._collab = callbacks.createBurpCollaboratorClientContext()
        except Exception as e:
            self._collab = None
            self._stderr("[!] Failed to create Collaborator context: " + str(e) + "\n" + traceback.format_exc())

        self._stdout("[*] Loaded: " + EXTENSION_NAME)
        if self._collab is None:
            self._stderr("[!] Burp Collaborator unavailable — blind SSRF detection disabled.")
        else:
            self._stdout("[+] Burp Collaborator enabled.")

    # ===== Scanner interface =====
    def doPassiveScan(self, baseRequestResponse):
        return None

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        """
        Strategy:
          1) Generate SSRF payloads (unique token per injection).
          2) Build ONE mutated request per target parameter/header (URL, form, JSON, XML, headers).
          3) Fire all requests (gather response codes for logging).
          4) Sleep once, fetchAllCollaboratorInteractions() once (log every hit).
          5) Map interactions back to collab domains/tokens (log matches & orphans).
          6) Check in-band evidence; raise issues:
             - Firm  : Collaborator hit for payload
             - Tentative : In-band hints only (reflections/metadata strings)
        """
        try:
            base_service = baseRequestResponse.getHttpService()
            base_req_bytes = baseRequestResponse.getRequest()

            analyzed_req = self._helpers.analyzeRequest(base_service, base_req_bytes)
            headers = list(analyzed_req.getHeaders())
            body_offset = analyzed_req.getBodyOffset()
            body_bytes = base_req_bytes[body_offset:]
            body_str = self._helpers.bytesToString(body_bytes)
            url = analyzed_req.getUrl()

            self._stdout("[*] === New Active Scan ===")
            self._stdout("[*] Target URL: " + str(url))
            self._stdout("[*] Method: " + str(analyzed_req.getMethod()))
            self._stdout("[*] Content-Type: " + _content_type(headers))

            sent = []  # list of dicts: {"where": "...","name": "...","payload": "...","domain": "...","reqresp": rr}
            collab_domains = []  # domains we used (to match later)

            # 1) URL query parameters (existing + synthetic if absent)
            self._stdout("[*] Building URL param injections …")
            sent.extend(self._inject_url_params(baseRequestResponse))

            # 2) POST body parameters (x-www-form-urlencoded)
            ct = _content_type(headers)
            if "application/x-www-form-urlencoded" in ct:
                self._stdout("[*] Building form-urlencoded body injections …")
                sent.extend(self._inject_form_params(baseRequestResponse))
            else:
                self._stdout("[*] Skipping form body (not x-www-form-urlencoded).")

            # 3) JSON body parameters
            if _is_json_content(headers):
                self._stdout("[*] Building JSON body injections …")
                sent.extend(self._inject_json_params(baseRequestResponse))
            else:
                self._stdout("[*] Skipping JSON body (content-type mismatch or not JSON).")

            # 4) XML body parameters
            if _is_xml_content(headers):
                self._stdout("[*] Building XML body injections …")
                sent.extend(self._inject_xml_params(baseRequestResponse))
            else:
                self._stdout("[*] Skipping XML body (content-type mismatch or not XML).")

            # 5) Headers (beyond Burp's default insertion points)
            self._stdout("[*] Building header injections …")
            sent.extend(self._inject_headers(baseRequestResponse))

            self._stdout("[*] Total injections built: " + str(len(sent)))

            if not sent:
                self._stdout("[*] No injection points found; returning.")
                return None

            # Record collab domains for later mapping
            for item in sent:
                collab_domains.append(item["domain"])

            # Single global wait after all requests have been fired by helpers in builders
            if self._collab is not None:
                self._stdout("[*] Waiting " + str(GLOBAL_WAIT_SECONDS) + "s for Collaborator callbacks (" + str(len(sent)) + " injections).")
                time.sleep(GLOBAL_WAIT_SECONDS)
                interactions = self._fetch_all_interactions()
            else:
                interactions = []
                self._stdout("[*] Collaborator disabled; skipping callback fetch.")

            # Build a fast lookup map: domain/token -> list of interactions
            inter_map = self._map_interactions(interactions, collab_domains)

            # Evaluate each sent request for interactions + in-band evidence
            issues = []
            confirmed_count = 0
            tentative_count = 0

            for item in sent:
                try:
                    pv_inter = inter_map.get(item["domain"], [])
                    if not pv_inter:
                        # also check by token fallback
                        tok = _extract_token_from_domain(item["domain"])
                        pv_inter = inter_map.get(tok, [])

                    if VERBOSE_LOGGING:
                        self._stdout("[*] Checking evidence for injection: where=" + str(item["where"]) + " name=" + str(item["name"]) + " domain=" + str(item["domain"]) + " payload=" + str(item["payload"]))

                    inband = self._find_inband_evidence(item["reqresp"], item["payload"])
                    if pv_inter or inband:
                        detail = self._build_detail(item, pv_inter, inband)
                        confidence = "Firm" if pv_inter else "Tentative"
                        if pv_inter:
                            confirmed_count += 1
                            self._stdout("[+] CONFIRMED via Collaborator (Firm): " + str(item["where"]) + ":" + str(item["name"]))
                        else:
                            tentative_count += 1
                            self._stdout("[*] Possible via in-band evidence (Tentative): " + str(item["where"]) + ":" + str(item["name"]))

                        # Create the Burp issue object
                        issue = CustomScanIssue(
                            httpService=item["reqresp"].getHttpService(),
                            url=self._helpers.analyzeRequest(item["reqresp"]).getUrl(),
                            httpMessages=[item["reqresp"]],
                            name=ISSUE_NAME + " (" + str(item["where"]) + ":" + str(item["name"]) + ")",
                            detail=detail,
                            severity=SEVERITY,
                            confidence=confidence
                        )

                        # Register the issue in Burp (appears in Target/Issues tab)
                        self._callbacks.addScanIssue(issue)

                        # Track locally too if needed
                        issues.append(issue)
                    else:
                        self._stdout("[-] No evidence for: " + str(item["where"]) + ":" + str(item["name"]))
                except Exception as e:
                    self._stderr("[!] Error evaluating evidence for " + str(item.get("name")) + ": " + str(e) + "\n" + traceback.format_exc())

            self._stdout("[*] Summary => Confirmed(Firm): " + str(confirmed_count) + " | Tentative: " + str(tentative_count))

            return issues if issues else None

        except Exception as e:
            self._stderr("Exception in doActiveScan: " + str(e) + "\n" + traceback.format_exc())
            return None

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        try:
            if existingIssue.getUrl().toString() == newIssue.getUrl().toString() and \
               existingIssue.getIssueDetail() == newIssue.getIssueDetail():
                return 1
        except Exception as e:
            self._stderr("[!] consolidateDuplicateIssues error: " + str(e) + "\n" + traceback.format_exc())
        return 0

    # ====== Injection builders (one request per parameter) ======

    def _canonical_payload_for_new_token(self):
        """Return (payload_value, full_collab_domain) e.g., ('http://abc.oastify.com/', 'abc.oastify.com')"""
        try:
            if self._collab is not None:
                try:
                    raw = self._collab.generatePayload(False)  # usually full domain
                    raw_s = str(raw)
                    if "." in raw_s:
                        dom = raw_s
                    else:
                        dom = raw_s + ".oastify.com"
                    payload = "http://" + dom + "/"
                    if VERBOSE_LOGGING:
                        self._stdout("[*] Generated Collaborator payload: " + payload)
                    return payload, dom
                except Exception as e:
                    self._stderr("[!] Collaborator generatePayload failed: " + str(e) + "\n" + traceback.format_exc())
            # fallback if no collaborator or error
            sfx = _rand_suffix(6)
            payload = "http://127.0.0.1/ssrf_probe_" + sfx + "/"
            if VERBOSE_LOGGING:
                self._stdout("[*] Fallback payload (no-collab): " + payload)
            return payload, "no-collab"
        except Exception as e:
            self._stderr("[!] _canonical_payload_for_new_token error: " + str(e) + "\n" + traceback.format_exc())
            # Final fallback
            return "http://127.0.0.1/ssrf_probe_err/", "no-collab"

    def _log_req_result(self, rr, where, name, payload):
        """Log response status for a sent mutated request."""
        try:
            resp = rr.getResponse()
            status = "no-response"
            if resp:
                ar = self._helpers.analyzeResponse(resp)
                status = str(ar.getStatusCode())
            self._stdout("    [sent] where=" + str(where) + " name=" + str(name) + " payload=" + str(payload) + " -> status=" + status)
        except Exception as e:
            self._stderr("    [sent] logging failed for " + str(where) + ":" + str(name) + ": " + str(e) + "\n" + traceback.format_exc())

    def _inject_url_params(self, baseRR):
        """Mutate URL query parameters. If none exist, create synthetic SSRF-looking params (one each)."""
        results = []
        try:
            service = baseRR.getHttpService()
            req = baseRR.getRequest()
            analyzed = self._helpers.analyzeRequest(service, req)
            url = analyzed.getUrl()

            params = analyzed.getParameters()
            seen = set()
            had_query = False
            for p in params:
                if p.getType() == IParameter.PARAM_URL:
                    had_query = True
                    name = p.getName()
                    if name in seen:
                        continue
                    seen.add(name)

                    payload, dom = self._canonical_payload_for_new_token()
                    new_param = self._helpers.buildParameter(name, payload, IParameter.PARAM_URL)
                    mutated = self._helpers.updateParameter(req, new_param)
                    rr = self._callbacks.makeHttpRequest(service, mutated)

                    results.append({
                        "where": "query",
                        "name": name,
                        "payload": payload,
                        "domain": dom,
                        "reqresp": rr
                    })
                    self._log_req_result(rr, "query", name, payload)

            if not had_query:
                synthetic_names = ["url", "redirect", "next", "dest", "target", "endpoint", "callback"]
                for sname in synthetic_names:
                    payload, dom = self._canonical_payload_for_new_token()
                    addp = self._helpers.buildParameter(sname, payload, IParameter.PARAM_URL)
                    mutated = self._helpers.addParameter(req, addp)
                    rr = self._callbacks.makeHttpRequest(service, mutated)
                    results.append({
                        "where": "query",
                        "name": sname,
                        "payload": payload,
                        "domain": dom,
                        "reqresp": rr
                    })
                    self._log_req_result(rr, "query", sname, payload)
                self._stdout("[*] Added synthetic query params: " + ", ".join(synthetic_names))
        except Exception as e:
            self._stderr("[!] _inject_url_params error: " + str(e) + "\n" + traceback.format_exc())

        return results

    def _inject_form_params(self, baseRR):
        """Mutate application/x-www-form-urlencoded body parameters (one per param)."""
        results = []
        try:
            service = baseRR.getHttpService()
            req = baseRR.getRequest()
            analyzed = self._helpers.analyzeRequest(service, req)
            params = analyzed.getParameters()

            seen = set()
            for p in params:
                if p.getType() == IParameter.PARAM_BODY:
                    name = p.getName()
                    if name in seen:
                        continue
                    seen.add(name)

                    payload, dom = self._canonical_payload_for_new_token()
                    newp = self._helpers.buildParameter(name, payload, IParameter.PARAM_BODY)
                    mutated = self._helpers.updateParameter(req, newp)
                    rr = self._callbacks.makeHttpRequest(service, mutated)
                    results.append({
                        "where": "body-form",
                        "name": name,
                        "payload": payload,
                        "domain": dom,
                        "reqresp": rr
                    })
                    self._log_req_result(rr, "body-form", name, payload)
        except Exception as e:
            self._stderr("[!] _inject_form_params error: " + str(e) + "\n" + traceback.format_exc())

        return results

    def _inject_json_params(self, baseRR):
        """Mutate JSON keys at top-level and one level deep (simple heuristic). One request per key."""
        results = []
        try:
            service = baseRR.getHttpService()
            req = baseRR.getRequest()
            analyzed = self._helpers.analyzeRequest(service, req)
            headers = list(analyzed.getHeaders())
            body = req[analyzed.getBodyOffset():]
            body_str = self._helpers.bytesToString(body)

            try:
                doc = json.loads(body_str)
            except Exception as e:
                self._stderr("[!] JSON parse failed; skipping JSON injection: " + str(e))
                return results  # not valid JSON

            # Collect (path_list) to values we will replace (strings/numbers/bools/null)
            targets = []

            def _collect(d, path, depth):
                try:
                    if depth > 2:
                        return
                    if isinstance(d, dict):
                        for k in d.keys():
                            v = d[k]
                            if isinstance(v, (unicode, str, int, float, bool)) or v is None:
                                targets.append(path + [k])
                            elif isinstance(v, (list, dict)):
                                _collect(v, path + [k], depth + 1)
                    elif isinstance(d, list):
                        if len(d) > 0:
                            v = d[0]
                            if isinstance(v, (unicode, str, int, float, bool)) or v is None:
                                targets.append(path + ["[0]"])
                            elif isinstance(v, (list, dict)):
                                _collect(v, path + ["[0]"], depth + 1)
                except Exception as e:
                    self._stderr("[!] _collect error: " + str(e) + "\n" + traceback.format_exc())

            _collect(doc, [], 0)

            self._stdout("[*] JSON targets found: " + (", ".join(["/".join(t) for t in targets]) if targets else "none"))

            for path in targets:
                try:
                    clone = json.loads(body_str)
                except Exception as e:
                    self._stderr("[!] JSON reparse failed: " + str(e))
                    continue

                # Walk and replace
                cursor = clone
                payload = None
                dom = None
                try:
                    for i in range(len(path)):
                        key = path[i]
                        last = (i == len(path) - 1)

                        if key == "[0]":
                            if isinstance(cursor, list) and len(cursor) > 0:
                                if last:
                                    payload, dom = self._canonical_payload_for_new_token()
                                    cursor[0] = payload
                                else:
                                    cursor = cursor[0]
                            else:
                                break
                        else:
                            if isinstance(cursor, dict) and key in cursor:
                                if last:
                                    payload, dom = self._canonical_payload_for_new_token()
                                    cursor[key] = payload
                                else:
                                    cursor = cursor[key]
                            else:
                                break
                    else:
                        try:
                            new_body = json.dumps(clone)
                        except Exception as e:
                            self._stderr("[!] JSON dumps failed: " + str(e))
                            continue
                        mutated = self._helpers.buildHttpMessage(headers, self._helpers.stringToBytes(new_body))
                        rr = self._callbacks.makeHttpRequest(service, mutated)
                        results.append({
                            "where": "body-json",
                            "name": "/".join(path),
                            "payload": payload,
                            "domain": dom,
                            "reqresp": rr
                        })
                        self._log_req_result(rr, "body-json", "/".join(path), payload)
                except Exception as e:
                    self._stderr("[!] JSON injection error @ " + "/".join(path) + ": " + str(e) + "\n" + traceback.format_exc())

        except Exception as e:
            self._stderr("[!] _inject_json_params error: " + str(e) + "\n" + traceback.format_exc())

        return results

    def _inject_xml_params(self, baseRR):
        """Very simple XML text-node replacer: replace values between tags (first level). One request per text node."""
        results = []
        try:
            service = baseRR.getHttpService()
            req = baseRR.getRequest()
            analyzed = self._helpers.analyzeRequest(service, req)
            headers = list(analyzed.getHeaders())
            body = req[analyzed.getBodyOffset():]
            body_str = self._helpers.bytesToString(body)

            pattern = re.compile(r"<([A-Za-z0-9:_\.-]+)>([^<]{0,4000})</\1>")
            matches = list(pattern.finditer(body_str))
            used_spans = set()

            self._stdout("[*] XML nodes matched: " + str(len(matches)))

            for m in matches:
                try:
                    tag = m.group(1)
                    span = m.span(2)
                    if span in used_spans:
                        continue
                    used_spans.add(span)

                    payload, dom = self._canonical_payload_for_new_token()
                    new_body = body_str[:span[0]] + payload + body_str[span[1]:]
                    mutated = self._helpers.buildHttpMessage(headers, self._helpers.stringToBytes(new_body))
                    rr = self._callbacks.makeHttpRequest(service, mutated)

                    results.append({
                        "where": "body-xml",
                        "name": tag,
                        "payload": payload,
                        "domain": dom,
                        "reqresp": rr
                    })
                    self._log_req_result(rr, "body-xml", tag, payload)
                except Exception as e:
                    self._stderr("[!] XML injection loop error: " + str(e) + "\n" + traceback.format_exc())
        except Exception as e:
            self._stderr("[!] _inject_xml_params error: " + str(e) + "\n" + traceback.format_exc())

        return results

    def _inject_headers(self, baseRR):
        """Inject into configured headers; one request per header."""
        results = []
        try:
            service = baseRR.getHttpService()
            req = baseRR.getRequest()
            analyzed = self._helpers.analyzeRequest(service, req)
            headers = list(analyzed.getHeaders())
            body = req[analyzed.getBodyOffset():]

            if not headers:
                return results
            req_line = headers[0]

            for hname in TARGET_HEADERS:
                try:
                    payload, dom = self._canonical_payload_for_new_token()
                    new_headers = [req_line]
                    replaced = False
                    hname_lower = hname.lower()

                    for existing in headers[1:]:
                        if ":" not in existing:
                            continue
                        n, v = existing.split(":", 1)
                        if n.strip().lower() == hname_lower:
                            new_headers.append(n + ": " + payload)
                            replaced = True
                        else:
                            new_headers.append(existing)

                    if not replaced:
                        new_headers.append(hname + ": " + payload)

                    mutated = self._helpers.buildHttpMessage(new_headers, body)
                    rr = self._callbacks.makeHttpRequest(service, mutated)

                    results.append({
                        "where": "header",
                        "name": hname,
                        "payload": payload,
                        "domain": dom,
                        "reqresp": rr
                    })
                    self._log_req_result(rr, "header", hname, payload)
                except Exception as e:
                    self._stderr("[!] Header injection error for " + str(hname) + ": " + str(e) + "\n" + traceback.format_exc())
        except Exception as e:
            self._stderr("[!] _inject_headers error: " + str(e) + "\n" + traceback.format_exc())

        return results

    # ====== Collaborator handling (batch) ======
    def _fetch_all_interactions(self):
        """Fetch all collaborator interactions once and log them."""
        try:
            interactions = list(self._collab.fetchAllCollaboratorInteractions())
            if not interactions:
                self._stdout("[*] No Collaborator interactions received.")
            else:
                self._stdout("[+] Retrieved " + str(len(interactions)) + " Collaborator interactions:")
                for i in interactions:
                    try:
                        props = i.getProperties()
                        # props is a java.util.Map; enumerate values safely
                        blob = []
                        try:
                            it_keys = props.keySet().iterator()
                            while it_keys.hasNext():
                                k = it_keys.next()
                                v = props.get(k)
                                blob.append(str(k) + "=" + str(v))
                        except:
                            blob.append(str(props))
                        self._stdout("    [Collab Hit] " + " | ".join(blob))
                    except Exception as e:
                        self._stderr("    [Collab Hit] Could not read properties: " + str(e) + "\n" + traceback.format_exc())
            return interactions
        except Exception as e:
            self._stderr("Collaborator fetch failed: " + str(e) + "\n" + traceback.format_exc())
            return []

    def _map_interactions(self, interactions, domains):
        """
        Build a mapping {domain_or_token: [interactions...]} so we can match
        both by full domain ('abc.oastify.com') and by token ('abc').
        Log when matches are found; log unmatched hits too.
        """
        out = {}
        try:
            wanted = set([str(d) for d in domains if d and d != "no-collab"])
            wanted_tokens = set([_extract_token_from_domain(d) for d in wanted])

            if VERBOSE_LOGGING:
                self._stdout("[*] Mapping interactions to " + str(len(wanted)) + " domains and " + str(len(wanted_tokens)) + " tokens.")
                if wanted:
                    self._stdout("    Domains: " + ", ".join(list(wanted)))
                if wanted_tokens:
                    self._stdout("    Tokens : " + ", ".join(list(wanted_tokens)))

            matched_total = 0
            unmatched_total = 0

            for i in interactions:
                try:
                    props = i.getProperties()
                    # Build a lowercase blob of all property values for substring search
                    vals = []
                    try:
                        it = props.values().iterator()
                        while it.hasNext():
                            v = it.next()
                            try:
                                vals.append(str(v))
                            except:
                                pass
                    except:
                        # fallback: try some common keys
                        for k in ["interaction_id", "raw_query", "qname", "query_type", "client_ip", "protocol"]:
                            try:
                                vals.append(str(props.get(k)))
                            except:
                                pass

                    blob = " ".join(vals)
                    blob_l = _safe_lower(blob)

                    matched_keys = []
                    for d in wanted:
                        if d and _safe_lower(d) in blob_l:
                            matched_keys.append(d)
                    for t in wanted_tokens:
                        if t and _safe_lower(t) in blob_l:
                            matched_keys.append(t)

                    if matched_keys:
                        for k in matched_keys:
                            if k not in out:
                                out[k] = []
                            out[k].append(i)
                        matched_total += 1
                        self._stdout("[+] Collaborator match for " + str(matched_keys) + " → " + blob)
                    else:
                        unmatched_total += 1
                        self._stdout("[*] Unmatched Collaborator hit: " + blob)

                except Exception as e:
                    self._stderr("[!] Error parsing Collaborator interaction: " + str(e) + "\n" + traceback.format_exc())

            self._stdout("[*] Mapping summary => matched: " + str(matched_total) + " | unmatched: " + str(unmatched_total))
        except Exception as e:
            self._stderr("[!] _map_interactions error: " + str(e) + "\n" + traceback.format_exc())

        return out

    # ====== Evidence & Issue building ======
    def _find_inband_evidence(self, rr, payload_value):
        try:
            resp = rr.getResponse()
            if not resp:
                return None
            ar = self._helpers.analyzeResponse(resp)
            body = resp[ar.getBodyOffset():]
            body_str = self._helpers.bytesToString(body)
            body_l = _safe_lower(body_str)
            token_l = _safe_lower(payload_value)

            ev = []
            if token_l in body_l:
                ev.append("Reflected payload in response body.")

            for h in ar.getHeaders():
                if token_l in _safe_lower(h):
                    ev.append("Reflected payload in response header: " + h)
                    break

            # cloud metadata strings (quick heuristic)
            for kw in ["169.254.169.254", "latest/meta-data", "aws", "gce", "azure", "imds", "meta-data"]:
                if kw in body_l:
                    ev.append("Cloud metadata indicator in response: " + kw)
                    break

            if ev:
                self._stdout("[*] In-band evidence found: " + "; ".join(ev))
            return "; ".join(ev) if ev else None
        except Exception as e:
            self._stderr("[!] _find_inband_evidence error: " + str(e) + "\n" + traceback.format_exc())
            return None

    def _build_detail(self, item, interactions, inband):
        try:
            parts = []
            parts.append("<p><b>Injected into:</b> {} → <code>{}</code></p>".format(
                self._helpers.escapeHTML(item["where"]),
                self._helpers.escapeHTML(item["name"])
            ))
            parts.append("<p><b>Payload:</b> <code>{}</code></p>".format(
                self._helpers.escapeHTML(item["payload"])
            ))
            if interactions:
                parts.append("<p><b>Blind SSRF confirmed via Collaborator:</b></p><ul>")
                for i in interactions:
                    try:
                        props = i.getProperties()
                        t = props.get("time_stamp") or props.get("timestamp") or "unknown"
                        q = props.get("query_type") or props.get("protocol") or "network"
                        src = props.get("client_ip") or props.get("source") or "unknown"
                        parts.append("<li>{} — {} from {}</li>".format(
                            self._helpers.escapeHTML(str(t)),
                            self._helpers.escapeHTML(str(q)),
                            self._helpers.escapeHTML(str(src))
                        ))
                    except:
                        parts.append("<li>(interaction details unavailable)</li>")
                parts.append("</ul>")
            if inband:
                parts.append("<p><b>In-band evidence:</b> {}</p>".format(self._helpers.escapeHTML(inband)))

            parts.append("<hr><p><b>Generated by:</b> {}</p>".format(self._helpers.escapeHTML(EXTENSION_NAME)))
            parts.append("<p><b>Remediation:</b> Use allowlists for outbound destinations; "
                         "block internal/link-local ranges; validate & re-validate after redirects; "
                         "enforce egress network controls; prefer IMDSv2 for cloud metadata.</p>")
            return "".join(parts)
        except Exception as e:
            self._stderr("[!] _build_detail error: " + str(e) + "\n" + traceback.format_exc())
            return "Issue detail construction failed."

    # ====== Logging ======
    def _stdout(self, msg):
        try:
            if VERBOSE_LOGGING:
                self._callbacks.printOutput(msg)
        except:
            pass

    def _stderr(self, msg):
        try:
            self._callbacks.printError(msg)
        except:
            pass


# ====== Custom issue ======
class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity, confidence):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence

    def getUrl(self): return self._url
    def getIssueName(self): return self._name
    def getIssueType(self): return 0x08000000   # custom type
    def getSeverity(self): return self._severity
    def getConfidence(self): return self._confidence
    def getIssueBackground(self):
        return ("Server-Side Request Forgery (SSRF) lets an attacker cause the server to "
                "make outbound requests, potentially reaching internal systems or cloud metadata services.")
    def getRemediationBackground(self):
        return ("Enforce allowlists for destinations, block internal/link-local ranges, "
                "validate and re-validate URLs after redirects, and restrict egress network access.")
    def getIssueDetail(self): return self._detail
    def getRemediationDetail(self): return None
    def getHttpMessages(self): return self._httpMessages
    def getHttpService(self): return self._httpService