# Cross-Site Scripting (XSS)

## 1. What it is

Cross-site scripting lets an attacker inject script that executes in another user's browser, in the security context of the vulnerable application. This allows the attacker to impersonate the victim, perform any action the victim is authorised to perform, read any data the victim can access, and steal session tokens or credentials.

The root cause is consistent across every variant: untrusted input is rendered into a page (or into the DOM) without context-appropriate encoding, so the browser parses attacker data as executable code rather than as inert text.

## 2. How it's exploited

XSS has three forms, distinguished by *where* the untrusted data enters and *when* it executes: reflected, stored, and DOM-based.

### 2a. Reflected XSS (HTML context, nothing encoded)

**Context:** input from the request (e.g. a `search` parameter) is echoed straight into the HTML response with no encoding.

**Payload:** `<script>alert(1)</script>`

**Why it works:** the input lands in HTML element context (between tags) with zero encoding, so the raw `<script>` is parsed and executed. "Reflected" means the payload rides in the request and is echoed back in that same response, so exploitation requires luring the victim to a crafted URL.

### 2b. Stored XSS (HTML context, nothing encoded)

**Context:** input (e.g. a comment) is persisted server-side and later rendered to every viewer, unencoded.

**Payload:** `<script>alert(1)</script>`

**Why it works:** the same no-encoding HTML-context flaw, but the payload persists in the datastore and fires for anyone who loads the page. Higher impact than reflected: no crafted URL or victim lure is needed, the payload waits for visitors.

### 2c. Context dictates the breakout (encoded angle brackets)

The same sink demands a different payload depending on *where* the input lands. When angle brackets are HTML-encoded (`<` becomes `&lt;`, `>` becomes `&gt;`), tag-injection payloads like `<script>` or `<img onerror>` are dead. If quotes are not also encoded, you break out of the surrounding attribute instead.

**Reflected XSS into an attribute, angle brackets HTML-encoded:**
- Input reflects inside an attribute, e.g. `<input ... value="SEARCH">`.
- Payload: `"onmouseover="alert(1)`
- Why it works: angle brackets are encoded, so you cannot open a new tag. Instead you use `"` to break out of the existing attribute value and append an event handler (`onmouseover`) to the current tag. No new tag, no angle brackets.

**Stored XSS into an anchor `href`, double quotes HTML-encoded:**
- The injection point is a "website" field rendered into an anchor `href` in the comment.
- Payload: `javascript:alert(document.domain)`
- Why it works: even with `<`, `>`, and `"` encoded, the `href` sink accepts the `javascript:` pseudo-protocol. The script executes when a viewer clicks the link. Sink type, not tag injection, carries the payload here.

**Reflected XSS into a JavaScript string, angle brackets HTML-encoded:**
- The input is reflected inside a JS string literal, e.g. `var searchItems = 'INPUT';`. Angle brackets are HTML-encoded, so HTML-injection payloads like `<svg onload=...>` are dead.
- Payload: `'-alert(document.domain)-'`
- Why it works: you are already inside JavaScript, so no angle brackets are needed. The leading `'` closes the string literal, `-alert(document.domain)-` runs as an expression (the `-` operators keep the statement syntactically valid), and the trailing `'` reopens the string. The line becomes `var searchItems = ''-alert(document.domain)-''`, and `alert` executes during evaluation.

### 2d. DOM-based XSS

**Concept:** the vulnerability lives entirely in client-side JavaScript, not on the server. JS reads an attacker-controlled **source**, writes it into a dangerous **sink** with no sanitisation, and the code executes in the browser. The server may never see the payload execute.

| Sources (attacker-controlled) | Sinks (dangerous writes) |
|---|---|
| `location.search`, `location.hash`, `document.referrer`, `document.cookie` | `innerHTML`, `document.write()`, `eval()`, `setTimeout()`, jQuery `.html()`, an `href` attribute |

The payload is dictated by the **sink** and the surrounding **context**:

**`document.write` sink, `location.search` source:**
- JS reads `location.search` and passes it into `document.write`, building an `<img src="...">`.
- Payload: `"><svg onload=alert(1)>`
- Why it works: `document.write` emits raw HTML. Input lands inside `img src="..."`, so `">` closes the attribute and the tag, then `<svg onload>` is a fresh, auto-firing element.

**`document.write` sink inside a `<select>` element, `location.search` source:**
- A `storeId` param flows into `document.write`, building `<option>`s inside a `<select>`.
- Payload: `"></select><img src=1 onerror=alert(1)>`
- Why it works: content inside a `<select>` (other than `<option>`) is not rendered, so an injected `<img>` stays inert until you escape the element. `</select>` breaks out, then the broken `img` fires `onerror`. Same sink as the lab above, different context, different breakout.

**`innerHTML` sink, `location.search` source:**
- `location.search` is assigned to an element's `innerHTML`.
- Payload: `<img src=1 onerror=alert(1)>`
- Why it works: `innerHTML` parses HTML, but per the HTML5 spec, `<script>` elements inserted via `innerHTML` do not execute. You need an element with an auto-firing event handler, so a broken `img` triggering `onerror` is the standard trick.

**jQuery `$()` selector sink, `location.hash` source (hashchange event):**
- A value from `location.hash` is passed into jQuery's `$()` selector, re-run on the `hashchange` event.
- Payload: `<iframe src="https://LAB-ID.web-security-academy.net/#" onload="this.src+='<img src=x onerror=print()>'"></iframe>`
- Why it works: when `$()` is handed a string that looks like HTML, jQuery builds DOM nodes from it instead of selecting existing ones, so the `<img>` is created and its broken `src` fires `onerror`. `hashchange` only fires when the fragment changes *after* load, so a plain link will not trigger it: you deliver via an iframe and mutate `this.src` in `onload` to change the hash post-load. `print()` is used over `alert()` because the lab verifies execution in the victim's context.

**AngularJS (`ng-app` scope), filter bypass:**
- Payload: `{{constructor.constructor('alert(1)')()}}`
- Why it works: inside an AngularJS expression context, this sandbox-escape executes JavaScript using no angle brackets and no event handlers, which makes it effective where tag and attribute injection are filtered.

## 3. Real-world impact + CVSS

**Severity: Medium → High** (typical reflected CVSS around **6.1**, stored and privileged cases reaching **8.0+**).

Impact scales with the application's sensitivity:
- Anonymous, fully public application with no sensitive data: minimal impact.
- Application holding sensitive data (banking, email, healthcare): serious, session hijacking and data theft.
- Application where the victim holds elevated/admin privileges: critical, the attacker inherits administrative control.

## 4. How to detect it (tester's signals)

Inject a unique tracer string (e.g. `xyz123`) into every input, then locate where it surfaces:
- **Reflected / stored:** search the HTML response for the tracer to find the reflection context.
- **DOM-based:** search the live DOM via DevTools (Elements tab), not view-source, since the value is written client-side. For HTML sinks, find the tracer in the rendered DOM. For JS-execution sinks (`eval`, `setTimeout`), set a breakpoint on the source in the debugger and step through to the sink, since the input may never appear in the DOM.

Once the context is known, test that exact spot with a payload appropriate to the sink and surrounding context. Sneaky sources (`document.cookie`) and sinks (`setTimeout`) require JS code review. Burp DOM Invader automates much of the source-to-sink tracing.

## 5. How to fix it

**Root cause:** untrusted input is rendered into a page or DOM without context-appropriate encoding, so the browser parses it as code.

**Primary fix: context-aware output encoding.** Encode user input on output according to the context it is rendered into (HTML body, HTML attribute, JavaScript, URL, CSS each require different encoding). Correct encoding ensures the browser treats the input as data, never as markup or script.

**Supporting controls:**
- Prefer safe sinks: use `textContent` instead of `innerHTML`, and avoid `document.write`, `eval`, and `setTimeout(string)` entirely.
- For DOM XSS, do not pass untrusted data into dangerous sinks. Where data must reach an `href`, validate the URL scheme and reject `javascript:`.
- Validate input against expected format where feasible (defence in depth, not a substitute for encoding).
- Deploy a Content Security Policy (CSP) to reduce the impact of any XSS that slips through.
- Use a framework that auto-encodes by default, and avoid bypassing its protections (e.g. `bypassSecurityTrust`, `dangerouslySetInnerHTML`).

## 6. References

- PortSwigger Web Security Academy: Cross-site scripting
- OWASP: Cross Site Scripting Prevention Cheat Sheet
- OWASP: DOM based XSS Prevention Cheat Sheet
