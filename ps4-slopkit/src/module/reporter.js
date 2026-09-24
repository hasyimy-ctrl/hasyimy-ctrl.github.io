export function createReporter(options) {
    const {
        channel,
        verbose = false,
        output,
        statusOutput,
        prose = [],
        classify
    } = options;
    const lines = [];
    let passCount = 0;
    let failCount = 0;

    function terse(value) {
        if (verbose || value == null) return value;
        let text = String(value);
        for (const re of prose) {
            const match = re.exec(text);
            if (match && match.index > 0) text = text.slice(0, match.index);
        }
        text = text.replace(/\s+$/, "");
        return text.length > 140 ? text.slice(0, 140) + "..." : text;
    }

    function post(tag, detail) {
        try {
            const request = new XMLHttpRequest();
            request.open("POST", "t", true);
            request.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
            request.send(channel + "&tag=" + encodeURIComponent(tag)
                + "&detail=" + encodeURIComponent(String(detail == null ? "" : detail)));
        } catch (_) { }
    }

    function mark(tag, detail) {
        const displayed = terse(detail);
        lines.push(tag + (displayed == null || displayed === ""
            ? "" : "  " + displayed));
        const escape = text => String(text).replace(/&/g, "&amp;")
            .replace(/</g, "&lt;").replace(/>/g, "&gt;");
        if (output) {
            output.innerHTML = lines.map(function(line) {
                const escaped = escape(line);
                const cls = classify ? classify(escaped) : "";
                return cls ? '<span class="' + cls + '">' + escaped + "</span>" : escaped;
            }).join("\n");
            output.scrollTop = output.scrollHeight;
        }
        post(tag, detail);
    }

    function trace(tag, detail) {
        if (verbose) mark(tag, detail);
        else post(tag, detail);
    }

    function state(text, cls) {
        if (statusOutput) {
            statusOutput.textContent = text;
            statusOutput.className = cls || "";
        }
    }

    function check(name, ok, detail) {
        if (ok) passCount++;
        else failCount++;
        mark(ok ? "PROOF-OK" : "PROOF-FAIL",
            name + (detail ? "  " + detail : ""));
        return ok;
    }

    return {
        mark, trace, state, check,
        get passCount() { return passCount; },
        get failCount() { return failCount; }
    };
}
