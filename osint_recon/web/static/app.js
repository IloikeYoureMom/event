const BUCKET_COLORS = {
  ioc: "#4cc2ff",
  leak: "#ff5d5d",
  leaked: "#ff5d5d",
  actor: "#b388ff",
  report: "#ffd166",
  threat: "#ffd166",
  chat: "#6ee7b7",
  forum: "#6ee7b7",
  paste: "#f472b6",
  github: "#9aa4b2",
  doc: "#4cc2ff",
  ransom: "#ff5d5d",
  device: "#4cc2ff",
  infected: "#4cc2ff",
  stealer: "#ff5d5d",
  secret: "#ff5d5d",
};

function bucketOf(category) {
  const head = (category || "").split("_")[0].split(" ")[0];
  return BUCKET_COLORS[head] ? head : "github";
}

function renderTimeline(el, timeline) {
  if (!el || !timeline || !timeline.length) return;
  el.innerHTML = "";
  const buckets = [];
  timeline.forEach((h) => {
    Object.keys(h).forEach((k) => {
      if (k !== "hour" && buckets.indexOf(k) === -1) buckets.push(k);
    });
  });
  const max = Math.max(
    1,
    ...timeline.map((h) =>
      buckets.reduce((s, b) => s + (h[b] || 0), 0)));
  timeline.slice(-24).forEach((h) => {
    const col = document.createElement("div");
    const wrap = document.createElement("div");
    wrap.className = "tl-col";
    buckets.forEach((b) => {
      const v = h[b] || 0;
      if (!v) return;
      const seg = document.createElement("div");
      seg.className = "tl-seg";
      seg.style.height = Math.max(2, (v / max) * 96) + "px";
      seg.style.background = BUCKET_COLORS[b] || "#9aa4b2";
      seg.title = b + ": " + v;
      wrap.appendChild(seg);
    });
    const lbl = document.createElement("div");
    lbl.className = "tl-hour";
    lbl.textContent = (h.hour || "").slice(11, 13) + "Z";
    col.appendChild(wrap);
    col.appendChild(lbl);
    el.appendChild(col);
  });
}

document.addEventListener("DOMContentLoaded", () => {
  const tl = document.getElementById("timeline");
  if (tl && tl.dataset.payload) {
    try { renderTimeline(tl, JSON.parse(tl.dataset.payload)); } catch (e) {}
  }

  const btn = document.getElementById("trigger-btn");
  if (btn) {
    const status = document.getElementById("trigger-status");
    const onlyInp = document.getElementById("trigger-only");
    let poll = null;
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      status.textContent = "starting...";
      try {
        const res = await fetch("/api/trigger", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ only: onlyInp.value.trim() }),
        });
        await res.json();
        status.textContent = "running collectors...";
        poll = setInterval(async () => {
          const jr = await fetch("/api/jobs");
          const jobs = await jr.json();
          const latest = jobs[jobs.length - 1];
          if (!latest) return;
          if (latest.status === "done") {
            clearInterval(poll);
            btn.disabled = false;
            status.textContent = "run finished - reloading";
            setTimeout(() => location.reload(), 800);
          } else if (latest.status === "failed") {
            clearInterval(poll);
            btn.disabled = false;
            status.textContent = "run failed: " +
              (latest.tail[latest.tail.length - 1] || "");
          } else {
            status.textContent = "running (" +
              Math.round(latest.duration) + "s)...";
          }
        }, 3000);
      } catch (err) {
        btn.disabled = false;
        status.textContent = "trigger error: " + err;
      }
    });
  }
});
