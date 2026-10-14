"use strict";

(function () {
  const state = {
    algos: [],
    jobs: new Map(), // id -> { id, algo, status, result, error, el }
  };

  const el = {
    form: document.getElementById("calc-form"),
    algo: document.getElementById("algo"),
    input: document.getElementById("input"),
    keylen: document.getElementById("keylen"),
    keylenWrap: document.getElementById("keylen-wrap"),
    flags: document.getElementById("flags"),
    error: document.getElementById("form-error"),
    desc: document.getElementById("algo-desc"),
    jobs: document.getElementById("jobs"),
    dot: document.getElementById("logic-dot"),
    status: document.getElementById("logic-status"),
    submit: document.querySelector("#calc-form button"),
  };

  async function getJSON(url, options) {
    const res = await fetch(url, options);
    let data = null;
    try {
      data = await res.json();
    } catch (e) {
      data = { error: "invalid server response" };
    }
    return { ok: res.ok, status: res.status, data };
  }

  // ---- algorithms -------------------------------------------------

  async function loadAlgos() {
    const { ok, data } = await getJSON("/api/algos");
    if (!ok || !data || !Array.isArray(data.algos)) return;
    state.algos = data.algos;
    el.algo.innerHTML = "";
    for (const a of state.algos) {
      const opt = document.createElement("option");
      opt.value = a.name;
      opt.textContent = a.name;
      opt.title = a.description || "";
      el.algo.appendChild(opt);
    }
    updateAlgoUI();
  }

  function currentAlgo() {
    return state.algos.find((a) => a.name === el.algo.value) || null;
  }

  function updateAlgoUI() {
    const a = currentAlgo();
    el.desc.textContent = a ? a.description : "";
    // key length is only meaningful for the XOR brute forcer
    el.keylenWrap.style.display = a && a.name === "xor_brute" ? "" : "none";
  }

  el.algo.addEventListener("change", updateAlgoUI);

  // ---- job rendering ---------------------------------------------

  function ensureJobEl(job) {
    if (job.el) return;
    const div = document.createElement("div");
    div.className = "job";
    div.innerHTML =
      '<div class="job-head">' +
      '<span>job #' + job.id + " &middot; " + job.algo + "</span>" +
      '<span class="badge pending">pending</span>' +
      "</div><pre></pre>";
    el.jobs.prepend(div);
    job.el = div;
  }

  function renderJob(job) {
    ensureJobEl(job);
    const badge = job.el.querySelector(".badge");
    badge.className = "badge " + job.status;
    badge.textContent = job.status;
    const pre = job.el.querySelector("pre");
    if (job.status === "error") {
      pre.textContent = job.error || "error";
    } else if (job.status === "done") {
      pre.textContent = job.result || "(empty result)";
    } else {
      pre.textContent = "working...";
    }
  }

  // ---- submitting -------------------------------------------------

  el.form.addEventListener("submit", async (e) => {
    e.preventDefault();
    el.error.textContent = "";

    const algo = el.algo.value;
    const input = el.input.value;
    if (!algo) {
      el.error.textContent = "no algorithm selected";
      return;
    }
    if (input.length === 0) {
      el.error.textContent = "input is empty";
      return;
    }

    const payload = {
      algo: algo,
      keylen: parseInt(el.keylen.value || "1", 10),
      flags: parseInt(el.flags.value || "0", 10),
      input: input,
    };

    el.submit.disabled = true;
    const { ok, status, data } = await getJSON("/api/calc", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    el.submit.disabled = false;

    if (!data || !data.id) {
      el.error.textContent = (data && data.error) || "request failed (" + status + ")";
      return;
    }

    const job = {
      id: data.id,
      algo: algo,
      status: "pending",
      result: "",
      error: "",
      el: null,
    };
    state.jobs.set(job.id, job);
    renderJob(job);
  });

  // ---- polling ----------------------------------------------------

  async function pollJob(job) {
    const { data } = await getJSON("/api/result?id=" + job.id);
    if (!data || !data.status) return;
    job.status = data.status;
    job.result = data.result || "";
    job.error = data.error || "";
    renderJob(job);
    return job.status !== "pending";
  }

  async function pollAll() {
    const pending = [];
    for (const job of state.jobs.values()) {
      if (job.status === "pending") pending.push(pollJob(job));
    }
    await Promise.all(pending);
  }

  async function pollHealth() {
    const { data } = await getJSON("/api/health");
    const up = data && data.logic === "up";
    el.dot.className = "dot " + (up ? "up" : "down");
    el.status.textContent = up
      ? "logic online"
      : "logic offline";
  }

  async function tick() {
    await pollAll();
    await pollHealth();
    setTimeout(tick, 700);
  }

  loadAlgos();
  pollHealth();
  tick();
})();
