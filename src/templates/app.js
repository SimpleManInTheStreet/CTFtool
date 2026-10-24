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
    hashRow: document.getElementById("hash-row"),
    hashFunc: document.getElementById("hash-func"),
    wordlen: document.getElementById("wordlen"),
    alphabetRow: document.getElementById("alphabet-row"),
    alphabet: document.getElementById("alphabet"),
    alphabetPreset: document.getElementById("alphabet-preset"),
    error: document.getElementById("form-error"),
    desc: document.getElementById("algo-desc"),
    jobs: document.getElementById("jobs"),
    dot: document.getElementById("logic-dot"),
    status: document.getElementById("logic-status"),
    submit: document.querySelector("#calc-form button"),
  };

  // Alphabet templates offered in the UI.  The selected value is copied into
  // the alphabet field, which the user may then edit freely; the exact string
  // is what gets sent to the server.
  const ALPHABET_PRESETS = [
    { label: "custom", value: "" },
    { label: "lowercase a-z", value: "abcdefghijklmnopqrstuvwxyz" },
    { label: "uppercase A-Z", value: "ABCDEFGHIJKLMNOPQRSTUVWXYZ" },
    {
      label: "letters",
      value: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    },
    { label: "digits 0-9", value: "0123456789" },
    { label: "hex lowercase", value: "0123456789abcdef" },
    { label: "hex uppercase", value: "0123456789ABCDEF" },
    {
      label: "lowercase + digits",
      value: "abcdefghijklmnopqrstuvwxyz0123456789",
    },
    {
      label: "alphanumeric",
      value: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    },
    {
      label: "printable ASCII",
      value:
        "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~",
    },
  ];

  for (const preset of ALPHABET_PRESETS) {
    const opt = document.createElement("option");
    opt.value = preset.value;
    opt.textContent = preset.label;
    el.alphabetPreset.appendChild(opt);
  }

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
    // hash brute takes a different set of parameters (hash/wordlen/alphabet)
    const isHash = a && a.name === "hash_brute";
    el.hashRow.style.display = isHash ? "" : "none";
    el.alphabetRow.style.display = isHash ? "" : "none";
    if (isHash) {
      el.input.placeholder = "hash digest to crack (hex, e.g. 5d41402a...)";
    } else if (a && (a.name === "base64_decode" || a.name === "hex_decode")) {
      el.input.placeholder = "paste the encoded string here";
    } else {
      el.input.placeholder = "paste the encoded string here";
    }
  }

  el.algo.addEventListener("change", updateAlgoUI);

  el.alphabetPreset.addEventListener("change", () => {
    if (el.alphabetPreset.value !== "") {
      el.alphabet.value = el.alphabetPreset.value;
      el.alphabetPreset.value = "";
    }
  });

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

    if (algo === "hash_brute") {
      payload.hash = el.hashFunc.value;
      payload.length = parseInt(el.wordlen.value || "0", 10);
      payload.alphabet = el.alphabet.value;
    }

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
