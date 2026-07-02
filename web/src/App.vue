<script setup lang="ts">
import { computed, ref } from "vue";
import {
  type ScanResult, type Severity, type Vulnerability,
  SEVERITY_ORDER, SEVERITY_LABEL, SEVERITY_COLOR, categoryLabel,
} from "./types";

declare const __APP_VERSION__: string;

const result = ref<ScanResult | null>(null);
const scanning = ref(false);
const error = ref<string | null>(null);
const pendingName = ref("");
const isDragging = ref(false);
const fileInput = ref<HTMLInputElement | null>(null);
const scanElapsed = ref(0);
let _scanTimer: ReturnType<typeof setInterval> | null = null;

const search = ref("");
const activeSev = ref<Record<Severity, boolean>>({
  critical: true, high: true, medium: true, low: true, info: true,
});
const expanded = ref<Set<string>>(new Set());

const MAX = 80 * 1024 * 1024;

async function handleFile(f: File) {
  if (f.size > MAX) { error.value = "Fichier trop volumineux (max 80 MB)"; return; }
  error.value = null;
  result.value = null;
  scanning.value = true;
  scanElapsed.value = 0;
  pendingName.value = f.name;
  _scanTimer = setInterval(() => { scanElapsed.value += 1; }, 1000);
  try {
    const form = new FormData();
    form.append("file", f);
    const res = await fetch("/api/scan", { method: "POST", body: form });
    if (!res.ok) {
      if (res.status === 429) throw new Error("Trop de scans — patientez avant de réessayer.");
      if (res.status >= 500) throw new Error(`Erreur interne du serveur (${res.status}) — réessayez.`);
      const msg = await res.json().then((j: { error?: string }) => j.error).catch(() => undefined);
      throw new Error(msg ?? `Erreur réseau (${res.status})`);
    }
    result.value = await res.json();
  } catch (e) {
    if (e instanceof TypeError && e.message.toLowerCase().includes("fetch")) {
      error.value = "Erreur réseau — vérifiez votre connexion et réessayez.";
    } else {
      error.value = e instanceof Error ? e.message : String(e);
    }
  } finally {
    scanning.value = false;
    if (_scanTimer !== null) { clearInterval(_scanTimer); _scanTimer = null; }
  }
}

function onPick(e: Event) {
  const f = (e.target as HTMLInputElement).files?.[0];
  if (f) handleFile(f);
  (e.target as HTMLInputElement).value = "";
}
function onDrop(e: DragEvent) {
  e.preventDefault(); isDragging.value = false;
  const f = e.dataTransfer?.files?.[0];
  if (f) handleFile(f);
}

const filtered = computed<Vulnerability[]>(() => {
  if (!result.value) return [];
  const q = search.value.trim().toLowerCase();
  return result.value.vulnerabilities.filter((v) => {
    if (!activeSev.value[v.severity]) return false;
    if (!q) return true;
    return v.title.toLowerCase().includes(q)
      || v.file_path.toLowerCase().includes(q)
      || categoryLabel(v.category).toLowerCase().includes(q);
  });
});

function toggle(id: string) {
  if (expanded.value.has(id)) expanded.value.delete(id);
  else expanded.value.add(id);
  expanded.value = new Set(expanded.value);
}

function reset() {
  result.value = null; error.value = null; search.value = "";
  expanded.value = new Set();
}

function exportJson() {
  if (!result.value) return;
  const blob = new Blob([JSON.stringify(result.value, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `secuscan_${result.value.target_path}.json`;
  a.click();
}

const totalFindings = computed(() => result.value?.stats
  ? result.value.stats.critical + result.value.stats.high + result.value.stats.medium + result.value.stats.low + result.value.stats.info
  : 0);
</script>

<template>
  <header class="header">
    <div class="brand">
      <span class="logo">🛡️</span>
      <h1>SecuScan</h1>
      <span class="version">v{{ __APP_VERSION__ }}</span>
    </div>
    <span style="font-size:12px;color:var(--text-dim)">SAST · secrets · binaires</span>
  </header>

  <main>
    <template v-if="!result">
      <div
        class="dropzone" :class="{ drag: isDragging, disabled: scanning }"
        @click="fileInput?.click()"
        @dragover.prevent="isDragging = true"
        @dragenter.prevent="isDragging = true"
        @dragleave.prevent="isDragging = false"
        @drop="onDrop"
      >
        <input ref="fileInput" type="file" hidden @change="onPick" />
        <svg width="42" height="42" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
          <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75 11.25 15 15 9.75M21 12c0 1.268-.63 2.39-1.593 3.068a3.745 3.745 0 0 1-1.043 3.296 3.745 3.745 0 0 1-3.296 1.043A3.745 3.745 0 0 1 12 21c-1.268 0-2.39-.63-3.068-1.593a3.746 3.746 0 0 1-3.296-1.043 3.745 3.745 0 0 1-1.043-3.296A3.745 3.745 0 0 1 3 12c0-1.268.63-2.39 1.593-3.068a3.745 3.745 0 0 1 1.043-3.296 3.746 3.746 0 0 1 3.296-1.043A3.746 3.746 0 0 1 12 3c1.268 0 2.39.63 3.068 1.593a3.746 3.746 0 0 1 3.296 1.043 3.746 3.746 0 0 1 1.043 3.296A3.745 3.745 0 0 1 21 12Z" />
        </svg>
        <p class="title">{{ isDragging ? 'Relâchez ici' : 'Glissez un fichier de code, un binaire, ou un ZIP de projet' }}</p>
        <p class="hint">Code source · scripts · config · exécutables · ZIP — max 80 MB</p>
      </div>

      <div v-if="scanning" class="scanning">
        <div class="spinner"></div>
        <p>Analyse de <strong>{{ pendingName }}</strong>… {{ scanElapsed }}s</p>
        <p class="hint" style="font-size:11px;margin-top:6px">SAST · injections · secrets · crypto · YARA binaire</p>
      </div>

      <div v-if="error" class="error">✗ {{ error }}</div>

      <div class="features">
        <p class="features-title">Détections</p>
        <div class="features-grid">
          <div>💉 <strong>Injections</strong> — SQL, XSS, commande, path traversal, désérialisation</div>
          <div>🔑 <strong>Secrets exposés</strong> — clés API, mots de passe, JWT, chaînes de connexion</div>
          <div>🔐 <strong>Crypto faible</strong> — MD5/SHA-1 sur mots de passe, RNG non sûr</div>
          <div>🌐 <strong>Mauvaise config</strong> — CORS wildcard, redirections ouvertes</div>
          <div>📜 <strong>Scripts malveillants</strong> — obfuscation, élévation privilèges, payloads</div>
          <div>⚙️ <strong>Binaires (PE)</strong> — ASLR/DEP manquants, YARA (injection, ransomware)</div>
          <div>📦 <strong>Projet complet</strong> — uploadez un ZIP, scan récursif de l'arbre</div>
          <div>🎯 <strong>Hints faux positifs</strong> — contexte test/exemple/placeholder signalé</div>
        </div>
      </div>
    </template>

    <template v-else>
      <!-- Résumé -->
      <div class="summary">
        <div style="flex:1;min-width:200px">
          <p class="target">📁 {{ result.target_path }}</p>
          <p class="files">{{ result.scanned_files }} fichier(s) scanné(s) · {{ totalFindings }} résultat(s)</p>
        </div>
        <div class="stat-pills">
          <span
            v-for="s in SEVERITY_ORDER" :key="s"
            class="pill" :class="{ off: !activeSev[s] }"
            :style="{ background: SEVERITY_COLOR[s] + '22', color: SEVERITY_COLOR[s] }"
            @click="activeSev[s] = !activeSev[s]"
          >
            <span class="n">{{ result.stats[s] }}</span> {{ SEVERITY_LABEL[s] }}
          </span>
        </div>
      </div>

      <div class="toolbar">
        <input class="search" v-model="search" placeholder="Filtrer par titre, fichier, catégorie…" />
        <span class="grow"></span>
        <button @click="exportJson">Export JSON</button>
        <button class="primary" @click="reset">Nouveau scan</button>
      </div>

      <!-- Aucune vulnérabilité -->
      <div v-if="totalFindings === 0" class="clean">
        <div class="big">✓</div>
        <p>Aucune vulnérabilité détectée.</p>
        <p class="hint" style="color:var(--text-dim);font-size:12px;margin-top:6px">
          Un scan propre ne garantit pas l'absence totale de faille.
        </p>
      </div>

      <!-- Liste -->
      <div v-for="v in filtered" :key="v.id" class="vuln" :style="{ borderLeftColor: SEVERITY_COLOR[v.severity] }">
        <div class="vuln-head" @click="toggle(v.id)">
          <span class="sev" :style="{ background: SEVERITY_COLOR[v.severity] + '22', color: SEVERITY_COLOR[v.severity] }">
            {{ SEVERITY_LABEL[v.severity] }}
          </span>
          <span class="vuln-title">{{ v.title }}</span>
          <span v-if="v.fp_hint" title="Possible faux positif">🎯</span>
          <span class="vuln-file">{{ v.file_path }}<span v-if="v.line_number">:{{ v.line_number }}</span></span>
        </div>
        <div v-if="expanded.has(v.id)" class="vuln-body">
          <div style="display:flex;gap:8px;align-items:center;margin-top:8px;flex-wrap:wrap">
            <span class="cwe">{{ categoryLabel(v.category) }}</span>
            <span v-if="v.cwe_id" class="cwe">{{ v.cwe_id }}</span>
          </div>
          <h4>Description</h4>
          <p>{{ v.description }}</p>
          <template v-if="v.code_snippet">
            <h4>Extrait</h4>
            <div class="snippet">{{ v.code_snippet }}</div>
          </template>
          <h4>Remédiation</h4>
          <p>{{ v.remediation }}</p>
          <div v-if="v.fp_hint" class="fp-hint">🎯 {{ v.fp_hint }}</div>
        </div>
      </div>
    </template>
  </main>

  <footer class="footer">
    Analyse statique locale — aucun fichier conservé après le scan (traitement en mémoire, répertoire temporaire supprimé).
    <a href="https://heiphaistos.org/legal/" target="_blank" rel="noopener noreferrer">Mentions légales</a>
  </footer>
</template>
