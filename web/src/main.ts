import './style.css';
import {
  cancelPendingCeremony,
  deletePasskey,
  describeError,
  detectSupport,
  getMe,
  getServerInfo,
  isAbort,
  listPasskeys,
  loginWithPasskey,
  logout,
  registerPasskey,
  type Passkey,
  type Support,
  type User,
} from './passkeys';

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;

const els = {
  message: $<HTMLDivElement>('message'),
  auth: $<HTMLElement>('auth'),
  panel: $<HTMLElement>('panel'),
  form: $<HTMLFormElement>('auth-form'),
  username: $<HTMLInputElement>('username'),
  btnLogin: $<HTMLButtonElement>('btn-login'),
  btnRegister: $<HTMLButtonElement>('btn-register'),
  btnAdd: $<HTMLButtonElement>('btn-add'),
  btnLogout: $<HTMLButtonElement>('btn-logout'),
  meName: $<HTMLSpanElement>('me-name'),
  credList: $<HTMLUListElement>('cred-list'),
  supportList: $<HTMLUListElement>('support-list'),
  rpId: $<HTMLElement>('rp-id'),
};

// Challenge żyje na serwerze 5 minut, więc czekające w tle żądanie autofill odświeżamy wcześniej.
const AUTOFILL_REFRESH_MS = 4 * 60 * 1000;

let support: Support = { webauthn: false, platform: false, autofill: false };
let loggedIn = false;
let busy = false;
let autofillTimer: number | undefined;

function showMessage(text: string, kind: 'info' | 'success' | 'error' = 'info') {
  els.message.textContent = text;
  els.message.dataset.kind = kind;
  els.message.hidden = false;
}

function clearMessage() {
  els.message.hidden = true;
}

function setBusy(value: boolean) {
  busy = value;
  for (const b of [els.btnLogin, els.btnRegister, els.btnAdd, els.btnLogout]) {
    b.disabled = value || (!support.webauthn && b !== els.btnLogout);
  }
}

function el<K extends keyof HTMLElementTagNameMap>(tag: K, className?: string, text?: string) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

// ---------- wykrywanie wsparcia ----------

function renderSupport() {
  const rows: [boolean, string, string][] = [
    [support.webauthn, 'WebAuthn', 'przeglądarka obsługuje API passkeys'],
    [
      support.platform,
      'Uwierzytelniacz platformowy',
      'Windows Hello / Touch ID / blokada ekranu telefonu (isUserVerifyingPlatformAuthenticatorAvailable)',
    ],
    [
      support.autofill,
      'Autofill passkeys',
      'logowanie z podpowiedzi pola (isConditionalMediationAvailable)',
    ],
  ];
  els.supportList.replaceChildren(
    ...rows.map(([ok, title, detail]) => {
      const li = el('li');
      li.append(
        el('span', ok ? 'badge ok' : 'badge no', ok ? 'tak' : 'nie'),
        el('strong', undefined, title),
        el('span', 'detail', detail),
      );
      return li;
    }),
  );
}

async function checkServerConfig() {
  try {
    const info = await getServerInfo();
    els.rpId.textContent = info.rpID;
    if (info.origin !== location.origin) {
      showMessage(
        `Serwer jest skonfigurowany dla ${info.origin}, a strona działa pod ${location.origin}. ` +
          'Ustaw RP_ID i ORIGIN w .env i uruchom ponownie kontener api – inaczej ceremonie będą odrzucane.',
        'error',
      );
    }
  } catch {
    showMessage('Brak połączenia z API.', 'error');
  }
}

// ---------- widoki ----------

function showAuth() {
  loggedIn = false;
  els.panel.hidden = true;
  els.auth.hidden = false;
  armAutofill();
}

async function showPanel(user: User) {
  loggedIn = true;
  window.clearTimeout(autofillTimer);
  cancelPendingCeremony();
  els.auth.hidden = true;
  els.panel.hidden = false;
  els.meName.textContent = user.username;
  els.username.value = '';
  await refreshPasskeys();
}

const dateFmt = new Intl.DateTimeFormat('pl-PL', { dateStyle: 'medium', timeStyle: 'short' });
const formatDate = (iso: string | null) => (iso ? dateFmt.format(new Date(iso)) : 'jeszcze nie użyty');

function renderPasskey(passkey: Passkey, canDelete: boolean) {
  const li = el('li', 'cred');
  const info = el('div', 'cred-info');
  const title = el('div', 'cred-title');
  title.append(
    el('strong', undefined, passkey.name),
    el(
      'span',
      'badge',
      passkey.deviceType === 'multiDevice' ? 'synchronizowany' : 'tylko to urządzenie',
    ),
    el('span', passkey.backedUp ? 'badge ok' : 'badge', passkey.backedUp ? 'kopia zapasowa' : 'bez kopii'),
  );
  const meta = el(
    'div',
    'detail',
    `Utworzony: ${formatDate(passkey.createdAt)} · Ostatnie użycie: ${formatDate(passkey.lastUsedAt)} · ` +
      `Licznik: ${passkey.counter} · Transport: ${passkey.transports.join(', ') || '—'}`,
  );
  const id = el('code', 'cred-id', passkey.id);
  id.title = 'Credential ID';
  info.append(title, meta, id);

  const remove = el('button', 'danger', 'Usuń');
  remove.type = 'button';
  remove.disabled = !canDelete;
  remove.title = canDelete ? 'Usuń ten passkey z konta' : 'Nie można usunąć ostatniego passkey';
  remove.addEventListener('click', () => void onDelete(passkey));

  li.append(info, remove);
  return li;
}

async function refreshPasskeys() {
  const passkeys = await listPasskeys();
  els.credList.replaceChildren(...passkeys.map((p) => renderPasskey(p, passkeys.length > 1)));
}

// ---------- akcje ----------

/** Conditional UI: żądanie logowania czeka w tle, passkey wybiera się z podpowiedzi pola nazwy użytkownika. */
function armAutofill() {
  window.clearTimeout(autofillTimer);
  if (!support.autofill || loggedIn || busy) return;
  autofillTimer = window.setTimeout(armAutofill, AUTOFILL_REFRESH_MS);

  loginWithPasskey({ autofill: true }).then(
    async (user) => {
      showMessage(`Zalogowano jako ${user.username} (autofill).`, 'success');
      await showPanel(user);
    },
    (err) => {
      // AbortError = żądanie zastąpione przez kliknięcie przycisku albo odświeżenie – to nie jest błąd.
      if (isAbort(err) || loggedIn) return;
      showMessage(describeError(err, 'login'), 'error');
      if (!busy) armAutofill();
    },
  );
}

/** Uruchamia ceremonię z przycisku; po niepowodzeniu przywraca autofill. */
async function runCeremony(kind: 'register' | 'login', action: () => Promise<void>) {
  if (busy) return;
  clearMessage();
  setBusy(true);
  try {
    await action();
  } catch (err) {
    if (!isAbort(err)) showMessage(describeError(err, kind), 'error');
  } finally {
    setBusy(false);
    if (!loggedIn) armAutofill();
  }
}

els.btnLogin.addEventListener('click', () =>
  runCeremony('login', async () => {
    const user = await loginWithPasskey();
    showMessage(`Zalogowano jako ${user.username}.`, 'success');
    await showPanel(user);
  }),
);

els.form.addEventListener('submit', (event) => {
  event.preventDefault();
  const username = els.username.value.trim();
  if (!username) {
    showMessage('Podaj nazwę użytkownika, aby założyć konto.', 'error');
    els.username.focus();
    return;
  }
  void runCeremony('register', async () => {
    const user = await registerPasskey(username);
    showMessage('Konto utworzone, passkey zapisany.', 'success');
    await showPanel(user);
  });
});

els.btnAdd.addEventListener('click', () =>
  runCeremony('register', async () => {
    await registerPasskey();
    showMessage('Dodano nowy passkey.', 'success');
    await refreshPasskeys();
  }),
);

els.btnLogout.addEventListener('click', async () => {
  clearMessage();
  await logout();
  showAuth();
});

async function onDelete(passkey: Passkey) {
  if (!confirm(`Usunąć passkey „${passkey.name}”? Nie będzie można się nim już zalogować.`)) return;
  clearMessage();
  try {
    await deletePasskey(passkey.id);
    showMessage(
      'Passkey usunięty z konta. Wpis w menedżerze haseł urządzenia trzeba usunąć osobno.',
      'success',
    );
  } catch (err) {
    showMessage(describeError(err, 'login'), 'error');
  }
  await refreshPasskeys();
}

// ---------- start ----------

async function init() {
  support = await detectSupport();
  renderSupport();
  setBusy(false);
  await checkServerConfig();
  if (!support.webauthn) {
    showMessage('Ta przeglądarka nie obsługuje WebAuthn – passkeys nie zadziałają.', 'error');
  }
  const me = await getMe().catch(() => null);
  if (me) await showPanel(me);
  else showAuth();
}

void init();
