import { initializeApp } from "https://www.gstatic.com/firebasejs/10.12.2/firebase-app.js";
import {
    getAuth, onAuthStateChanged, createUserWithEmailAndPassword,
    signInWithEmailAndPassword, signOut,
    GoogleAuthProvider, signInWithPopup, sendEmailVerification
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-auth.js";
import {
    getFirestore, doc, getDoc, setDoc, updateDoc,
    collection, addDoc, query, where, onSnapshot
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-firestore.js";

const firebaseConfig = {
    apiKey: "AIzaSyB4LDvi0qarMPNpkuTdyLDmiqgcynLLtbs",
    authDomain: "exile-7aacf.firebaseapp.com",
    projectId: "exile-7aacf",
    storageBucket: "exile-7aacf.firebasestorage.app",
    messagingSenderId: "205703165815",
    appId: "1:205703165815:web:75ea9f9e6aa40cfd6ad372"
};

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);

// email akun guru piket (harus sama dengan di Rules)
const PIKET_EMAILS = ["guru.piket@exile.com"];

// true  = akun email+password WAJIB verifikasi email dulu sebelum bisa memakai aplikasi
// false = verifikasi dimatikan (berguna saat testing dengan email palsu)
// Akun Google selalu dianggap terverifikasi, akun guru piket dikecualikan.
const WAJIB_VERIFIKASI = true;

const EXILE = (() => {

    function kodeSurat() {
        const t = Date.now().toString(36).toUpperCase().slice(-5);
        const r = Math.random().toString(36).toUpperCase().slice(2, 5);
        return `EXL-${t}${r}`;
    }

    function formatWaktu(ts) {
        const d = new Date(ts);
        return d.toLocaleString("id-ID", {
            weekday: "long", day: "2-digit", month: "long", year: "numeric",
            hour: "2-digit", minute: "2-digit"
        });
    }

    /* ---------- auth & users ---------- */

    function isPiket(user) {
        return PIKET_EMAILS.includes(user.email.toLowerCase());
    }

    // Terjemahkan kode error Firebase ke bahasa Indonesia
    function authError(err) {
        const map = {
            "auth/email-already-in-use": "Email sudah terdaftar. Silakan masuk.",
            "auth/invalid-credential": "Email atau password salah.",
            "auth/invalid-email": "Format email tidak valid.",
            "auth/weak-password": "Password minimal 6 karakter.",
            "auth/too-many-requests": "Terlalu banyak percobaan. Coba lagi nanti.",
            "auth/network-request-failed": "Koneksi internet bermasalah.",
            "auth/popup-blocked": "Popup diblokir browser. Izinkan popup untuk situs ini lalu coba lagi.",
            "auth/unauthorized-domain": "Domain ini belum diizinkan di Firebase (Authentication > Settings > Authorized domains).",
            "auth/operation-not-allowed": "Metode login ini belum diaktifkan di Firebase Console.",
            "auth/account-exists-with-different-credential": "Email ini sudah terdaftar dengan cara login lain."
        };
        return new Error(map[err.code] || err.message);
    }

    async function registerUser({ nama, email, password, kelas, noAbsen }) {
        try {
            const cred = await createUserWithEmailAndPassword(auth, email, password);
            const profile = { nama, email, kelas, noAbsen, createdAt: Date.now() };
            // dokumen profil memakai UID dari Auth sebagai ID-nya
            await setDoc(doc(db, "users", cred.user.uid), profile);
            // kirim link verifikasi; kalau gagal kirim, pendaftaran tetap berhasil
            // (user bisa menekan "Kirim ulang" di halaman verify.html)
            try { await sendEmailVerification(cred.user); } catch (e) { /* diabaikan */ }
            return { id: cred.user.uid, ...profile };
        } catch (err) {
            throw authError(err);
        }
    }

    async function loginWithPassword(email, password) {
        try {
            await signInWithEmailAndPassword(auth, email, password);
        } catch (err) {
            throw authError(err);
        }
        return getCurrentUser();
    }

    function logout() {
        return signOut(auth);
    }

    // Firebase butuh waktu sebentar untuk memulihkan sesi login,
    // jadi kita tunggu event pertamanya
    function waitForAuth() {
        return new Promise(resolve => {
            const unsub = onAuthStateChanged(auth, fbUser => {
                unsub();
                resolve(fbUser);
            });
        });
    }

    async function getCurrentUser() {
        const fbUser = await waitForAuth();
        if (!fbUser) return null;
        const snap = await getDoc(doc(db, "users", fbUser.uid));
        if (!snap.exists()) return null;
        return { id: fbUser.uid, ...snap.data(), emailVerified: fbUser.emailVerified };
    }

    async function requireAuth(redirectTo = "login.html") {
        const u = await getCurrentUser();
        if (!u) {
            window.location.href = redirectTo;
            return null;
        }
        if (needsVerification(u)) {
            window.location.href = "verify.html";
            return null;
        }
        return u;
    }

    async function requirePiket() {
        const u = await requireAuth();
        if (u && !isPiket(u)) {
            window.location.href = "home.html";
            return null;
        }
        return u;
    }

    /* ---------- login Google & verifikasi email ---------- */

    function needsVerification(user) {
        return WAJIB_VERIFIKASI && !user.emailVerified && !isPiket(user);
    }

    // Mengembalikan null kalau popup ditutup user.
    // needsProfile = true -> akun Google baru, belum punya kelas/no. absen.
    async function loginWithGoogle() {
        try {
            const provider = new GoogleAuthProvider();
            provider.setCustomParameters({ prompt: "select_account" });
            const cred = await signInWithPopup(auth, provider);
            const snap = await getDoc(doc(db, "users", cred.user.uid));
            if (!snap.exists()) return { needsProfile: true, user: null };
            return { needsProfile: false, user: await getCurrentUser() };
        } catch (err) {
            if (err.code === "auth/popup-closed-by-user" || err.code === "auth/cancelled-popup-request") return null;
            throw authError(err);
        }
    }

    // Dipanggil setelah login Google pertama kali, untuk menyimpan nama, kelas, dan no. absen
    async function completeGoogleProfile({ nama, kelas, noAbsen }) {
        const fb = await waitForAuth();
        if (!fb) throw new Error("Sesi Google berakhir. Silakan masuk dengan Google lagi.");
        const profile = { nama, email: fb.email, kelas, noAbsen, createdAt: Date.now() };
        await setDoc(doc(db, "users", fb.uid), profile);
        return { id: fb.uid, ...profile };
    }

    async function resendVerification() {
        const fb = await waitForAuth();
        if (!fb) throw new Error("Sesi berakhir. Silakan masuk lagi.");
        try {
            await sendEmailVerification(fb);
        } catch (err) {
            throw authError(err);
        }
    }

    // Muat ulang status akun dari server (setelah user klik link di email)
    async function checkVerified() {
        const fb = await waitForAuth();
        if (!fb) return false;
        await fb.reload();
        if (fb.emailVerified) await fb.getIdToken(true); // segarkan token supaya Rules membaca email_verified terbaru
        return fb.emailVerified;
    }

    function updateProfile(userId, patch) {
        return updateDoc(doc(db, "users", userId), patch);
    }

    /* ---------- requests (pengajuan izin) ---------- */

    async function createRequest({ userId, nama, kelas, noAbsen, alasan }) {
        const data = {
            userId, nama, kelas, noAbsen, alasan,
            status: "pending",
            createdAt: Date.now(),
            updatedAt: Date.now(),
            kodeSurat: null,
            alasanTolak: null,
            respondedBy: null
        };
        const ref = await addDoc(collection(db, "requests"), data);
        return { id: ref.id, ...data };
    }

    function updateRequestStatus(id, status, extra = {}) {
        return updateDoc(doc(db, "requests", id), {
            status, updatedAt: Date.now(), ...extra
        });
    }

    // onSnapshot = "pasang telinga": callback dipanggil sekali di awal
    // dan lagi setiap data berubah. Mengembalikan fungsi untuk berhenti mendengar.
    function listenRequestsByUser(userId, callback) {
        const q = query(collection(db, "requests"), where("userId", "==", userId));
        return onSnapshot(q, snap => {
            const reqs = snap.docs
                .map(d => ({ id: d.id, ...d.data() }))
                .sort((a, b) => b.createdAt - a.createdAt); // diurutkan di JS, tidak perlu index
            callback(reqs);
        });
    }

    function listenAllRequests(callback) {
        return onSnapshot(collection(db, "requests"), snap => {
            callback(snap.docs.map(d => ({ id: d.id, ...d.data() })));
        });
    }

    function listenRequest(id, callback, onError) {
        return onSnapshot(
            doc(db, "requests", id),
            snap => callback(snap.exists() ? { id: snap.id, ...snap.data() } : null),
            onError
        );
    }

    function playCallSound() {
        try {
            const ctx = new (window.AudioContext || window.webkitAudioContext)();
            const now = ctx.currentTime;
            const notes = [880, 1046.5, 880, 1046.5];
            notes.forEach((freq, i) => {
                const osc = ctx.createOscillator();
                const gain = ctx.createGain();
                osc.type = "sine";
                osc.frequency.value = freq;
                gain.gain.setValueAtTime(0, now + i * 0.22);
                gain.gain.linearRampToValueAtTime(0.18, now + i * 0.22 + 0.02);
                gain.gain.linearRampToValueAtTime(0, now + i * 0.22 + 0.18);
                osc.connect(gain).connect(ctx.destination);
                osc.start(now + i * 0.22);
                osc.stop(now + i * 0.22 + 0.2);
            });
        } catch (e) { /* audio not available, ignore */ }
    }

    /* ---------- toast ---------- */

    function toast(msg, ms = 2400) {
        let el = document.querySelector(".toast");
        if (!el) {
            el = document.createElement("div");
            el.className = "toast";
            document.body.appendChild(el);
        }
        el.textContent = msg;
        requestAnimationFrame(() => el.classList.add("show"));
        clearTimeout(el._t);
        el._t = setTimeout(() => el.classList.remove("show"), ms);
    }

    /* ---------- status label ---------- */

    const STATUS_LABEL = {
        pending: "Menunggu",
        calling: "Memanggil Guru",
        reviewing: "Sedang Direspon",
        accepted: "Disetujui",
        rejected: "Ditolak"
    };

    return {
        kodeSurat, formatWaktu, isPiket,
        registerUser, loginWithPassword, logout, getCurrentUser, getFirebaseUser: waitForAuth,
        loginWithGoogle, completeGoogleProfile, needsVerification, resendVerification, checkVerified,
        requireAuth, requirePiket, updateProfile,
        createRequest, updateRequestStatus,
        listenRequestsByUser, listenAllRequests, listenRequest,
        playCallSound, toast, STATUS_LABEL
    };
})();

window.EXILE = EXILE;   // supaya bisa dipakai dari script di halaman HTML